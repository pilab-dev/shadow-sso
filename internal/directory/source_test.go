package directory

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pilab-dev/shadow-sso/domain"
	accountsv1 "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/accounts/v1"
	accountsv1connect "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/accounts/v1/accountsv1connect"
	commonv1 "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/common/v1"
	credentialsv1 "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/credentials/v1"
	credentialsv1connect "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/credentials/v1/credentialsv1connect"
	"github.com/pilab-dev/shadow-sso/internal/identity"
)

// fakeAccounts answers the four RPCs the adapter uses and records what it was
// asked for.
type fakeAccounts struct {
	accountsv1connect.UnimplementedAccountsServiceHandler

	resolveLogin *accountsv1.ResolveLoginResponse
	get          *accountsv1.GetResponse
	membership   *accountsv1.ResolveMembershipResponse

	resolveErr error
	getErr     error

	// procedure is the procedure of the last call, header its ActorContext.
	procedure string
	header    string
}

func (f *fakeAccounts) ResolveLogin(_ context.Context, req *connect.Request[accountsv1.ResolveLoginRequest]) (*connect.Response[accountsv1.ResolveLoginResponse], error) {
	f.procedure, f.header = req.Spec().Procedure, req.Header().Get(Header)
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	return connect.NewResponse(f.resolveLogin), nil
}

func (f *fakeAccounts) Get(_ context.Context, req *connect.Request[accountsv1.GetRequest]) (*connect.Response[accountsv1.GetResponse], error) {
	f.procedure, f.header = req.Spec().Procedure, req.Header().Get(Header)
	if f.getErr != nil {
		return nil, f.getErr
	}
	return connect.NewResponse(f.get), nil
}

func (f *fakeAccounts) ResolveMembership(_ context.Context, req *connect.Request[accountsv1.ResolveMembershipRequest]) (*connect.Response[accountsv1.ResolveMembershipResponse], error) {
	f.procedure, f.header = req.Spec().Procedure, req.Header().Get(Header)
	return connect.NewResponse(f.membership), nil
}

// fakeCredentials answers VerifyPassword.
type fakeCredentials struct {
	credentialsv1connect.UnimplementedCredentialsServiceHandler

	response *credentialsv1.VerifyPasswordResponse
	err      error

	request *credentialsv1.VerifyPasswordRequest
	header  string
}

func (f *fakeCredentials) VerifyPassword(_ context.Context, req *connect.Request[credentialsv1.VerifyPasswordRequest]) (*connect.Response[credentialsv1.VerifyPasswordResponse], error) {
	f.request, f.header = req.Msg, req.Header().Get(Header)
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(f.response), nil
}

// rig is a fake pir-accounts plus the source talking to it.
type rig struct {
	accounts    *fakeAccounts
	credentials *fakeCredentials
	source      *Source
	signingKey  ed25519.PrivateKey
	server      *httptest.Server
}

func newRig(t *testing.T, withSigner bool) *rig {
	t.Helper()
	r := &rig{accounts: &fakeAccounts{}, credentials: &fakeCredentials{}}

	mux := http.NewServeMux()
	mux.Handle(accountsv1connect.NewAccountsServiceHandler(r.accounts))
	mux.Handle(credentialsv1connect.NewCredentialsServiceHandler(r.credentials))
	r.server = httptest.NewServer(mux)
	t.Cleanup(r.server.Close)

	if withSigner {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		r.signingKey = priv
	}

	httpClient := r.server.Client()
	opts := []connect.ClientOption{}
	if withSigner {
		opts = append(opts, connect.WithInterceptors((&signer{id: ServiceName, key: r.signingKey}).interceptor()))
	}
	r.source = &Source{
		accounts:    accountsv1connect.NewAccountsServiceClient(httpClient, r.server.URL, opts...),
		credentials: credentialsv1connect.NewCredentialsServiceClient(httpClient, r.server.URL, opts...),
		timeout:     5 * time.Second,
	}
	if withSigner {
		r.source.signer = &signer{id: ServiceName, key: r.signingKey}
	}
	return r
}

func TestResolveTranslatesResolveLogin(t *testing.T) {
	r := newRig(t, false)
	r.accounts.resolveLogin = &accountsv1.ResolveLoginResponse{
		Id: "guid-1", Dn: "cn=Alice,cn=Users,dc=pi,dc=lab", Class: "user",
		Enabled: true, Login: "alice", Upn: "alice@pi.lab", Mail: "alice@pi.lab",
	}

	got, err := r.source.Resolve(context.Background(), "  alice  ")
	require.NoError(t, err)
	assert.Equal(t, "guid-1", got.ID)
	assert.Equal(t, "cn=Alice,cn=Users,dc=pi,dc=lab", got.DN)
	assert.Equal(t, "user", got.Class)
	assert.Equal(t, domain.UserStatusActive, got.Status)
	assert.Equal(t, "alice", got.Login)
	assert.Equal(t, "alice@pi.lab", got.UPN)
	assert.Equal(t, "alice@pi.lab", got.Email)
	// ResolveLogin is service-only: it goes out without an acting principal.
	assert.Empty(t, r.accounts.header)
}

func TestResolveTrimsTheLoginAndReportsADisabledAccountAsLocked(t *testing.T) {
	r := newRig(t, false)
	r.accounts.resolveLogin = &accountsv1.ResolveLoginResponse{Id: "guid-1", Enabled: false}

	got, err := r.source.Resolve(context.Background(), "   bob   ")
	require.NoError(t, err)
	assert.Equal(t, domain.UserStatusLocked, got.Status)
}

func TestResolveFoldsConnectErrorsOntoThePort(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    error
		notWant error
	}{
		{"no such identity", connect.NewError(connect.CodeNotFound, assert.AnError), identity.ErrNotFound, identity.ErrUnavailable},
		{"empty login", connect.NewError(connect.CodeInvalidArgument, assert.AnError), identity.ErrNotFound, identity.ErrUnavailable},
		{"directory down", connect.NewError(connect.CodeUnavailable, assert.AnError), identity.ErrUnavailable, identity.ErrNotFound},
		{"not allowed", connect.NewError(connect.CodeUnauthenticated, assert.AnError), identity.ErrUnavailable, identity.ErrInvalidCredentials},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, false)
			r.accounts.resolveErr = tc.err

			_, err := r.source.Resolve(context.Background(), "alice")
			require.ErrorIs(t, err, tc.want)
			assert.NotErrorIs(t, err, tc.notWant)
		})
	}
}

func TestAuthenticateSendsThePasswordAndMapsTheResult(t *testing.T) {
	tests := []struct {
		name       string
		response   *credentialsv1.VerifyPasswordResponse
		wantCode   identity.Code
		wantChange bool
	}{
		{"ok", &credentialsv1.VerifyPasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_OK}, identity.CodeOK, false},
		{"wrong password", &credentialsv1.VerifyPasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_INVALID}, identity.CodeInvalid, false},
		{"locked out", &credentialsv1.VerifyPasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_LOCKED}, identity.CodeLocked, false},
		{"expired", &credentialsv1.VerifyPasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_EXPIRED}, identity.CodeExpired, false},
		{"must change", &credentialsv1.VerifyPasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_OK, MustChange: true}, identity.CodeOK, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, false)
			r.credentials.response = tc.response

			got, err := r.source.Authenticate(context.Background(), &identity.Identity{ID: "guid-1"}, "s3cret")
			require.NoError(t, err)
			assert.Equal(t, tc.wantCode, got.Code)
			assert.Equal(t, tc.wantChange, got.MustChange)
			assert.Equal(t, "guid-1", r.credentials.request.GetPrincipalId())
			assert.Equal(t, "s3cret", r.credentials.request.GetPassword())
			assert.Equal(t, "oidc", r.credentials.request.GetContext().GetProtocol())
			// VerifyPassword is service-only too.
			assert.Empty(t, r.credentials.header)
		})
	}
}

func TestAuthenticateTreatsAnUnknownPrincipalAsAWrongPassword(t *testing.T) {
	r := newRig(t, false)

	got, err := r.source.Authenticate(context.Background(), nil, "s3cret")
	require.NoError(t, err)
	assert.Equal(t, identity.CodeInvalid, got.Code)
	assert.Nil(t, r.credentials.request, "nothing is sent for an identity that was never resolved")
}

func TestGetReadsAsTheIdentityAndCarriesASignedPrincipal(t *testing.T) {
	r := newRig(t, true)
	r.accounts.get = &accountsv1.GetResponse{
		Object: &accountsv1.Object{
			Id: "guid-1", Class: "user", Dn: "cn=Alice,cn=Users,dc=pi,dc=lab",
			Attributes: []*accountsv1.Attribute{
				{Name: "sAMAccountName", Values: []*accountsv1.Value{{Kind: &accountsv1.Value_StringValue{StringValue: "alice"}}}},
				{Name: "userPrincipalName", Values: []*accountsv1.Value{{Kind: &accountsv1.Value_StringValue{StringValue: "alice@pi.lab"}}}},
				{Name: "mail", Values: []*accountsv1.Value{{Kind: &accountsv1.Value_StringValue{StringValue: "alice@pi.lab"}}}},
				{Name: "givenName", Values: []*accountsv1.Value{{Kind: &accountsv1.Value_StringValue{StringValue: "Alice"}}}},
				{Name: "sn", Values: []*accountsv1.Value{{Kind: &accountsv1.Value_StringValue{StringValue: "Example"}}}},
				{Name: "enabled", Values: []*accountsv1.Value{{Kind: &accountsv1.Value_BoolValue{BoolValue: true}}}},
			},
		},
		AppliedUsn: 42,
	}

	got, err := r.source.Get(context.Background(), "guid-1")
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Login)
	assert.Equal(t, "alice@pi.lab", got.UPN)
	assert.Equal(t, "alice@pi.lab", got.Email)
	assert.Equal(t, "Alice", got.GivenName)
	assert.Equal(t, "Example", got.Surname)
	assert.Equal(t, domain.UserStatusActive, got.Status)
	assert.Equal(t, int64(42), got.USN)

	// The header is signed for this procedure, by this service, for this id.
	require.NotEmpty(t, r.accounts.header)
	assert.Equal(t, "/pirectory.accounts.v1.AccountsService/Get", r.accounts.procedure)
	actor := decodeActor(t, r.accounts.header)
	assert.Equal(t, "guid-1", actor.GetPrincipalId())
	assert.Equal(t, ServiceName, actor.GetSigner())
	assert.Equal(t, "oidc", actor.GetAuthMethod())
	assert.NotEmpty(t, actor.GetNonce())
	require.NotNil(t, actor.GetIssuedAt())
	pub := r.signingKey.Public().(ed25519.PublicKey)
	require.True(t, ed25519.Verify(pub, message(r.accounts.procedure, actor), actor.GetSignature()),
		"the signature must be the one pir-accounts verifies")
}

func TestGetWithoutASignerGoesOutServiceOnly(t *testing.T) {
	r := newRig(t, false)
	r.accounts.get = &accountsv1.GetResponse{Object: &accountsv1.Object{Id: "guid-1"}}

	_, err := r.source.Get(context.Background(), "guid-1")
	require.NoError(t, err)
	assert.Empty(t, r.accounts.header, "no actor key configured means no acting principal")
}

func TestMembershipsNameTheGroups(t *testing.T) {
	r := newRig(t, true)
	r.accounts.membership = &accountsv1.ResolveMembershipResponse{
		Groups: []*accountsv1.GroupRef{
			{Id: "g1", Dn: "cn=engineering,cn=Users,dc=pi,dc=lab", Sid: "S-1-5-21-1", Depth: 1},
			{Id: "g2", Dn: "cn=Smith\\, John,cn=Users,dc=pi,dc=lab", Depth: 2},
		},
	}

	got, err := r.source.Memberships(context.Background(), "guid-1", true)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "engineering", got[0].Name)
	assert.Equal(t, "S-1-5-21-1", got[0].SID)
	assert.Equal(t, 1, got[0].Depth)
	assert.Equal(t, "Smith, John", got[1].Name)
	assert.Equal(t, "guid-1", decodeActor(t, r.accounts.header).GetPrincipalId())
}

func TestCommonName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"cn=engineering,cn=Users,dc=pi,dc=lab", "engineering"},
		{"cn=Smith\\, John,cn=Users,dc=pi,dc=lab", "Smith, John"},
		{"ou=people,dc=pi,dc=lab", "people"},
		{"dc=pi,dc=lab", "pi"},
		{"engineering", "engineering"},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, commonName(tc.in), tc.in)
	}
}

func TestNewOverMTLS(t *testing.T) {
	mux := http.NewServeMux()
	accounts := &fakeAccounts{resolveLogin: &accountsv1.ResolveLoginResponse{Id: "guid-1", Enabled: true}}
	credentials := &fakeCredentials{response: &credentialsv1.VerifyPasswordResponse{Result: credentialsv1.VerifyResult_VERIFY_RESULT_OK}}
	mux.Handle(accountsv1connect.NewAccountsServiceHandler(accounts))
	mux.Handle(credentialsv1connect.NewCredentialsServiceHandler(credentials))
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", server.Certificate().Raw)
	certFile, keyFile := writeClientCert(t, dir)

	src, err := New(Config{
		Addr:         server.URL,
		CAFile:       caFile,
		CertFile:     certFile,
		KeyFile:      keyFile,
		ActorKeyFile: writeActorKey(t, dir),
	})
	require.NoError(t, err)
	assert.Equal(t, identity.SourceDirectory, src.Name())

	ident, err := src.Resolve(context.Background(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "guid-1", ident.ID)
	assert.Equal(t, domain.UserStatusActive, ident.Status)
}

func TestNewFailsOnMissingOrBadMaterial(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{})
	require.ErrorContains(t, err, "addr is required")

	_, err = New(Config{Addr: "https://127.0.0.1:7443"})
	require.ErrorContains(t, err, "client certificate")

	_, err = New(Config{Addr: "https://127.0.0.1:7443", CertFile: "nope", KeyFile: "nope"})
	require.ErrorContains(t, err, "client certificate")

	_, err = New(Config{Addr: "https://127.0.0.1:7443", CertFile: "nope", KeyFile: "nope", CAFile: "nope"})
	require.ErrorContains(t, err, "client certificate")

	certFile, keyFile := writeClientCert(t, dir)
	_, err = New(Config{Addr: "https://127.0.0.1:7443", CertFile: certFile, KeyFile: keyFile, CAFile: "nope"})
	require.ErrorContains(t, err, "CA")

	_, err = New(Config{
		Addr: "https://127.0.0.1:7443", CertFile: certFile, KeyFile: keyFile,
		CAFile: writePEM(t, filepath.Join(dir, "empty-ca.pem"), "CERTIFICATE", []byte("not a certificate")),
	})
	require.ErrorContains(t, err, "holds no certificate")

	_, err = New(Config{
		Addr: "https://127.0.0.1:7443", CertFile: certFile, KeyFile: keyFile,
		CAFile: certFile, ActorKeyFile: "nope",
	})
	require.ErrorContains(t, err, "actor key")
}

func TestReadSigner(t *testing.T) {
	dir := t.TempDir()
	path := writeActorKey(t, dir)
	s, err := readSigner(ServiceName, path)
	require.NoError(t, err)
	assert.Equal(t, ServiceName, s.id)
	assert.Len(t, s.key, ed25519.PrivateKeySize)

	bad := filepath.Join(dir, "bad.key")
	require.NoError(t, os.WriteFile(bad, []byte("not base64\n"), 0o600))
	_, err = readSigner(ServiceName, bad)
	require.ErrorContains(t, err, "Ed25519")

	_, err = readSigner(ServiceName, filepath.Join(dir, "missing.key"))
	require.ErrorContains(t, err, "actor key")
}

func decodeActor(t *testing.T, header string) *commonv1.ActorContext {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(header)
	require.NoError(t, err)
	a := &commonv1.ActorContext{}
	require.NoError(t, proto.Unmarshal(raw, a))
	return a
}

func writePEM(t *testing.T, path, block string, der []byte) string {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: block, Bytes: der}))
	return path
}

// writeClientCert writes a self-signed client certificate for ServiceName.
// The fake server does not ask for it; the point is that New loads and
// presents it.
func writeClientCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ServiceName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certFile = writePEM(t, filepath.Join(dir, "client.pem"), "CERTIFICATE", der)

	enc, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyFile = writePEM(t, filepath.Join(dir, "client.key"), "EC PRIVATE KEY", enc)
	return certFile, keyFile
}

// writeActorKey writes an Ed25519 private key the way PiRectory's
// actor.WritePair does: base64 of the raw key.
func writeActorKey(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	path := filepath.Join(dir, "shadowsso-actor.key")
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600))
	return path
}
