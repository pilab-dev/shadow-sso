// Package directory adapts PiRectory to the identity.IdentitySource port over
// ConnectRPC: accounts.v1 for identity and membership, credentials.v1 for the
// password check. It is the `pirectory` identity source.
//
// The transport is mTLS plus a signed ActorContext header, exactly the pair
// pir-accounts expects from a gateway: the certificate says which service is
// calling, the header says which directory principal the call is made for.
package directory

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/pilab-dev/shadow-sso/internal/identity"

	accountsv1connect "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/accounts/v1/accountsv1connect"
	credentialsv1connect "github.com/pilab-dev/shadow-sso/internal/directory/gen/pirectory/credentials/v1/credentialsv1connect"
)

// ServiceName is the mTLS identity this adapter presents, and therefore the
// signer name pir-accounts expects in the ActorContext header. It must match
// the `shadowsso` entry in the directory's allowed_callers.
const ServiceName = "shadowsso"

// Config is how the adapter reaches one pir-accounts node.
type Config struct {
	// Addr is the base URL of pir-accounts, e.g. https://127.0.0.1:7443.
	Addr string
	// CAFile verifies the server certificate; CertFile and KeyFile are the
	// client certificate for ServiceName.
	CAFile   string
	CertFile string
	KeyFile  string
	// ActorKeyFile is the Ed25519 key the acting principal is signed with.
	// accounts.Get and accounts.ResolveMembership refuse a call that carries
	// no acting principal, so it is required for anything but the login path
	// (ResolveLogin and VerifyPassword are service-only). Empty means no
	// header is ever sent.
	ActorKeyFile string
	// Timeout bounds a single directory call. Zero means 5s.
	Timeout time.Duration
}

// Source is the `pirectory` identity source.
type Source struct {
	accounts    accountsv1connect.AccountsServiceClient
	credentials credentialsv1connect.CredentialsServiceClient
	signer      *signer
	timeout     time.Duration
}

// New builds the source. It fails when the certificates or the actor key
// cannot be read, so a misconfigured deployment refuses to start instead of
// failing every login.
func New(cfg Config) (*Source, error) {
	if strings.TrimSpace(cfg.Addr) == "" {
		return nil, errors.New("directory: addr is required")
	}
	tlsCfg, err := tlsConfig(cfg)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var s *signer
	if cfg.ActorKeyFile != "" {
		if s, err = readSigner(ServiceName, cfg.ActorKeyFile); err != nil {
			return nil, err
		}
	}

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg, //nolint:gosec // the operator names their own CA
			Proxy: http.ProxyFromEnvironment},
		Timeout: timeout,
	}
	opts := []connect.ClientOption{}
	if s != nil {
		opts = append(opts, connect.WithInterceptors(s.interceptor()))
	}
	return &Source{
		accounts:    accountsv1connect.NewAccountsServiceClient(httpClient, cfg.Addr, opts...),
		credentials: credentialsv1connect.NewCredentialsServiceClient(httpClient, cfg.Addr, opts...),
		signer:      s,
		timeout:     timeout,
	}, nil
}

// Name implements identity.IdentitySource.
func (s *Source) Name() string { return identity.SourceDirectory }

func tlsConfig(cfg Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("directory: client certificate: %w", err)
	}
	pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // G304: the operator names their own CA
	if err != nil {
		return nil, fmt.Errorf("directory: CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("directory: CA file holds no certificate")
	}
	return &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// readSigner reads a base64 Ed25519 private key of the shape PiRectory's
// actor.WritePair produces.
func readSigner(id, path string) (*signer, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator names their own key
	if err != nil {
		return nil, fmt.Errorf("directory: actor key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("directory: actor key %s: want a base64 Ed25519 private key", path)
	}
	return &signer{id: id, key: ed25519.PrivateKey(decoded)}, nil
}
