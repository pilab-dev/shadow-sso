package webauth_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	pkOrigin = "https://sso.test"
	pkRPID   = "sso.test"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// softAuthenticator is a minimal software passkey (ES256, "none" attestation, UV always on).
type softAuthenticator struct {
	key       *ecdsa.PrivateKey
	credID    []byte
	signCount uint32
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &softAuthenticator{key: k, credID: id}
}

func (a *softAuthenticator) clientData(t *testing.T, typ, challenge string) []byte {
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": pkOrigin, "crossOrigin": false})
	require.NoError(t, err)
	return b
}

func rpHash() []byte { h := sha256.Sum256([]byte(pkRPID)); return h[:] }

// register answers a navigator.credentials.create() request.
func (a *softAuthenticator) register(t *testing.T, challenge string) []byte {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	a.key.PublicKey.X.FillBytes(x)
	a.key.PublicKey.Y.FillBytes(y)
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	require.NoError(t, err)

	authData := append(rpHash(), 0x45) // UP | UV | AT
	authData = binary.BigEndian.AppendUint32(authData, a.signCount)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.credID)))
	authData = append(authData, a.credID...)
	authData = append(authData, cose...)

	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	require.NoError(t, err)
	out, err := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(a.clientData(t, "webauthn.create", challenge)),
			"attestationObject": b64(att),
			"transports":        []string{"internal"},
		},
	})
	require.NoError(t, err)
	return out
}

// assert answers a navigator.credentials.get() request for userHandle.
func (a *softAuthenticator) assert(t *testing.T, challenge string, userHandle []byte, signCount uint32) []byte {
	t.Helper()
	authData := append(rpHash(), 0x05) // UP | UV
	authData = binary.BigEndian.AppendUint32(authData, signCount)
	cd := a.clientData(t, "webauthn.get", challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	require.NoError(t, err)
	out, err := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64(cd), "authenticatorData": b64(authData),
			"signature": b64(sig), "userHandle": b64(userHandle),
		},
	})
	require.NoError(t, err)
	return out
}

type pkEnv struct {
	router *gin.Engine
	users  *mock_domain.MockUserRepository
	hasher *mock_domain.MockPasswordHasher
	flows  *mock_domain.MockFlowStore
	sso    *http.Cookie
	flow   *domain.LoginFlowState
}

func setupPasskeyTest(t *testing.T, enabled bool) *pkEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)
	e := &pkEnv{
		users:  mock_domain.NewMockUserRepository(ctrl),
		hasher: mock_domain.NewMockPasswordHasher(ctrl),
		flows:  mock_domain.NewMockFlowStore(ctrl),
		flow:   &domain.LoginFlowState{FlowID: "f1", ClientID: "c1", ExpiresAt: time.Now().Add(10 * time.Minute)},
	}
	opts := &webauth.Options{
		UserRepo: e.users, PasswordHasher: e.hasher, FlowStore: e.flows,
		Config: webauth.DefaultConfig(), SSOCookieSecret: raSecret,
	}
	if enabled {
		rp, err := webauth.NewWebAuthn(pkOrigin, "Test")
		require.NoError(t, err)
		opts.WebAuthn = rp
	}
	wa := webauth.New(opts)
	e.router = gin.New()
	e.router.LoadHTMLGlob("templates/*.html")
	e.router.GET("/static/:name", wa.StaticAssetHandler)
	e.router.GET("/account/passkeys", wa.AccountPasskeysPageHandler())
	e.router.POST("/account/passkeys/register/begin", wa.PasskeyRegisterBeginHandler())
	e.router.POST("/account/passkeys/register/finish", wa.PasskeyRegisterFinishHandler())
	e.router.POST("/account/passkeys/delete", wa.PasskeyDeleteSubmitHandler())
	e.router.POST("/login/passkey/begin", wa.PasskeyLoginBeginHandler)
	e.router.POST("/login/passkey/finish", wa.PasskeyLoginFinishHandler)

	rec := httptest.NewRecorder()
	require.NoError(t, webauth.SetSSOSessionCookie(rec, &ssosession.Session{SessionID: "s",
		Accounts: []ssosession.Account{{UserID: "u1", Email: "a@b.c", LastUsed: time.Now()}}}, false, raSecret))
	e.sso = rec.Result().Cookies()[0]
	return e
}

// jsonPost sends a request carrying the CSRF header/cookie and any extra cookies.
func (e *pkEnv) jsonPost(path string, body []byte, contentType string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-CSRF-Token", "csrf")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "csrf"})
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func challengeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out), w.Body.String())
	require.NotEmpty(t, out.PublicKey.Challenge)
	return out.PublicKey.Challenge
}

func TestPasskeys_DisabledWithoutRelyingParty(t *testing.T) {
	e := setupPasskeyTest(t, false)
	w := e.jsonPost("/login/passkey/begin", nil, "application/json")
	assert.Equal(t, http.StatusNotFound, w.Code)
	w = e.jsonPost("/login/passkey/finish", nil, "application/json")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPasskeys_StaticScriptServedOnlyForKnownName(t *testing.T) {
	e := setupPasskeyTest(t, true)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, httptest.NewRequest("GET", "/static/webauthn.js", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "javascript")
	assert.Contains(t, w.Body.String(), "parseCreationOptionsFromJSON")
	w = httptest.NewRecorder()
	e.router.ServeHTTP(w, httptest.NewRequest("GET", "/static/../../etc/passwd", nil))
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestPasskeys_RegisterThenLoginEndToEnd(t *testing.T) {
	e := setupPasskeyTest(t, true)
	auth := newSoftAuthenticator(t)
	user := &domain.User{ID: "u1", Email: "a@b.c", PasswordHash: "pw-hash", Status: domain.UserStatusActive}
	e.users.EXPECT().GetUserByID(gomock.Any(), "u1").DoAndReturn(func(_ any, _ string) (*domain.User, error) { return user, nil }).AnyTimes()

	// --- registration: begin (needs step-up + CSRF header) ---
	e.hasher.EXPECT().Verify("pw-hash", "hunter2").Return(nil)
	form := url.Values{"current_password": {"hunter2"}, "name": {"Laptop"}}.Encode()
	w := e.jsonPost("/account/passkeys/register/begin", []byte(form), "application/x-www-form-urlencoded", e.sso)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	ceremony := cookieNamed(w, "sso_webauthn")
	require.NotNil(t, ceremony, "challenge state must travel in the signed cookie")
	assert.True(t, ceremony.HttpOnly)
	challenge := challengeOf(t, w)
	assert.Contains(t, w.Body.String(), `"residentKey":"required"`, "passkeys must be discoverable")
	assert.Contains(t, w.Body.String(), `"userVerification":"required"`)

	// --- registration: finish ---
	var stored *domain.WebAuthnDevice
	e.users.EXPECT().AddWebAuthnDevice(gomock.Any(), "u1", gomock.Any()).DoAndReturn(
		func(_ any, _ string, d *domain.WebAuthnDevice) error {
			stored = d
			user.WebAuthnDevices = append(user.WebAuthnDevices, *d)
			return nil
		})
	w = e.jsonPost("/account/passkeys/register/finish", auth.register(t, challenge), "application/json", e.sso, ceremony)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotNil(t, stored)
	assert.Equal(t, "Laptop", stored.Name)
	assert.NotEmpty(t, stored.CredentialJSON)

	// The ceremony cookie is single-use: replaying finish with it must fail.
	w = e.jsonPost("/account/passkeys/register/finish", auth.register(t, challenge), "application/json", e.sso, ceremony)
	assert.Equal(t, http.StatusBadRequest, w.Code, "replayed registration must not add a second device")

	// --- login: begin ---
	e.flows.EXPECT().GetFlow(gomock.Any(), "f1").DoAndReturn(func(_ any, _ string) (*domain.LoginFlowState, error) {
		cp := *e.flow
		return &cp, nil
	}).AnyTimes()
	flowCookie := &http.Cookie{Name: "sso_oidc_flow_id", Value: "f1"}
	w = e.jsonPost("/login/passkey/begin", nil, "application/json", flowCookie)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	loginCeremony := cookieNamed(w, "sso_webauthn")
	require.NotNil(t, loginCeremony)
	loginChallenge := challengeOf(t, w)

	// A tampered ceremony cookie is rejected.
	tampered := &http.Cookie{Name: "sso_webauthn", Value: loginCeremony.Value[:len(loginCeremony.Value)-3] + "AAA"}
	w = e.jsonPost("/login/passkey/finish", auth.assert(t, loginChallenge, []byte("u1"), 1), "application/json", flowCookie, tampered)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// An assertion for a different challenge is rejected.
	other := auth.assert(t, b64([]byte("not-the-challenge-not-the-challenge!")), []byte("u1"), 1)
	w = e.jsonPost("/login/passkey/finish", other, "application/json", flowCookie, loginCeremony)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// --- login: finish with a valid assertion ---
	e.flows.EXPECT().UpdateFlow(gomock.Any(), "f1", gomock.Any()).DoAndReturn(func(_ any, _ string, s *domain.LoginFlowState) error {
		cp := *s
		e.flow = &cp
		return nil
	})
	e.users.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	w = e.jsonPost("/login/passkey/begin", nil, "application/json", flowCookie)
	loginCeremony, loginChallenge = cookieNamed(w, "sso_webauthn"), challengeOf(t, w)
	assertion := auth.assert(t, loginChallenge, []byte("u1"), 1)
	w = e.jsonPost("/login/passkey/finish", assertion, "application/json", flowCookie, loginCeremony)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"next":"/oauth2/authorize?flow_id=f1"}`, w.Body.String())
	assert.NotNil(t, cookieNamed(w, "sso_session"), "SSO cookie issued after a verified passkey")
	assert.True(t, e.flow.Authenticated(), "a passkey (user-verified) satisfies password and MFA")

	// Replaying the captured assertion with its cookie must not log in again.
	w = e.jsonPost("/login/passkey/finish", assertion, "application/json", flowCookie, loginCeremony)
	assert.NotEqual(t, http.StatusOK, w.Code, "a completed flow cannot be re-completed")
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// On a fresh flow, an assertion with a non-increasing sign counter is rejected as a possible clone.
	e.flow = &domain.LoginFlowState{FlowID: "f1", ClientID: "c1", ExpiresAt: time.Now().Add(10 * time.Minute)}
	w = e.jsonPost("/login/passkey/begin", nil, "application/json", flowCookie)
	loginCeremony, loginChallenge = cookieNamed(w, "sso_webauthn"), challengeOf(t, w)
	w = e.jsonPost("/login/passkey/finish", auth.assert(t, loginChallenge, []byte("u1"), 1), "application/json", flowCookie, loginCeremony)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "non-increasing sign counter must be rejected")
}

func TestPasskeys_RegisterRequiresCSRFAndStepUp(t *testing.T) {
	e := setupPasskeyTest(t, true)
	user := &domain.User{ID: "u1", Email: "a@b.c", PasswordHash: "pw-hash", Status: domain.UserStatusActive}
	e.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(user, nil).AnyTimes()

	// Missing CSRF header.
	req := httptest.NewRequest("POST", "/account/passkeys/register/begin", strings.NewReader("current_password=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(e.sso)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Wrong password.
	e.hasher.EXPECT().Verify("pw-hash", "wrong").Return(assert.AnError)
	w = e.jsonPost("/account/passkeys/register/begin", []byte("current_password=wrong"), "application/x-www-form-urlencoded", e.sso)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestPasskeys_LoginBeginRequiresLiveFlow(t *testing.T) {
	e := setupPasskeyTest(t, true)
	w := e.jsonPost("/login/passkey/begin", nil, "application/json") // no flow cookie
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
