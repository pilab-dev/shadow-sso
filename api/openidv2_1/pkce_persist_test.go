package openidv2_1

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	"github.com/pilab-dev/shadow-sso/services"
	services_mocks "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// memPkceRepo is an in-memory domain.PkceRepository fake that mirrors the
// Mongo repo's contract: challenges are keyed by authorization code.
type memPkceRepo struct {
	challenges map[string]string
	saves      int
}

func newMemPkceRepo() *memPkceRepo {
	return &memPkceRepo{challenges: make(map[string]string)}
}

func (r *memPkceRepo) SaveCodeChallenge(_ context.Context, code, challenge string) error {
	r.challenges[code] = challenge
	r.saves++
	return nil
}

func (r *memPkceRepo) GetCodeChallenge(_ context.Context, code string) (string, error) {
	challenge, ok := r.challenges[code]
	if !ok {
		return "", fmt.Errorf("code challenge not found for code: %s", code)
	}
	return challenge, nil
}

func (r *memPkceRepo) DeleteCodeChallenge(_ context.Context, code string) error {
	delete(r.challenges, code)
	return nil
}

func newTestAPIWithPkce(t *testing.T, pkceRepo domain.PkceRepository, authCode string) (*OAuth2API, *gomock.Controller) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)

	mockOAuthService := services_mocks.NewMockOAuthService(ctrl)
	mockOAuthService.EXPECT().
		GenerateAuthCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(authCode, nil).
		AnyTimes()

	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockClientRepo.EXPECT().
		GetClient(gomock.Any(), gomock.Any()).
		Return(&domain.Client{ID: "test-client", RequireConsent: false, Type: domain.ClientTypePublic}, nil).
		AnyTimes()

	api := NewOAuth2API(&OAuth2APIOptions{
		OAuthService:     mockOAuthService,
		ClientService:    client.NewClientService(mockClientRepo),
		PkceService:      services.NewPKCEService(pkceRepo),
		Config:           &sssoapi.OpenIDProviderConfig{NextJSLoginURL: "http://localhost:3000/login"},
		FlowStore:        oidcflow.NewInMemoryFlowStore(),
		UserSessionStore: oidcflow.NewInMemoryUserSessionStore(),
	})

	return api, ctrl
}

func TestCompleteAuthorizeAfterAuth_PersistsPKCEChallenge(t *testing.T) {
	pkceRepo := newMemPkceRepo()
	api, ctrl := newTestAPIWithPkce(t, pkceRepo, "test-code")
	defer ctrl.Finish()

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)

	authReqData := &authorizeRequestData{
		clientID:            "test-client",
		redirectURI:         "http://localhost/callback",
		responseType:        "code",
		scopeQuery:          "openid profile",
		state:               "state-123",
		nonce:               "nonce-123",
		codeChallenge:       codeChallenge,
		codeChallengeMethod: "S256",
	}
	flowState := &domain.LoginFlowState{
		FlowID:              "flow-1",
		ClientID:            "test-client",
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid profile",
		State:               "state-123",
		Nonce:               "nonce-123",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		UserID:              "user-1",
		UserAuthenticatedAt: time.Now(),
	}

	api.completeAuthorizeAfterAuth(c, authReqData, flowState)

	require.Equal(t, http.StatusFound, w.Code)

	// GetCodeChallenge is the read path ValidateCodeVerifier uses during token
	// exchange — it must now find the challenge that was persisted.
	stored, err := pkceRepo.GetCodeChallenge(c.Request.Context(), "test-code")
	require.NoError(t, err)
	require.Equal(t, codeChallenge, stored)
	require.Equal(t, 1, pkceRepo.saves)

	// Full round-trip: the code_verifier validates against the persisted challenge.
	require.NoError(t, api.pkceService.ValidateCodeVerifier(c.Request.Context(), "test-code", verifier))
}

func TestCompleteAuthorizeAfterAuth_SkipsSaveWhenNoChallenge(t *testing.T) {
	pkceRepo := newMemPkceRepo()
	api, ctrl := newTestAPIWithPkce(t, pkceRepo, "test-code")
	defer ctrl.Finish()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth2/authorize", nil)

	authReqData := &authorizeRequestData{
		clientID:     "test-client",
		redirectURI:  "http://localhost/callback",
		responseType: "code",
		scopeQuery:   "openid",
	}
	flowState := &domain.LoginFlowState{
		FlowID:      "flow-1",
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
		UserID:      "user-1",
	}

	api.completeAuthorizeAfterAuth(c, authReqData, flowState)

	require.Equal(t, http.StatusFound, w.Code)
	require.Zero(t, pkceRepo.saves, "no PKCE challenge should be persisted when code_challenge is empty")

	_, err := pkceRepo.GetCodeChallenge(c.Request.Context(), "test-code")
	require.Error(t, err)
}
