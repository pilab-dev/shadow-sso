package openidv2_1_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	sssoapi "github.com/pilab-dev/shadow-sso/api"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/services"
	services_mocks "github.com/pilab-dev/shadow-sso/services/mocks"
)

func TestUserInfoHandler_SignedResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)
	tokenSvc := services_mocks.NewMockTokenService(ctrl)
	userRepo := mock_domain.NewMockUserRepository(ctrl)
	clientRepo := mock_domain.NewMockClientRepository(ctrl)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "k.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600))
	signer := services.NewTokenSigner()
	require.NoError(t, signer.AddRSASigner(keyPath))

	api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		TokenService:  tokenSvc,
		UserRepo:      userRepo,
		TokenSigner:   signer,
		ClientService: client.NewClientService(clientRepo),
		Config:        &sssoapi.OpenIDProviderConfig{Issuer: "http://localhost"},
	})
	router := gin.New()
	api.RegisterRoutes(router)

	do := func(alg string) *httptest.ResponseRecorder {
		clientRepo.EXPECT().GetClient(gomock.Any(), "app").Return(&domain.Client{ID: "app", UserinfoSignedResponseAlg: alg}, nil)
		tokenSvc.EXPECT().ValidateAccessToken(gomock.Any(), "t").Return(&domain.Token{
			UserID: "u1", ClientID: "app", TokenType: "access_token", Scope: "openid email",
		}, nil)
		tokenSvc.EXPECT().ApplyTokenMappers(gomock.Any(), gomock.Any(), "app", "u1", "userinfo").Return(nil)
		userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{
			ID: "u1", Email: "a@b.c", Status: domain.UserStatusActive,
		}, nil)
		req := httptest.NewRequest("GET", "/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer t")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	w := do("RS256")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/jwt", w.Header().Get("Content-Type"))
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(w.Body.String(), claims, func(*jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("http://localhost"), jwt.WithAudience("app"))
	require.NoError(t, err)
	assert.Equal(t, "u1", claims["sub"])
	assert.Equal(t, "a@b.c", claims["email"])

	// the active key cannot satisfy a different registered algorithm
	assert.Equal(t, http.StatusInternalServerError, do("ES256").Code)
}
