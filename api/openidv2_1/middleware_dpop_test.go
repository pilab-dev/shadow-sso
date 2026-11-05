package openidv2_1

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/dpop"
	"github.com/pilab-dev/shadow-sso/services"
	mock_services "github.com/pilab-dev/shadow-sso/services/mocks"
	"go.uber.org/mock/gomock"
)

func makeDPoPProof(t *testing.T, priv *rsa.PrivateKey, method, htu, ath string) string {
	t.Helper()
	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "RS256",
		"jwk": map[string]string{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		},
	}
	claims := jwt.MapClaims{"jti": "j1", "htm": method, "htu": htu, "iat": time.Now().Unix(), "ath": ath}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header = header
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestUserAuthMiddleware_DPoPEnforcement(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ts := mock_services.NewMockTokenService(ctrl)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	access := "access-token-value"
	htu := "http://example.com/protected"
	ath := dpop.AccessTokenHash(access)
	proof := makeDPoPProof(t, priv, "POST", htu, ath)
	jkt, err := dpop.VerifyProof(proof, "POST", htu, ath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ts.EXPECT().ValidateAccessToken(gomock.Any(), access).Return(&domain.Token{
		ID: "jti", UserID: "user-1", CnfJKT: jkt, ExpiresAt: time.Now().Add(time.Hour),
	}, nil).Times(2)

	r := gin.New()
	r.POST("/protected", UserAuthMiddleware(ts), func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest("POST", htu, nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Missing proof must fail.
	req2 := httptest.NewRequest("POST", htu, nil)
	req2.Header.Set("Authorization", "Bearer "+access)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without proof, got %d", w2.Code)
	}
}

var _ services.TokenService = (*mock_services.MockTokenService)(nil)
