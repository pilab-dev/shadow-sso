package services_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/cache"
	mock_cache "github.com/pilab-dev/shadow-sso/cache/mocks"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/internal/dpop"
	"github.com/pilab-dev/shadow-sso/internal/reqinfo"
	"github.com/pilab-dev/shadow-sso/services"
	"go.uber.org/mock/gomock"
)

func proofForTokenTest(t *testing.T, priv *rsa.PrivateKey, htu string) string {
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
	claims := jwt.MapClaims{"jti": "j1", "htm": "POST", "htu": htu, "iat": time.Now().Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header = header
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCreateToken_DPoPBinding(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockCache := mock_cache.NewMockTokenStore(ctrl)
	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	signer := services.NewTokenSigner()
	signer.AddKeySigner("test-secret")
	ts := services.NewTokenService(mockTokenRepo, mockCache, "test-issuer", signer,
		mock_domain.NewMockPublicKeyRepository(ctrl), mock_domain.NewMockServiceAccountRepository(ctrl),
		mockUserRepo, nil, nil, nil, nil)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	htu := "https://issuer.example/token"
	proof := proofForTokenTest(t, priv, htu)
	jkt, err := dpop.VerifyProof(proof, "POST", htu, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	ctx := reqinfo.WithContext(context.Background(), reqinfo.Info{Method: "POST", DPoPProof: proof, DPoPHTU: htu})
	mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "user-id").Return(nil, errors.New("not found"))
	mockTokenRepo.EXPECT().StoreToken(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tok *domain.Token) error {
		if tok.CnfJKT != jkt {
			t.Fatalf("token not bound: got %q want %q", tok.CnfJKT, jkt)
		}
		return nil
	})
	mockCache.EXPECT().Set(gomock.Any(), gomock.Any()).Return(nil)

	_, err = ts.CreateToken(ctx, domain.CreateTokenOptions{
		TokenID: "token-id", ClientID: "client", UserID: "user-id",
		TokenType: api.TokenTypeAccessToken, ExpireIn: time.Hour,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
}

var _ cache.TokenStore = (*mock_cache.MockTokenStore)(nil)
