package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/pilab-dev/shadow-sso/api"
	mock_cache "github.com/pilab-dev/shadow-sso/cache/mocks"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/services"
)

func TestGenerateTokenPair_OfflineAccessRefreshLifetime(t *testing.T) {
	for scope, wantTTL := range map[string]time.Duration{
		"openid":                24 * time.Hour,
		"openid offline_access": 90 * 24 * time.Hour,
	} {
		ctrl := gomock.NewController(t)
		repo := mock_domain.NewMockTokenRepository(ctrl)
		cache := mock_cache.NewMockTokenStore(ctrl)
		users := mock_domain.NewMockUserRepository(ctrl)
		signer := services.NewTokenSigner()
		signer.AddKeySigner("test-secret")
		ts := services.NewTokenService(repo, cache, "iss", signer,
			mock_domain.NewMockPublicKeyRepository(ctrl), mock_domain.NewMockServiceAccountRepository(ctrl),
			users, nil, nil, nil, nil)

		users.EXPECT().GetUserByID(gomock.Any(), gomock.Any()).Return(nil, errors.New("nf")).AnyTimes()
		cache.EXPECT().Set(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		var refreshTTL time.Duration
		repo.EXPECT().StoreToken(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tok *domain.Token) error {
			if tok.TokenType == api.TokenTypeRefreshToken {
				refreshTTL = time.Until(tok.ExpiresAt).Round(time.Hour)
			}
			return nil
		}).AnyTimes()

		_, err := ts.GenerateTokenPairWithSession(context.Background(), "c", "u", scope, time.Hour, "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, wantTTL, refreshTTL, scope)
		ctrl.Finish()
	}
}
