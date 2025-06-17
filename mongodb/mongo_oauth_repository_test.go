package mongodb

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/ssso" // For ssso.Token, ssso.TokenInfo, ssso.TokenRepository
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	// "go.mongodb.org/mongo-driver/v2/bson"
)

// Helper function to setup DB for OAuthRepository (TokenRepository part) tests
func setupOAuthTokenRepoTest(t *testing.T) (ssso.TokenRepository, func(), error) {
	mongoURI := os.Getenv("TEST_MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	dbName := fmt.Sprintf("test_sso_oauth_repo_%d", time.Now().UnixNano())

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	// Direct client connection for test isolation
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI).SetConnectTimeout(10*time.Second))
	if err != nil {
		return nil, func() {}, fmt.Errorf("mongo.Connect failed for oauth repo test: %w", err)
	}
	if errPing := client.Ping(ctx, nil); errPing != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("mongo.Ping failed for oauth repo test: %w", errPing)
	}
	db := client.Database(dbName)

	// NewOAuthRepository returns a broader ssso.OAuthRepository,
	// but it also implements ssso.TokenRepository.
	oauthRepoExt, err := NewOAuthRepository(ctx, db)
	if err != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("NewOAuthRepository failed: %w", err)
	}

	var tokenRepo ssso.TokenRepository = oauthRepoExt // Ensure compatibility

	cleanupFunc := func() {
		mainCtx := context.Background()
		if errDbDrop := db.Drop(mainCtx); errDbDrop != nil {
			t.Logf("Warning: failed to drop database %s during cleanup: %v", dbName, errDbDrop)
		}
		if errDisconnect := client.Disconnect(mainCtx); errDisconnect != nil {
			t.Logf("Warning: failed to disconnect test client during cleanup: %v", errDisconnect)
		}
	}
	return tokenRepo, cleanupFunc, nil
}

func TestOAuthRepository_TokenMethods_Integration(t *testing.T) {
	if os.Getenv("TEST_MONGO_URI") == "" && os.Getenv("CI") != "" {
		t.Skip("Skipping MongoDB integration tests: TEST_MONGO_URI not set and CI environment detected.")
	}

	repo, cleanup, err := setupOAuthTokenRepoTest(t)
	require.NoError(t, err, "Failed to setup OAuthTokenRepository test")
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Using string literals for token types as constants like ssso.TokenTypeAccessToken might not be defined
	// or might be in api package. The actual values are "access_token", "refresh_token".
	accessTokenType := "access_token"
	refreshTokenType := "refresh_token"

	token1 := &ssso.Token{
		ID:         "token-id-1", // Manually set ID for predictability, repo uses this as _id
		TokenType:  accessTokenType,
		TokenValue: "access_token_value_1_unique",
		ClientID:   "client-for-tokens",
		UserID:     "user-for-tokens-1",
		Scope:      "read write",
		ExpiresAt:  now.Add(1 * time.Hour),
		CreatedAt:  now.Add(-1 * time.Minute),
		IsRevoked:  false,
		Issuer:     "sso-issuer",
	}

	refreshToken1 := &ssso.Token{
		ID:         "refresh-token-id-1",
		TokenType:  refreshTokenType,
		TokenValue: "refresh_token_value_1_unique",
		ClientID:   "client-for-tokens",
		UserID:     "user-for-tokens-1",
		Scope:      "offline_access",
		ExpiresAt:  now.Add(24 * time.Hour),
		CreatedAt:  now.Add(-1 * time.Minute),
		IsRevoked:  false,
		Issuer:     "sso-issuer",
	}

	t.Run("StoreTokenAndGetAccessToken", func(t *testing.T) {
		err := repo.StoreToken(ctx, token1)
		require.NoError(t, err, "StoreToken for token1 should succeed")

		fetchedToken, err := repo.GetAccessToken(ctx, token1.TokenValue)
		require.NoError(t, err, "GetAccessToken for token1 should succeed")
		require.NotNil(t, fetchedToken)
		assert.Equal(t, token1.ID, fetchedToken.ID)
		assert.Equal(t, token1.UserID, fetchedToken.UserID)
		assert.False(t, fetchedToken.IsRevoked)
		assert.WithinDuration(t, token1.ExpiresAt, fetchedToken.ExpiresAt, time.Second)

		// Store refresh token for other tests
		err = repo.StoreToken(ctx, refreshToken1)
		require.NoError(t, err, "StoreToken for refreshToken1 should succeed")
	})

	t.Run("GetAccessToken_NotFoundOrExpiredOrRevoked", func(t *testing.T) {
		// Not found
		_, err := repo.GetAccessToken(ctx, "non-existent-access-token")
		assert.Error(t, err)
		// The repo GetAccessToken method filters by token_type, is_revoked, and expiry.

		// Expired token
		expiredToken := &ssso.Token{
			ID: "expired-access", TokenType: accessTokenType, TokenValue: "expired_access_value_unique",
			UserID: "user-exp", ExpiresAt: now.Add(-1 * time.Minute), CreatedAt: now.Add(-2 * time.Minute),
		}
		err = repo.StoreToken(ctx, expiredToken)
		require.NoError(t, err)
		_, err = repo.GetAccessToken(ctx, expiredToken.TokenValue)
		assert.Error(t, err, "GetAccessToken for expired token should fail")

		// Revoked token
		revokedToken := &ssso.Token{
			ID: "revoked-access", TokenType: accessTokenType, TokenValue: "revoked_access_value_unique",
			UserID: "user-rev", ExpiresAt: now.Add(1 * time.Hour), IsRevoked: true, CreatedAt: now,
		}
		err = repo.StoreToken(ctx, revokedToken)
		require.NoError(t, err)
		_, err = repo.GetAccessToken(ctx, revokedToken.TokenValue)
		assert.Error(t, err, "GetAccessToken for revoked token should fail")
	})

	t.Run("RevokeToken", func(t *testing.T) {
		// token1 is currently active (or was, before this test runs; ensure it's findable before revoke)
		// Re-store token1 to ensure it's active for this test if previous tests modified it.
		token1.IsRevoked = false
		token1.ExpiresAt = time.Now().Add(time.Hour) // Ensure not expired
		// Need a unique TokenValue if StoreToken uses unique index on TokenValue
		token1.TokenValue = "access_token_value_for_revoke_test"
		errStore := repo.StoreToken(ctx, token1)
		require.NoError(t, errStore)


		err := repo.RevokeToken(ctx, token1.TokenValue)
		require.NoError(t, err, "RevokeToken for token1 should succeed")

		_, err = repo.GetAccessToken(ctx, token1.TokenValue)
		assert.Error(t, err, "GetAccessToken for token1 should fail after revocation")
	})

	t.Run("GetAccessTokenInfo_And_GetRefreshTokenInfo", func(t *testing.T) {
		// Ensure refreshToken1 is findable (active, not expired)
		refreshToken1.IsRevoked = false
		refreshToken1.ExpiresAt = time.Now().Add(24 * time.Hour)
		refreshToken1.TokenValue = "refresh_token_value_for_info_test" // Unique value
		errStoreRefresh := repo.StoreToken(ctx, refreshToken1)
		require.NoError(t, errStoreRefresh)


		activeAccessToken := &ssso.Token{
			ID: "active-info-access", TokenType: accessTokenType, TokenValue: "active_info_access_value_unique",
			UserID: "user-info", ClientID: "client-info", Scope: "info",
			ExpiresAt: now.Add(1 * time.Hour), CreatedAt: now, IsRevoked: false, Issuer: "sso-issuer",
		}
		err := repo.StoreToken(ctx, activeAccessToken)
		require.NoError(t, err)

		accessTokenInfo, err := repo.GetAccessTokenInfo(ctx, activeAccessToken.TokenValue)
		require.NoError(t, err, "GetAccessTokenInfo should succeed for active token")
		require.NotNil(t, accessTokenInfo)
		assert.Equal(t, activeAccessToken.ID, accessTokenInfo.ID)
		assert.Equal(t, activeAccessToken.UserID, accessTokenInfo.UserID)
		assert.Equal(t, activeAccessToken.Scope, accessTokenInfo.Scope)
		assert.False(t, accessTokenInfo.IsRevoked)

		refreshTokenInfo, err := repo.GetRefreshTokenInfo(ctx, refreshToken1.TokenValue)
		require.NoError(t, err, "GetRefreshTokenInfo should succeed for active refresh token")
		require.NotNil(t, refreshTokenInfo)
		assert.Equal(t, refreshToken1.ID, refreshTokenInfo.ID)
		assert.Equal(t, refreshToken1.UserID, refreshTokenInfo.UserID)
		assert.False(t, refreshTokenInfo.IsRevoked)

		// Test GetXxxInfo for non-existent token
		_, err = repo.GetAccessTokenInfo(ctx, "non-existent-for-info")
		assert.Error(t, err)
	})
}
