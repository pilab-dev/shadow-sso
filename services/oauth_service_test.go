package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

func createOAuthService(ctrl *gomock.Controller) services.OAuthService {
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	return services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)
}

func TestOAuthService_RegisterUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	username := "test@example.com"
	password := "password123"

	mockUserRepo.EXPECT().CreateUser(ctx, gomock.Any()).Return(nil)

	user, err := oauthService.RegisterUser(ctx, username, password)

	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, username, user.Email)
	assert.Equal(t, domain.UserStatusActive, user.Status)
}

func TestOAuthService_RegisterUser_CreateError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	username := "test@example.com"
	password := "password123"

	mockUserRepo.EXPECT().CreateUser(ctx, gomock.Any()).Return(errors.New("database error"))

	_, err := oauthService.RegisterUser(ctx, username, password)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create user")
}

func TestOAuthService_Login_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	username := "test@example.com"
	password := "password123"
	deviceInfo := "Mozilla/5.0"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        username,
		PasswordHash: string(hashedPassword),
		Status:       domain.UserStatusActive,
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, username).Return(user, nil)
	mockSessionRepo.EXPECT().ListSessionsByUserID(gomock.Any(), user.ID, gomock.Any()).Return(nil, nil)
	mockSessionRepo.EXPECT().StoreSession(ctx, gomock.Any()).Return(nil)
	mockSessionRepo.EXPECT().StoreSessionEvent(gomock.Any(), gomock.Any()).Return(nil)
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, "oauth-service-login-client", user.ID, "openid profile email", time.Hour, gomock.Any()).Return(&api.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil)

	resp, err := oauthService.Login(ctx, username, password, deviceInfo)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestOAuthService_Login_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	username := "test@example.com"
	password := "password123"

	mockUserRepo.EXPECT().GetUserByEmail(ctx, username).Return(nil, domain.ErrUserNotFound)

	_, err := oauthService.Login(ctx, username, password, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestOAuthService_Login_InvalidCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	username := "test@example.com"
	password := "wrongpassword"

	user := &domain.User{
		ID:           "user-id",
		Email:        username,
		PasswordHash: "$2a$10$abcdefghijklmnopqrstuvwxyz1234567890",
		Status:       domain.UserStatusActive,
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, username).Return(user, nil)

	_, err := oauthService.Login(ctx, username, password, "")

	require.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
}

func TestOAuthService_GetUserSessions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	userID := "user-id"

	sessions := []*domain.Session{
		{ID: "session-1", UserID: userID},
		{ID: "session-2", UserID: userID},
	}

	mockSessionRepo.EXPECT().ListSessionsByUserID(ctx, userID, gomock.Any()).Return(sessions, nil)

	result, err := oauthService.GetUserSessions(ctx, userID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestOAuthService_RefreshToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	refreshTokenValue := "refresh-token"
	clientID := "client-id"

	tokenInfo := &domain.TokenInfo{
		ID:                 "token-id",
		ClientID:           clientID,
		UserID:             "user-id",
		Scope:              "openid profile",
		ExpiresAt:          time.Now().Add(time.Hour),
		IsRevoked:          false,
		RefreshTokenFamily: "family-123",
	}

	mockTokenRepo.EXPECT().GetRefreshTokenInfo(ctx, refreshTokenValue).Return(tokenInfo, nil)
	mockTokenRepo.EXPECT().RevokeRefreshToken(ctx, refreshTokenValue).Return(nil)
	mockTokenRepo.EXPECT().MarkRefreshTokenUsed(ctx, refreshTokenValue, "").Return(nil)
	mockTokenServiceInterface.EXPECT().
		GenerateTokenPairWithSession(ctx, clientID, tokenInfo.UserID, tokenInfo.Scope, time.Hour, "", "family-123", "token-id").
		Return(&api.TokenResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}, nil)

	resp, err := oauthService.RefreshToken(ctx, refreshTokenValue, clientID)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestOAuthService_RefreshToken_ReplayRevokesFamilyAndSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	usedAt := time.Now().Add(-time.Minute)
	tokenInfo := &domain.TokenInfo{
		ID:                 "token-id",
		ClientID:           "client-id",
		UserID:             "user-id",
		Scope:              "openid",
		ExpiresAt:          time.Now().Add(time.Hour),
		IsRevoked:          true,
		UsedAt:             &usedAt,
		RefreshTokenFamily: "family-123",
		SessionID:          "session-1",
	}
	sess := &domain.Session{ID: "session-1", UserID: "user-id", ExpiresAt: time.Now().Add(time.Hour)}

	mockTokenRepo.EXPECT().GetRefreshTokenInfo(ctx, "replayed").Return(tokenInfo, nil)
	mockTokenRepo.EXPECT().RevokeTokenFamily(ctx, "family-123").Return(nil)
	mockSessionRepo.EXPECT().GetSessionByID(ctx, "session-1").Return(sess, nil)
	mockSessionRepo.EXPECT().UpdateSession(ctx, gomock.Any()).Return(nil)
	mockTokenRepo.EXPECT().RevokeTokensBySessionID(ctx, "session-1").Return(nil)
	// No new token pair may be issued.

	_, err := oauthService.RefreshToken(ctx, "replayed", "client-id")

	require.Error(t, err)
	var oauthErr *domain.OAuth2Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, domain.InvalidGrant, oauthErr.Code)
}

func TestOAuthService_RefreshToken_RejectsRevokedSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	tokenInfo := &domain.TokenInfo{
		ID:                 "token-id",
		ClientID:           "client-id",
		UserID:             "user-id",
		Scope:              "openid",
		ExpiresAt:          time.Now().Add(time.Hour),
		RefreshTokenFamily: "family-123",
		SessionID:          "session-1",
	}
	kicked := &domain.Session{ID: "session-1", IsRevoked: true, ExpiresAt: time.Now().Add(time.Hour)}

	mockTokenRepo.EXPECT().GetRefreshTokenInfo(ctx, "refresh").Return(tokenInfo, nil)
	mockSessionRepo.EXPECT().GetSessionByID(ctx, "session-1").Return(kicked, nil)

	_, err := oauthService.RefreshToken(ctx, "refresh", "client-id")

	require.Error(t, err)
	var oauthErr *domain.OAuth2Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, domain.InvalidGrant, oauthErr.Code)
}

func TestOAuthService_RefreshToken_InvalidToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	refreshTokenValue := "invalid-token"
	clientID := "client-id"

	mockTokenRepo.EXPECT().GetRefreshTokenInfo(ctx, refreshTokenValue).Return(nil, errors.New("token not found"))

	_, err := oauthService.RefreshToken(ctx, refreshTokenValue, clientID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
}

func TestOAuthService_RefreshToken_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	refreshTokenValue := "expired-token"
	clientID := "client-id"

	tokenInfo := &domain.TokenInfo{
		ID:                 "token-id",
		ClientID:           clientID,
		UserID:             "user-id",
		ExpiresAt:          time.Now().Add(-time.Hour),
		IsRevoked:          false,
		RefreshTokenFamily: "family-123",
	}

	mockTokenRepo.EXPECT().GetRefreshTokenInfo(ctx, refreshTokenValue).Return(tokenInfo, nil)

	_, err := oauthService.RefreshToken(ctx, refreshTokenValue, clientID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token expired")
}

func TestOAuthService_RefreshToken_Revoked(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	refreshTokenValue := "revoked-token"
	clientID := "client-id"

	tokenInfo := &domain.TokenInfo{
		ID:                 "token-id",
		ClientID:           clientID,
		UserID:             "user-id",
		ExpiresAt:          time.Now().Add(time.Hour),
		IsRevoked:          true,
		RefreshTokenFamily: "family-123",
	}

	mockTokenRepo.EXPECT().GetRefreshTokenInfo(ctx, refreshTokenValue).Return(tokenInfo, nil)

	_, err := oauthService.RefreshToken(ctx, refreshTokenValue, clientID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token expired or revoked")
}

func TestOAuthService_GetJWKS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	jwks := oauthService.GetJWKS()

	assert.NotNil(t, jwks)
	assert.NotNil(t, jwks.Keys)
}

func TestOAuthService_ValidateClient_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "client-id"
	clientSecret := "secret"

	client := &domain.Client{
		ID:     clientID,
		Secret: clientSecret,
	}

	mockClientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)

	result, err := oauthService.ValidateClient(ctx, clientID, clientSecret)

	require.NoError(t, err)
	assert.Equal(t, clientID, result.ID)
}

func TestOAuthService_ValidateClient_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "unknown-client"
	clientSecret := "secret"

	mockClientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(nil, errors.New("not found"))

	_, err := oauthService.ValidateClient(ctx, clientID, clientSecret)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "client not found")
}

func TestOAuthService_ValidateClient_InvalidSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "client-id"
	clientSecret := "wrong-secret"

	mockClientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(nil, domain.ErrInvalidClientCredentials)

	_, err := oauthService.ValidateClient(ctx, clientID, clientSecret)

	require.Error(t, err)
	assert.Equal(t, domain.ErrInvalidClientCredentials, err)
}

func TestOAuthService_DirectGrant_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "client-id"
	clientSecret := "secret"
	username := "user@example.com"
	password := "password"

	client := &domain.Client{
		ID:                clientID,
		Secret:            clientSecret,
		AllowedGrantTypes: []string{"password"},
		AllowedScopes:     []string{"openid", "profile"},
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        username,
		PasswordHash: string(hashedPassword),
	}

	mockClientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)
	mockUserRepo.EXPECT().GetUserByEmail(ctx, username).Return(user, nil)
	mockSessionRepo.EXPECT().ListSessionsByUserID(gomock.Any(), user.ID, gomock.Any()).Return(nil, nil)
	mockSessionRepo.EXPECT().StoreSession(ctx, gomock.Any()).Return(nil)
	mockSessionRepo.EXPECT().StoreSessionEvent(gomock.Any(), gomock.Any()).Return(nil)
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, clientID, user.ID, "openid", gomock.Any(), gomock.Any()).Return(&api.TokenResponse{
		AccessToken:  "jwt-access-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "jwt-refresh-token",
	}, nil)

	resp, err := oauthService.DirectGrant(ctx, clientID, clientSecret, username, password, "openid")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "jwt-access-token", resp.AccessToken)
	assert.Equal(t, "jwt-refresh-token", resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

func TestOAuthService_DirectGrant_InvalidGrantType(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "client-id"
	clientSecret := "secret"

	client := &domain.Client{
		ID:                clientID,
		Secret:            clientSecret,
		AllowedGrantTypes: []string{"authorization_code"},
		AllowedScopes:     []string{"openid"},
	}

	mockClientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)

	_, err := oauthService.DirectGrant(ctx, clientID, clientSecret, "user", "password", "openid")

	require.Error(t, err)
	assert.Equal(t, domain.ErrInvalidConfig, err)
}

func TestOAuthService_ClientCredentials_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "client-id"
	clientSecret := "secret"

	client := &domain.Client{
		ID:                clientID,
		Secret:            clientSecret,
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{"openid", "profile"},
	}

	mockClientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)
	mockTokenServiceInterface.EXPECT().CreateToken(ctx, gomock.Any(), nil).Return(&domain.Token{
		ID:         "token-id",
		TokenValue: "access-token-value",
		TokenType:  "access_token",
		ClientID:   clientID,
		ExpiresAt:  time.Now().Add(time.Hour),
	}, nil)

	resp, err := oauthService.ClientCredentials(ctx, clientID, clientSecret, "openid", nil)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestOAuthService_ClientCredentials_AudienceSubjectAndGroups(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	const (
		clientID     = "sa-1234@pilab.iam.sso.dev"
		clientSecret = "secret"
	)

	client := &domain.Client{
		ID:                  clientID,
		Secret:              clientSecret,
		AllowedGrantTypes:   []string{"client_credentials"},
		AllowedScopes:       []string{"openid"},
		AllowedAudiences:    []string{"kubernetes"},
		ServiceAccountRoles: []string{"k8s-view"},
	}

	mockClientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)
	mockTokenServiceInterface.EXPECT().
		CreateToken(gomock.Any(), gomock.Any(), nil).
		DoAndReturn(func(_ context.Context, opts domain.CreateTokenOptions, _ jwt.Claims) (*domain.Token, error) {
			assert.Equal(t, clientID, opts.Subject, "client_credentials tokens need a non-empty sub")
			assert.Empty(t, opts.UserID)
			assert.Equal(t, []string{"kubernetes"}, opts.Audience)
			assert.Equal(t, []string{"k8s-view"}, opts.Roles)
			assert.Equal(t, []string{"k8s-view"}, opts.Groups, "groups fall back to roles when not set")
			return &domain.Token{
				ID:         "token-id",
				TokenValue: "access-token-value",
				TokenType:  "access_token",
				ClientID:   clientID,
				ExpiresAt:  time.Now().Add(time.Hour),
			}, nil
		})

	resp, err := oauthService.ClientCredentials(ctx, clientID, clientSecret, "openid", []string{"kubernetes"})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "access-token-value", resp.AccessToken)
}

func TestOAuthService_ClientCredentials_AudienceNotAllowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	const (
		clientID     = "client-id"
		clientSecret = "secret"
	)

	// No AllowedAudiences: the client may only mint tokens for itself.
	client := &domain.Client{
		ID:                clientID,
		Secret:            clientSecret,
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{"openid"},
	}

	mockClientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)
	// CreateToken must not be called.

	resp, err := oauthService.ClientCredentials(ctx, clientID, clientSecret, "openid", []string{"kubernetes"})

	require.Error(t, err)
	assert.Nil(t, resp)

	var oauthErr *domain.OAuth2Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, domain.InvalidTarget, oauthErr.Code)
}

func TestOAuthService_IssueClientCredentialsForClient_SkipsSecretValidation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	client := &domain.Client{
		ID:                "sa-private-key-jwt@pilab.iam.sso.dev",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{"openid"},
		AllowedAudiences:  []string{"kubernetes"},
	}

	// No ValidateClient expectation: the client was authenticated with a
	// private_key_jwt assertion and has no secret to re-validate.
	mockTokenServiceInterface.EXPECT().CreateToken(gomock.Any(), gomock.Any(), nil).Return(&domain.Token{
		ID:         "token-id",
		TokenValue: "access-token-value",
		TokenType:  "access_token",
		ClientID:   client.ID,
		ExpiresAt:  time.Now().Add(time.Hour),
	}, nil)

	resp, err := oauthService.IssueClientCredentialsForClient(ctx, client, "openid", []string{"kubernetes"})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "access-token-value", resp.AccessToken)
}

func TestOAuthService_PasswordGrant_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	username := "user@example.com"
	password := "password"
	scope := "openid"

	client := &domain.Client{
		ID:            "client-id",
		AllowedScopes: []string{"openid", "profile"},
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        username,
		PasswordHash: string(hashedPassword),
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, username).Return(user, nil)
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, client.ID, user.ID, scope, time.Hour, "").Return(&api.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil)

	resp, err := oauthService.PasswordGrant(ctx, username, password, scope, client)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestOAuthService_PasswordGrant_UsesRealmAccessTokenLifespan(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockRealmSettingsRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
		services.WithRealmSettings(mockRealmSettingsRepo),
	)

	ctx := context.Background()
	username := "user@example.com"
	password := "password"
	scope := "openid"

	client := &domain.Client{
		ID:            "client-id",
		AllowedScopes: []string{"openid", "profile"},
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        username,
		PasswordHash: string(hashedPassword),
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, username).Return(user, nil)
	mockRealmSettingsRepo.EXPECT().GetRealmSettings(ctx).Return(&domain.RealmSettings{
		Realm:               "master",
		AccessTokenLifespan: 1500,
	}, nil)
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, client.ID, user.ID, scope, 1500*time.Second, "").Return(&api.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    1500,
	}, nil)

	resp, err := oauthService.PasswordGrant(ctx, username, password, scope, client)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestOAuthService_PasswordGrant_RealmTTLZero_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockRealmSettingsRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
		services.WithRealmSettings(mockRealmSettingsRepo),
	)

	ctx := context.Background()
	username := "user@example.com"
	password := "password"
	scope := "openid"

	client := &domain.Client{
		ID:            "client-id",
		AllowedScopes: []string{"openid", "profile"},
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &domain.User{
		ID:           "user-id",
		Email:        username,
		PasswordHash: string(hashedPassword),
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, username).Return(user, nil)
	mockRealmSettingsRepo.EXPECT().GetRealmSettings(ctx).Return(&domain.RealmSettings{
		Realm:               "master",
		AccessTokenLifespan: 0,
	}, nil)

	_, err := oauthService.PasswordGrant(ctx, username, password, scope, client)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "access token lifespan")
}

func TestOAuthService_ExchangeAuthorizationCode_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	code := "auth-code"
	clientID := "client-id"
	clientSecret := "secret"
	redirectURI := "https://callback"

	authCode := &domain.AuthCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		UserID:      "user-id",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}

	mockAuthCodeRepo.EXPECT().GetAuthCode(ctx, code).Return(authCode, nil)
	mockAuthCodeRepo.EXPECT().MarkAuthCodeAsUsed(ctx, code).Return(nil)
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, clientID, authCode.UserID, authCode.Scope, time.Hour, "").Return(&api.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil)

	resp, err := oauthService.ExchangeAuthorizationCode(ctx, code, clientID, clientSecret, redirectURI)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestOAuthService_ExchangeAuthorizationCode_InvalidCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	code := "invalid-code"
	clientID := "client-id"
	clientSecret := "secret"
	redirectURI := "https://callback"

	mockAuthCodeRepo.EXPECT().GetAuthCode(ctx, code).Return(nil, errors.New("code not found"))

	_, err := oauthService.ExchangeAuthorizationCode(ctx, code, clientID, clientSecret, redirectURI)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid authorization code")
}

func TestOAuthService_ExchangeAuthorizationCode_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	code := "expired-code"
	clientID := "client-id"
	clientSecret := "secret"
	redirectURI := "https://callback"

	authCode := &domain.AuthCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		UserID:      "user-id",
		ExpiresAt:   time.Now().Add(-time.Minute),
		Used:        false,
	}

	mockAuthCodeRepo.EXPECT().GetAuthCode(ctx, code).Return(authCode, nil)

	_, err := oauthService.ExchangeAuthorizationCode(ctx, code, clientID, clientSecret, redirectURI)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired or already used")
}

func TestOAuthService_IntrospectToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	token := "access-token"
	clientID := "client-id"
	clientSecret := "secret"

	client := &domain.Client{
		ID:     clientID,
		Secret: clientSecret,
	}

	tokenInfo := &domain.TokenInfo{
		ID:        "token-id",
		TokenType: "access_token",
		ClientID:  clientID,
		UserID:    "user-id",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	user := &domain.User{
		ID:    "user-id",
		Email: "user@example.com",
	}

	mockClientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)
	mockTokenServiceInterface.EXPECT().GetAccessTokenInfo(ctx, token).Return(tokenInfo, nil)
	mockUserRepo.EXPECT().GetUserByID(ctx, "user-id").Return(user, nil)

	resp, err := oauthService.IntrospectToken(ctx, token, "access_token", clientID, clientSecret)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Active)
	assert.Equal(t, "user-id", resp.Sub)
}

func TestOAuthService_IntrospectToken_InvalidClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()

	mockClientRepo.EXPECT().ValidateClient(ctx, "invalid-client", "secret").Return(nil, errors.New("not found"))

	_, err := oauthService.IntrospectToken(ctx, "token", "", "invalid-client", "secret")

	require.Error(t, err)
}

func TestOAuthService_RevokeToken(t *testing.T) {
	setup := func(t *testing.T) (services.OAuthService, *mock_domain.MockTokenRepository, *mock_domain.MockClientRepository, *mock_domain.MockTokenServiceInterface) {
		ctrl := gomock.NewController(t)
		mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
		mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
		mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
		svc := services.NewOAuthService(
			mockTokenRepo,
			mock_domain.NewMockAuthorizationCodeRepository(ctrl),
			mock_domain.NewMockDeviceAuthorizationRepository(ctrl),
			mockClientRepo,
			mock_domain.NewMockUserRepository(ctrl),
			mock_domain.NewMockSessionRepository(ctrl),
			mockTokenService,
			"test-issuer",
		)
		return svc, mockTokenRepo, mockClientRepo, mockTokenService
	}

	ctx := context.Background()
	clientID := "client-id"
	clientSecret := "secret"
	client := &domain.Client{ID: clientID, Secret: clientSecret}

	t.Run("owner revokes access token", func(t *testing.T) {
		svc, _, clientRepo, tokenSvc := setup(t)
		clientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)
		tokenSvc.EXPECT().GetAccessTokenInfo(ctx, "token-to-revoke").Return(&domain.TokenInfo{ClientID: clientID}, nil)
		tokenSvc.EXPECT().RevokeToken(ctx, "token-to-revoke").Return(nil)

		require.NoError(t, svc.RevokeToken(ctx, "token-to-revoke", "", clientID, clientSecret))
	})

	t.Run("foreign client cannot revoke", func(t *testing.T) {
		svc, _, clientRepo, tokenSvc := setup(t)
		clientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)
		tokenSvc.EXPECT().GetAccessTokenInfo(ctx, "other-token").Return(&domain.TokenInfo{ClientID: "someone-else"}, nil)

		require.NoError(t, svc.RevokeToken(ctx, "other-token", "", clientID, clientSecret))
	})

	t.Run("owner revokes refresh token and its family", func(t *testing.T) {
		svc, tokenRepo, clientRepo, tokenSvc := setup(t)
		clientRepo.EXPECT().ValidateClient(ctx, clientID, clientSecret).Return(client, nil)
		tokenSvc.EXPECT().GetRefreshTokenInfo(ctx, "rt").Return(&domain.TokenInfo{ClientID: clientID, RefreshTokenFamily: "fam"}, nil)
		tokenRepo.EXPECT().RevokeRefreshToken(ctx, "rt").Return(nil)
		tokenRepo.EXPECT().RevokeTokenFamily(ctx, "fam").Return(nil)

		require.NoError(t, svc.RevokeToken(ctx, "rt", "refresh_token", clientID, clientSecret))
	})
}

func TestOAuthService_GenerateAuthCode_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "client-id"
	userID := "user-id"
	redirectURI := "https://callback"
	scope := "openid"

	client := &domain.Client{
		ID:            clientID,
		AllowedScopes: []string{"openid", "profile"},
	}

	mockClientRepo.EXPECT().GetClient(gomock.Any(), clientID).Return(client, nil)
	mockSessionRepo.EXPECT().ListSessionsByUserID(gomock.Any(), userID, gomock.Any()).Return(nil, nil)
	mockSessionRepo.EXPECT().StoreSession(gomock.Any(), gomock.Any()).Return(nil)
	mockSessionRepo.EXPECT().StoreSessionEvent(gomock.Any(), gomock.Any()).Return(nil)
	mockAuthCodeRepo.EXPECT().SaveAuthCode(gomock.Any(), gomock.Any()).Return(nil)

	code, err := oauthService.GenerateAuthCode(ctx, clientID, userID, redirectURI, scope, "", "", "", time.Now())

	require.NoError(t, err)
	assert.NotEmpty(t, code)
}

func TestOAuthService_GenerateAuthCode_InvalidScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "client-id"

	client := &domain.Client{
		ID:            clientID,
		AllowedScopes: []string{"openid"},
	}

	mockClientRepo.EXPECT().GetClient(gomock.Any(), clientID).Return(client, nil)

	_, err := oauthService.GenerateAuthCode(ctx, clientID, "user-id", "https://callback", "admin", "", "", "", time.Now())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "requested scope not allowed")
}

func TestOAuthService_InitiateDeviceAuthorization_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "client-id"
	scope := "openid"
	verificationBaseURI := "https://device"

	client := &domain.Client{
		ID:            clientID,
		AllowedScopes: []string{"openid"},
	}

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
	mockDeviceAuthRepo.EXPECT().SaveDeviceAuth(ctx, gomock.Any()).Return(nil)

	resp, err := oauthService.InitiateDeviceAuthorization(ctx, clientID, scope, verificationBaseURI)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.DeviceCode)
	assert.NotEmpty(t, resp.UserCode)
	assert.Equal(t, "https://device/oauth2/device/verify", resp.VerificationURI)
	assert.Equal(t, "https://device/oauth2/device/verify?user_code="+resp.UserCode, resp.VerificationURIComplete)
}

func TestOAuthService_InitiateDeviceAuthorization_InvalidScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	clientID := "client-id"

	client := &domain.Client{
		ID:            clientID,
		AllowedScopes: []string{"openid"},
	}

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)

	_, err := oauthService.InitiateDeviceAuthorization(ctx, clientID, "admin", "https://device")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "requested scope not allowed")
}

func TestOAuthService_VerifyUserCode_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	userCode := "ABCD-1234"
	userID := "user-id"

	deviceCode := &domain.DeviceCode{
		UserCode:  userCode,
		Status:    domain.DeviceCodeStatusPending,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	mockDeviceAuthRepo.EXPECT().GetDeviceAuthByUserCode(ctx, userCode).Return(deviceCode, nil)
	mockDeviceAuthRepo.EXPECT().ApproveDeviceAuth(ctx, userCode, userID).Return(deviceCode, nil)

	result, err := oauthService.VerifyUserCode(ctx, userCode, userID)

	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestOAuthService_VerifyUserCode_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	userCode := "invalid-code"

	mockDeviceAuthRepo.EXPECT().GetDeviceAuthByUserCode(ctx, userCode).Return(nil, domain.ErrUserCodeNotFound)

	_, err := oauthService.VerifyUserCode(ctx, userCode, "user-id")

	require.Error(t, err)
	assert.Equal(t, domain.ErrUserCodeNotFound, err)
}

func TestOAuthService_IssueTokenForDeviceFlow_Authorized(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	deviceCode := "device-code"
	clientID := "client-id"

	deviceAuth := &domain.DeviceCode{
		DeviceCode: deviceCode,
		ClientID:   clientID,
		UserID:     "user-id",
		Scope:      "openid",
		Status:     domain.DeviceCodeStatusAuthorized,
	}

	mockDeviceAuthRepo.EXPECT().GetDeviceAuthByDeviceCode(ctx, deviceCode).Return(deviceAuth, nil)
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, clientID, "user-id", "openid", time.Hour, "").Return(&api.TokenResponse{
		AccessToken: "access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil)
	mockDeviceAuthRepo.EXPECT().UpdateDeviceAuthStatus(ctx, deviceCode, domain.DeviceCodeStatusRedeemed).Return(nil)

	resp, err := oauthService.IssueTokenForDeviceFlow(ctx, deviceCode, clientID)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestOAuthService_IssueTokenForDeviceFlow_Pending(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	deviceCode := "device-code"
	clientID := "client-id"

	deviceAuth := &domain.DeviceCode{
		DeviceCode: deviceCode,
		ClientID:   clientID,
		Status:     domain.DeviceCodeStatusPending,
	}

	mockDeviceAuthRepo.EXPECT().GetDeviceAuthByDeviceCode(ctx, deviceCode).Return(deviceAuth, nil)
	mockDeviceAuthRepo.EXPECT().UpdateDeviceAuthLastPolledAt(ctx, deviceCode).Return(nil)

	_, err := oauthService.IssueTokenForDeviceFlow(ctx, deviceCode, clientID)

	require.Error(t, err)
	assert.Equal(t, domain.ErrAuthorizationPending, err)
}

func TestOAuthService_TokenExchange_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	subjectToken := "access-token"
	subjectTokenType := "urn:ietf:params:oauth:token-type:access_token"
	clientID := "client-id"
	scope := "openid"

	client := &domain.Client{
		ID:            clientID,
		AllowedScopes: []string{"openid", "profile"},
	}

	mockTokenServiceInterface.EXPECT().ValidateAccessToken(ctx, subjectToken).Return(&domain.Token{
		ID:        "token-id",
		ClientID:  clientID,
		UserID:    "user-id",
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: false,
	}, nil)
	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, clientID, "user-id", scope, time.Hour, "").Return(&api.TokenResponse{
		AccessToken: "exchanged-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil)

	resp, err := oauthService.TokenExchange(ctx, subjectToken, subjectTokenType, "", "", scope, clientID)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestOAuthService_TokenExchange_InvalidSubjectTokenType(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()

	_, err := oauthService.TokenExchange(ctx, "token", "invalid", "", "", "", "client-id")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported subject_token_type")
}

func TestOAuthService_TokenExchange_ExpiredSubjectToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	subjectToken := "expired-token"
	subjectTokenType := "urn:ietf:params:oauth:token-type:access_token"
	clientID := "client-id"

	mockTokenServiceInterface.EXPECT().ValidateAccessToken(ctx, subjectToken).Return(nil, domain.ErrTokenExpiredOrRevoked)

	_, err := oauthService.TokenExchange(ctx, subjectToken, subjectTokenType, "", "", "", clientID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid subject token")
}

func TestOAuthService_TokenExchange_ScopeIntersection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	mockAuthCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenServiceInterface := mock_domain.NewMockTokenServiceInterface(ctrl)

	oauthService := services.NewOAuthService(
		mockTokenRepo,
		mockAuthCodeRepo,
		mockDeviceAuthRepo,
		mockClientRepo,
		mockUserRepo,
		mockSessionRepo,
		mockTokenServiceInterface,
		"test-issuer",
	)

	ctx := context.Background()
	subjectToken := "access-token"
	subjectTokenType := "urn:ietf:params:oauth:token-type:access_token"
	clientID := "client-id"

	tests := []struct {
		name           string
		requestedScope string
		grantedScope   string
		expectedScope  string
		expectError    bool
	}{
		{
			name:           "requested is subset of granted",
			requestedScope: "openid",
			grantedScope:   "openid profile email",
			expectedScope:  "openid",
			expectError:    false,
		},
		{
			name:           "requested equals granted",
			requestedScope: "openid profile",
			grantedScope:   "openid profile",
			expectedScope:  "openid profile",
			expectError:    false,
		},
		{
			name:           "requested exceeds granted - partial overlap",
			requestedScope: "openid profile admin",
			grantedScope:   "openid profile",
			expectedScope:  "openid profile",
			expectError:    false,
		},
		{
			name:           "requested exceeds granted - no overlap",
			requestedScope: "admin write",
			grantedScope:   "openid profile",
			expectedScope:  "",
			expectError:    true,
		},
		{
			name:           "empty requested uses granted",
			requestedScope: "",
			grantedScope:   "openid profile",
			expectedScope:  "openid profile",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &domain.Client{
				ID:            clientID,
				AllowedScopes: []string{"openid", "profile"},
			}

			mockTokenServiceInterface.EXPECT().ValidateAccessToken(ctx, subjectToken).Return(&domain.Token{
				ID:        "token-id",
				ClientID:  clientID,
				UserID:    "user-id",
				Scope:     tt.grantedScope,
				ExpiresAt: time.Now().Add(time.Hour),
				IsRevoked: false,
			}, nil)
			mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)

			if !tt.expectError {
				mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, clientID, "user-id", tt.expectedScope, time.Hour, "").Return(&api.TokenResponse{
					AccessToken: "exchanged-access-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}, nil)
			}

			resp, err := oauthService.TokenExchange(ctx, subjectToken, subjectTokenType, "", "", tt.requestedScope, clientID)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "scope")
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, resp.AccessToken)
			}
		})
	}
}
