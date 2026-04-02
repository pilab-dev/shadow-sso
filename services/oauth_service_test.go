package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

func createOAuthService(ctrl *gomock.Controller) *services.OAuthService {
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
	mockSessionRepo.EXPECT().StoreSession(ctx, gomock.Any()).Return(nil)
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, "oauth-service-login-client", user.ID, "openid profile email", time.Hour).Return(&api.TokenResponse{
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

	mockUserRepo.EXPECT().GetUserByEmail(ctx, username).Return(nil, errors.New("user not found"))

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

	mockSessionRepo.EXPECT().ListSessionsByUserID(ctx, userID, domain.SessionFilter{}).Return(sessions, nil)

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
	mockTokenServiceInterface.EXPECT().GenerateTokenPairWithFamily(ctx, clientID, tokenInfo.UserID, tokenInfo.Scope, time.Hour, tokenInfo.RefreshTokenFamily, "", gomock.Any()).Return(&api.TokenResponse{
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil)

	resp, err := oauthService.RefreshToken(ctx, refreshTokenValue, clientID)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
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
	mockTokenRepo.EXPECT().RevokeTokenFamily(ctx, "family-123").Return(nil)

	_, err := oauthService.RefreshToken(ctx, refreshTokenValue, clientID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token reused")
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

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)

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

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(nil, errors.New("not found"))

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

	client := &domain.Client{
		ID:     clientID,
		Secret: "correct-secret",
	}

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)

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

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
	mockUserRepo.EXPECT().GetUserByEmail(ctx, username).Return(user, nil)
	mockSessionRepo.EXPECT().StoreSession(ctx, gomock.Any()).Return(nil)
	mockTokenRepo.EXPECT().StoreToken(ctx, gomock.Any()).Return(nil)

	resp, err := oauthService.DirectGrant(ctx, clientID, clientSecret, username, password, "openid")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
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

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)

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

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
	mockTokenServiceInterface.EXPECT().CreateToken(ctx, gomock.Any(), nil).Return(&domain.Token{
		ID:         "token-id",
		TokenValue: "access-token-value",
		TokenType:  "access_token",
		ClientID:   clientID,
		ExpiresAt:  time.Now().Add(time.Hour),
	}, nil)

	resp, err := oauthService.ClientCredentials(ctx, clientID, clientSecret, "openid")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
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
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, client.ID, user.ID, scope, time.Hour).Return(&api.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil)

	resp, err := oauthService.PasswordGrant(ctx, username, password, scope, client)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
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

	client := &domain.Client{
		ID:     clientID,
		Secret: clientSecret,
	}

	authCode := &domain.AuthCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		UserID:      "user-id",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
	mockAuthCodeRepo.EXPECT().GetAuthCode(ctx, code).Return(authCode, nil)
	mockAuthCodeRepo.EXPECT().MarkAuthCodeAsUsed(ctx, code).Return(nil)
	mockTokenServiceInterface.EXPECT().GenerateTokenPairWithFamily(ctx, clientID, authCode.UserID, authCode.Scope, time.Hour, "", "", time.Time{}).Return(&api.TokenResponse{
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

	client := &domain.Client{
		ID:     clientID,
		Secret: clientSecret,
	}

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
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

	client := &domain.Client{
		ID:     clientID,
		Secret: clientSecret,
	}

	authCode := &domain.AuthCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		UserID:      "user-id",
		ExpiresAt:   time.Now().Add(-time.Minute),
		Used:        false,
	}

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
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

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
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

	mockClientRepo.EXPECT().GetClient(ctx, "invalid-client").Return(nil, errors.New("not found"))

	_, err := oauthService.IntrospectToken(ctx, "token", "", "invalid-client", "secret")

	require.Error(t, err)
}

func TestOAuthService_RevokeToken(t *testing.T) {
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

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
	mockTokenServiceInterface.EXPECT().RevokeToken(ctx, "token-to-revoke").Return(nil)

	err := oauthService.RevokeToken(ctx, "token-to-revoke", "", clientID, clientSecret)

	require.NoError(t, err)
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

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)
	mockAuthCodeRepo.EXPECT().SaveAuthCode(ctx, gomock.Any()).Return(nil)

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

	mockClientRepo.EXPECT().GetClient(ctx, clientID).Return(client, nil)

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
	assert.NotEmpty(t, resp.VerificationURI)
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
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, clientID, "user-id", "openid", time.Hour).Return(&api.TokenResponse{
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
	mockTokenServiceInterface.EXPECT().GenerateTokenPair(ctx, clientID, "user-id", scope, time.Hour).Return(&api.TokenResponse{
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
