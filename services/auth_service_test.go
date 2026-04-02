package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/api"
	client_mocks "github.com/pilab-dev/shadow-sso/client/mocks"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestAuthServer_Login_UserNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockPasswordHasher := mock_domain.NewMockPasswordHasher(ctrl)
	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		mockUserRepo,
		nil,
		mockTokenService,
		mockPasswordHasher,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()
	email := "test@example.com"

	mockUserRepo.EXPECT().GetUserByEmail(ctx, email).Return(nil, errors.New("user not found"))

	_, err := authServer.Login(ctx, connect.NewRequest(&ssov1.LoginRequest{
		Email:    email,
		Password: "password123",
	}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid email or password")

	ctrl.Finish()
}

func TestAuthServer_Login_AccountLocked(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockPasswordHasher := mock_domain.NewMockPasswordHasher(ctrl)
	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		mockUserRepo,
		nil,
		mockTokenService,
		mockPasswordHasher,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()
	email := "test@example.com"

	user := &domain.User{
		ID:     "user-id",
		Email:  email,
		Status: domain.UserStatusLocked,
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, email).Return(user, nil)

	_, err := authServer.Login(ctx, connect.NewRequest(&ssov1.LoginRequest{
		Email:    email,
		Password: "password123",
	}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account is locked")
}

func TestAuthServer_Login_AccountPending(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockPasswordHasher := mock_domain.NewMockPasswordHasher(ctrl)
	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		mockUserRepo,
		nil,
		mockTokenService,
		mockPasswordHasher,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()
	email := "test@example.com"

	user := &domain.User{
		ID:     "user-id",
		Email:  email,
		Status: domain.UserStatusPending,
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, email).Return(user, nil)

	_, err := authServer.Login(ctx, connect.NewRequest(&ssov1.LoginRequest{
		Email:    email,
		Password: "password123",
	}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account pending")
}

func TestAuthServer_Login_InvalidPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockPasswordHasher := mock_domain.NewMockPasswordHasher(ctrl)
	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		mockUserRepo,
		nil,
		mockTokenService,
		mockPasswordHasher,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()
	email := "test@example.com"

	user := &domain.User{
		ID:           "user-id",
		Email:        email,
		PasswordHash: "hashed-password",
		Status:       domain.UserStatusActive,
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, email).Return(user, nil)
	mockPasswordHasher.EXPECT().Verify(user.PasswordHash, "wrongpassword").Return(errors.New("invalid password"))

	_, err := authServer.Login(ctx, connect.NewRequest(&ssov1.LoginRequest{
		Email:    email,
		Password: "wrongpassword",
	}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid email or password")
}

func TestAuthServer_Login_With2FA(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockPasswordHasher := mock_domain.NewMockPasswordHasher(ctrl)
	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		mockUserRepo,
		nil,
		mockTokenService,
		mockPasswordHasher,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()
	email := "test@example.com"

	user := &domain.User{
		ID:                 "user-id",
		Email:              email,
		PasswordHash:       "hashed-password",
		Status:             domain.UserStatusActive,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
		TwoFactorSecret:    "secret",
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, email).Return(user, nil)
	mockPasswordHasher.EXPECT().Verify(user.PasswordHash, "password123").Return(nil)

	resp, err := authServer.Login(ctx, connect.NewRequest(&ssov1.LoginRequest{
		Email:    email,
		Password: "password123",
	}))

	require.NoError(t, err)
	assert.True(t, resp.Msg.TwoFactorRequired)
	assert.NotEmpty(t, resp.Msg.TwoFactorSessionToken)
}

func TestAuthServer_Login_Success_GeneratesTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockPasswordHasher := mock_domain.NewMockPasswordHasher(ctrl)
	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		mockUserRepo,
		mockSessionRepo,
		mockTokenService,
		mockPasswordHasher,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()
	email := "test@example.com"

	user := &domain.User{
		ID:           "user-id",
		Email:        email,
		PasswordHash: "hashed-password",
		Status:       domain.UserStatusActive,
	}

	mockUserRepo.EXPECT().GetUserByEmail(ctx, email).Return(user, nil)
	mockPasswordHasher.EXPECT().Verify(user.PasswordHash, "password123").Return(nil)
	mockTokenService.EXPECT().GenerateTokenPair(ctx, "sso-default-client", user.ID, "openid profile email offline_access", time.Hour).Return(&api.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil)
	mockSessionRepo.EXPECT().StoreSession(ctx, gomock.Any()).Return(nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	resp, err := authServer.Login(ctx, connect.NewRequest(&ssov1.LoginRequest{
		Email:    email,
		Password: "password123",
	}))

	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.AccessToken)
	assert.NotEmpty(t, resp.Msg.RefreshToken)
	assert.NotEmpty(t, resp.Msg.IdToken)
	assert.False(t, resp.Msg.TwoFactorRequired)
}

func TestAuthServer_ListUserSessions_NotAuthenticated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		mockUserRepo,
		nil,
		mockTokenService,
		nil,
		nil,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()

	_, err := authServer.ListUserSessions(ctx, connect.NewRequest(&ssov1.ListUserSessionsRequest{
		UserId: "user-id",
	}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authenticated")
}

func TestAuthServer_ListUserSessions_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		mockUserRepo,
		mockSessionRepo,
		mockTokenService,
		nil,
		nil,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()
	userID := "user-id"

	sessions := []*domain.Session{
		{ID: "session-1", UserID: userID},
		{ID: "session-2", UserID: userID},
	}

	tokenInfo := &domain.TokenInfo{
		UserID: userID,
		Roles:  []string{"user"},
	}
	ctx = context.WithValue(ctx, domain.TokenContextKey, tokenInfo)

	mockSessionRepo.EXPECT().ListSessionsByUserID(ctx, userID, domain.SessionFilter{}).Return(sessions, nil)

	resp, err := authServer.ListUserSessions(ctx, connect.NewRequest(&ssov1.ListUserSessionsRequest{
		UserId: userID,
	}))

	require.NoError(t, err)
	assert.Len(t, resp.Msg.Sessions, 2)
}

func TestAuthServer_GetConsentInfo_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		nil,
		nil,
		mockTokenService,
		nil,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()

	mockFlowStore.EXPECT().GetFlow("invalid-flow").Return(nil, domain.ErrFlowNotFound)

	_, err := authServer.GetConsentInfo(ctx, connect.NewRequest(&ssov1.GetConsentInfoRequest{
		FlowId: "invalid-flow",
	}))

	require.Error(t, err)
}

func TestAuthServer_GetConsentInfo_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		nil,
		nil,
		mockTokenService,
		nil,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()

	mockFlowStore.EXPECT().GetFlow("expired-flow").Return(nil, domain.ErrFlowExpired)

	_, err := authServer.GetConsentInfo(ctx, connect.NewRequest(&ssov1.GetConsentInfoRequest{
		FlowId: "expired-flow",
	}))

	require.Error(t, err)
}

func TestAuthServer_SubmitConsent_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		nil,
		nil,
		mockTokenService,
		nil,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()
	flowID := "flow-id"

	flowState := &domain.LoginFlowState{
		ClientID:            "client-id",
		Scope:               "openid profile email",
		RedirectURI:         "https://callback",
		State:               "state123",
		CodeChallenge:       "",
		CodeChallengeMethod: "",
		Nonce:               "",
		UserAuthenticatedAt: time.Now(),
	}

	mockFlowStore.EXPECT().GetFlow(flowID).Return(flowState, nil)
	mockOAuthService.EXPECT().GenerateAuthCode(ctx, "client-id", "", "https://callback", "openid profile email", "", "", "", flowState.UserAuthenticatedAt).Return("auth-code", nil)
	mockFlowStore.EXPECT().DeleteFlow(flowID).Return(nil)

	resp, err := authServer.SubmitConsent(ctx, connect.NewRequest(&ssov1.SubmitConsentRequest{
		FlowId:          flowID,
		AcceptedScopes:  []string{"openid", "profile", "email"},
		RememberConsent: true,
	}))

	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.RedirectUrl)
	assert.Contains(t, resp.Msg.RedirectUrl, "code=auth-code")
}

func TestAuthServer_DenyConsent_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockTokenService := mock_domain.NewMockTokenServiceInterface(ctrl)
	mockOAuthService := mock_domain.NewMockOAuthServiceInterface(ctrl)
	mockClientService := client_mocks.NewMockClientServiceInterface(ctrl)

	authServer := services.NewAuthServer(
		nil,
		nil,
		mockTokenService,
		nil,
		mockFlowStore,
		mockOAuthService,
		mockClientService,
	)

	ctx := context.Background()
	flowID := "flow-id"

	flowState := &domain.LoginFlowState{
		ClientID:    "client-id",
		Scope:       "openid profile email",
		RedirectURI: "https://callback",
		State:       "state123",
	}

	mockFlowStore.EXPECT().GetFlow(flowID).Return(flowState, nil)
	mockFlowStore.EXPECT().DeleteFlow(flowID).Return(nil)

	resp, err := authServer.DenyConsent(ctx, connect.NewRequest(&ssov1.DenyConsentRequest{
		FlowId: flowID,
	}))

	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.RedirectUrl)
	assert.Contains(t, resp.Msg.RedirectUrl, "error=access_denied")
}
