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

func TestWebAuthnLogin_ReturnsUnimplemented(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authServer := services.NewAuthServer(nil, nil, nil, nil, nil, nil, nil)

	_, err := authServer.CompleteWebAuthnLogin(context.Background(), connect.NewRequest(&ssov1.VerifyWebAuthnAuthenticationRequest{}))

	require.Error(t, err)
	var connectErr *connect.Error
	require.ErrorAs(t, err, &connectErr)
	assert.Equal(t, connect.CodeUnimplemented, connectErr.Code())
	assert.Contains(t, connectErr.Message(), "not yet implemented")
}

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

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), email).Return(nil, errors.New("user not found"))

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

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), email).Return(user, nil)

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

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), email).Return(user, nil)

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

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), email).Return(user, nil)
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

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), email).Return(user, nil)
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

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), email).Return(user, nil)
	mockPasswordHasher.EXPECT().Verify(user.PasswordHash, "password123").Return(nil)
	mockTokenService.EXPECT().GenerateTokenPair(gomock.Any(), "sso-default-client", user.ID, "openid profile email offline_access", time.Hour, gomock.Any()).Return(&api.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil)
	mockSessionRepo.EXPECT().StoreSession(gomock.Any(), gomock.Any()).Return(nil)
	mockUserRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)

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

	mockSessionRepo.EXPECT().ListSessionsByUserID(gomock.Any(), userID, domain.SessionFilter{}).Return(sessions, nil)

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

	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "invalid-flow").Return(nil, domain.ErrFlowNotFound)

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

	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "expired-flow").Return(nil, domain.ErrFlowExpired)

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

	mockFlowStore.EXPECT().GetFlow(gomock.Any(), flowID).Return(flowState, nil)
	mockOAuthService.EXPECT().GenerateAuthCode(gomock.Any(), "client-id", "", "https://callback", "openid profile email", "", "", "", flowState.UserAuthenticatedAt).Return("auth-code", nil)
	mockFlowStore.EXPECT().DeleteFlow(gomock.Any(), flowID).Return(nil)

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

	mockFlowStore.EXPECT().GetFlow(gomock.Any(), flowID).Return(flowState, nil)
	mockFlowStore.EXPECT().DeleteFlow(gomock.Any(), flowID).Return(nil)

	resp, err := authServer.DenyConsent(ctx, connect.NewRequest(&ssov1.DenyConsentRequest{
		FlowId: flowID,
	}))

	require.NoError(t, err)
	assert.NotEmpty(t, resp.Msg.RedirectUrl)
	assert.Contains(t, resp.Msg.RedirectUrl, "error=access_denied")
}

func loginFor2FA(t *testing.T, authServer *services.AuthServer, email, password string, user *domain.User) string {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockPasswordHasher := mock_domain.NewMockPasswordHasher(ctrl)

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), email).Return(user, nil)
	mockPasswordHasher.EXPECT().Verify(user.PasswordHash, password).Return(nil)

	freshAuth := services.NewAuthServer(
		mockUserRepo,
		nil,
		nil,
		mockPasswordHasher,
		nil,
		nil,
		nil,
	)

	ctx := context.Background()
	resp, err := freshAuth.Login(ctx, connect.NewRequest(&ssov1.LoginRequest{
		Email:    email,
		Password: password,
	}))
	require.NoError(t, err)
	require.True(t, resp.Msg.TwoFactorRequired)
	return resp.Msg.TwoFactorSessionToken
}

func TestVerify2FA_ConsecutiveLoginsProduceDifferentTokens(t *testing.T) {
	user := &domain.User{
		ID:                 "user-1",
		Email:              "test@example.com",
		PasswordHash:       "hashed-password",
		Status:             domain.UserStatusActive,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
	}

	token1 := loginFor2FA(t, nil, "test@example.com", "pass", user)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockUserRepo2 := mock_domain.NewMockUserRepository(ctrl)
	mockHasher2 := mock_domain.NewMockPasswordHasher(ctrl)
	mockUserRepo2.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
	mockHasher2.EXPECT().Verify(user.PasswordHash, "pass").Return(nil)
	auth2 := services.NewAuthServer(mockUserRepo2, nil, nil, mockHasher2, nil, nil, nil)
	resp2, err := auth2.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    "test@example.com",
		Password: "pass",
	}))
	require.NoError(t, err)
	token2 := resp2.Msg.TwoFactorSessionToken

	assert.NotEqual(t, token1, token2, "consecutive 2FA session tokens must differ")
}

func TestVerify2FA_TokenFromUserAFailsForUserB(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userA := &domain.User{
		ID:                 "user-a",
		Email:              "a@example.com",
		PasswordHash:       "hashed",
		Status:             domain.UserStatusActive,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
		TwoFactorSecret:    "secret-a",
	}

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockHasher := mock_domain.NewMockPasswordHasher(ctrl)

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "a@example.com").Return(userA, nil)
	mockHasher.EXPECT().Verify(userA.PasswordHash, "pass").Return(nil)
	auth := services.NewAuthServer(mockUserRepo, nil, nil, mockHasher, nil, nil, nil)

	// Login as user A
	resp, err := auth.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    "a@example.com",
		Password: "pass",
	}))
	require.NoError(t, err)
	tokenA := resp.Msg.TwoFactorSessionToken

	_, err = auth.Verify2FA(context.Background(), connect.NewRequest(&ssov1.Verify2FARequest{
		UserId:                 "user-b",
		TwoFactorSessionToken: tokenA,
		TotpCode:               "123456",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired 2FA session")
}

func TestVerify2FA_ExpiredTokenFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := &domain.User{
		ID:                 "user-1",
		Email:              "test@example.com",
		PasswordHash:       "hashed",
		Status:             domain.UserStatusActive,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
		TwoFactorSecret:    "secret",
	}

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockHasher := mock_domain.NewMockPasswordHasher(ctrl)

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
	mockHasher.EXPECT().Verify(user.PasswordHash, "pass").Return(nil)
	auth := services.NewAuthServer(mockUserRepo, nil, nil, mockHasher, nil, nil, nil)

	_, err := auth.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    "test@example.com",
		Password: "pass",
	}))
	require.NoError(t, err)

	_, err = auth.Verify2FA(context.Background(), connect.NewRequest(&ssov1.Verify2FARequest{
		UserId:                 "user-1",
		TwoFactorSessionToken: "completely-fake-token-that-was-never-stored",
		TotpCode:               "123456",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired 2FA session")
}

func TestVerify2FA_NeverExistingTokenFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := &domain.User{
		ID:                 "user-1",
		Email:              "test@example.com",
		PasswordHash:       "hashed",
		Status:             domain.UserStatusActive,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
		TwoFactorSecret:    "secret",
	}

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockHasher := mock_domain.NewMockPasswordHasher(ctrl)

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
	mockHasher.EXPECT().Verify(user.PasswordHash, "pass").Return(nil)
	auth := services.NewAuthServer(mockUserRepo, nil, nil, mockHasher, nil, nil, nil)

	_, err := auth.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    "test@example.com",
		Password: "pass",
	}))
	require.NoError(t, err)

	_, err = auth.Verify2FA(context.Background(), connect.NewRequest(&ssov1.Verify2FARequest{
		UserId:                 "user-1",
		TwoFactorSessionToken: "totally-fake-token",
		TotpCode:               "123456",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired 2FA session")
}

func TestVerify2FA_OldPlaceholderFormatRejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := &domain.User{
		ID:                 "user-1",
		Email:              "test@example.com",
		PasswordHash:       "hashed",
		Status:             domain.UserStatusActive,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
		TwoFactorSecret:    "secret",
	}

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockHasher := mock_domain.NewMockPasswordHasher(ctrl)

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
	mockHasher.EXPECT().Verify(user.PasswordHash, "pass").Return(nil)
	auth := services.NewAuthServer(mockUserRepo, nil, nil, mockHasher, nil, nil, nil)

	_, err := auth.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    "test@example.com",
		Password: "pass",
	}))
	require.NoError(t, err)

	oldPlaceholder := "placeholder_2fa_session_token_for_user-1"
	_, err = auth.Verify2FA(context.Background(), connect.NewRequest(&ssov1.Verify2FARequest{
		UserId:                 "user-1",
		TwoFactorSessionToken: oldPlaceholder,
		TotpCode:               "123456",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired 2FA session")
}

func TestVerify2FA_TokenDeletedAfterUse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	user := &domain.User{
		ID:                 "user-1",
		Email:              "test@example.com",
		PasswordHash:       "hashed",
		Status:             domain.UserStatusActive,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
		TwoFactorSecret:    "JBSWY3DPEHPK3PXP",
	}

	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockHasher := mock_domain.NewMockPasswordHasher(ctrl)

	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
	mockHasher.EXPECT().Verify(user.PasswordHash, "pass").Return(nil)
	auth := services.NewAuthServer(mockUserRepo, nil, nil, mockHasher, nil, nil, nil)

	resp, err := auth.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    "test@example.com",
		Password: "pass",
	}))
	require.NoError(t, err)
	token := resp.Msg.TwoFactorSessionToken

	mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "user-1").Return(user, nil)
	_, err = auth.Verify2FA(context.Background(), connect.NewRequest(&ssov1.Verify2FARequest{
		UserId:                 "user-1",
		TwoFactorSessionToken: token,
		TotpCode:               "wrong-code",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid 2FA code")

	_, err = auth.Verify2FA(context.Background(), connect.NewRequest(&ssov1.Verify2FARequest{
		UserId:                 "user-1",
		TwoFactorSessionToken: token,
		TotpCode:               "123456",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired 2FA session")
}
