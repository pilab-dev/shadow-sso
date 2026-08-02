package services

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func createAuthenticatedContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, domain.TokenContextKey, &domain.TokenInfo{UserID: userID})
}

func TestUserServer_UpdateUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	existingUser := &domain.User{
		ID:        "user-123",
		Email:     "old@example.com",
		FirstName: "Old",
		LastName:  "Name",
		Roles:     []string{"user"},
		Status:    domain.UserStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(existingUser, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.Equal(t, "new@example.com", u.Email)
		assert.Equal(t, "New", u.FirstName)
		assert.Equal(t, "Name", u.LastName)
		assert.Equal(t, []string{"user", "admin"}, u.Roles)
		return nil
	})

	req := connect.NewRequest(&ssov1.UpdateUserRequest{
		UserId:    "user-123",
		Email:     "new@example.com",
		FirstName: "New",
		Roles:     []string{"user", "admin"},
	})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.UpdateUser(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.NotNil(t, resp.Msg.User)
	assert.Equal(t, "new@example.com", resp.Msg.User.Email)
	assert.Equal(t, "New", resp.Msg.User.FirstName)
}

func TestUserServer_DeleteUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().DeleteUser(gomock.Any(), "user-123").Return(nil)

	req := connect.NewRequest(&ssov1.DeleteUserRequest{UserId: "user-123"})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.DeleteUser(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, &emptypb.Empty{}, resp.Msg)
}

func TestUserServer_AddMfaMethod(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	existingUser := &domain.User{
		ID:         "user-123",
		Email:      "test@example.com",
		MfaMethods: []domain.MfaMethod{},
		Status:     domain.UserStatusActive,
	}

	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(existingUser, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.Len(t, u.MfaMethods, 1)
		assert.Equal(t, domain.MfaMethodTypeTOTP, u.MfaMethods[0].Type)
		return nil
	})

	req := connect.NewRequest(&ssov1.AddMfaMethodRequest{
		UserId: "user-123",
		Method: &ssov1.MfaMethod{
			Type:     ssov1.MfaMethodType_MFA_METHOD_TYPE_TOTP,
			Secret:   "JBSWY3DPEHPK3PXP",
			Name:     "Authenticator",
			Verified: false,
		},
	})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.AddMfaMethod(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.NotNil(t, resp.Msg.Method)
	assert.Equal(t, ssov1.MfaMethodType_MFA_METHOD_TYPE_TOTP, resp.Msg.Method.Type)
}

func TestUserServer_ListMfaMethods(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().ListMfaMethods(gomock.Any(), "user-123").Return([]domain.MfaMethod{
		{ID: "mfa-1", Type: domain.MfaMethodTypeTOTP, Name: "Authenticator", Verified: true},
		{ID: "mfa-2", Type: domain.MfaMethodTypeSMS, Name: "SMS", Verified: false},
	}, nil)

	req := connect.NewRequest(&ssov1.ListMfaMethodsRequest{UserId: "user-123"})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.ListMfaMethods(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.Len(t, resp.Msg.Methods, 2)
	assert.Equal(t, "mfa-1", resp.Msg.Methods[0].Id)
	assert.Equal(t, ssov1.MfaMethodType_MFA_METHOD_TYPE_TOTP, resp.Msg.Methods[0].Type)
}

func TestUserServer_RemoveMfaMethod(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().RemoveMfaMethod(gomock.Any(), "user-123", "mfa-1").Return(nil)

	req := connect.NewRequest(&ssov1.RemoveMfaMethodRequest{UserId: "user-123", MethodId: "mfa-1"})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.RemoveMfaMethod(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, &emptypb.Empty{}, resp.Msg)
}

func TestUserServer_AddWebAuthnDevice(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	existingUser := &domain.User{
		ID:              "user-123",
		Email:           "test@example.com",
		WebAuthnDevices: []domain.WebAuthnDevice{},
		Status:          domain.UserStatusActive,
	}

	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(existingUser, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.Len(t, u.WebAuthnDevices, 1)
		assert.Equal(t, "YubiKey", u.WebAuthnDevices[0].Name)
		return nil
	})

	req := connect.NewRequest(&ssov1.AddWebAuthnDeviceRequest{
		UserId: "user-123",
		Device: &ssov1.WebAuthnDevice{
			Name:         "YubiKey",
			CredentialId: "cred-123",
			PublicKey:    "base64pubkey",
			Counter:      0,
		},
	})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.AddWebAuthnDevice(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.NotNil(t, resp.Msg.Device)
	assert.Equal(t, "YubiKey", resp.Msg.Device.Name)
}

func TestUserServer_ListWebAuthnDevices(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().ListWebAuthnDevices(gomock.Any(), "user-123").Return([]domain.WebAuthnDevice{
		{ID: "webauthn-1", Name: "YubiKey 1", CredentialID: "cred-1", Counter: 10},
		{ID: "webauthn-2", Name: "YubiKey 2", CredentialID: "cred-2", Counter: 5},
	}, nil)

	req := connect.NewRequest(&ssov1.ListWebAuthnDevicesRequest{UserId: "user-123"})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.ListWebAuthnDevices(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.Len(t, resp.Msg.Devices, 2)
	assert.Equal(t, "webauthn-1", resp.Msg.Devices[0].Id)
}

func TestUserServer_RemoveWebAuthnDevice(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().RemoveWebAuthnDevice(gomock.Any(), "user-123", "webauthn-1").Return(nil)

	req := connect.NewRequest(&ssov1.RemoveWebAuthnDeviceRequest{UserId: "user-123", DeviceId: "webauthn-1"})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.RemoveWebAuthnDevice(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, &emptypb.Empty{}, resp.Msg)
}

func TestUserServer_IncrementFailedLoginAttempts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().IncrementFailedLoginAttempts(gomock.Any(), "user-123").Return(int32(3), nil)

	req := connect.NewRequest(&ssov1.IncrementFailedLoginAttemptsRequest{UserId: "user-123"})
	resp, err := service.IncrementFailedLoginAttempts(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	assert.Equal(t, int32(3), resp.Msg.CurrentAttempts)
}

func TestTwoFactorServer_InitiateTOTPSetup_ReturnsSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewTwoFactorServer(userRepo, nil, nil, nil, "ShadowSSO")

	existingUser := &domain.User{
		ID:    "user-123",
		Email: "test@example.com",
	}

	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(existingUser, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)

	req := connect.NewRequest(&ssov1.InitiateTOTPSetupRequest{})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.InitiateTOTPSetup(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	assert.NotEmpty(t, resp.Msg.Secret, "TOTP secret must be returned in API response for CLI enrollment")
	assert.NotEmpty(t, resp.Msg.QrCodeUri, "QR code URI must be returned")
}

func TestOTPGeneration(t *testing.T) {
	otp1 := generateSecureOTP(6)
	otp2 := generateSecureOTP(6)

	assert.Len(t, otp1, 6, "OTP should be 6 digits")
	assert.Len(t, otp2, 6, "OTP should be 6 digits")

	for _, ch := range otp1 {
		assert.True(t, ch >= '0' && ch <= '9', "OTP should only contain digits")
	}

	assert.NotEqual(t, otp1, otp2, "Consecutive OTPs should be different (cryptographic randomness)")
}

func TestChangePasswordAuthorization(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	hasher := mock_domain.NewMockPasswordHasher(ctrl)
	service := NewUserServer(userRepo, hasher, nil)

	t.Run("admin changes another user password succeeds", func(t *testing.T) {
		adminCtx := context.WithValue(context.Background(), domain.TokenContextKey, &domain.TokenInfo{
			UserID: "admin-user",
			Roles:  []string{"ROLE_ADMIN"},
		})

		userRepo.EXPECT().GetUserByID(gomock.Any(), "target-user").Return(&domain.User{
			ID:           "target-user",
			Email:        "target@example.com",
			PasswordHash: "old-hash",
			Status:       domain.UserStatusActive,
		}, nil)
		hasher.EXPECT().Hash("new-password").Return("new-hash", nil)
		userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)

		req := connect.NewRequest(&ssov1.ChangePasswordRequest{
			UserId:      "target-user",
			NewPassword: "new-password",
		})
		_, err := service.ChangePassword(adminCtx, req)
		assert.NoError(t, err)
	})

	t.Run("non-admin changes another user password denied", func(t *testing.T) {
		userCtx := context.WithValue(context.Background(), domain.TokenContextKey, &domain.TokenInfo{
			UserID: "regular-user",
			Roles:  []string{"ROLE_USER"},
		})

		userRepo.EXPECT().GetUserByID(gomock.Any(), "target-user").Return(&domain.User{
			ID:           "target-user",
			Email:        "target@example.com",
			PasswordHash: "old-hash",
			Status:       domain.UserStatusActive,
		}, nil)

		req := connect.NewRequest(&ssov1.ChangePasswordRequest{
			UserId:      "target-user",
			NewPassword: "new-password",
		})
		_, err := service.ChangePassword(userCtx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied")
	})

	t.Run("self-change works without admin role", func(t *testing.T) {
		selfCtx := context.WithValue(context.Background(), domain.TokenContextKey, &domain.TokenInfo{
			UserID: "target-user",
			Roles:  []string{"ROLE_USER"},
		})

		userRepo.EXPECT().GetUserByID(gomock.Any(), "target-user").Return(&domain.User{
			ID:           "target-user",
			Email:        "target@example.com",
			PasswordHash: "old-hash",
			Status:       domain.UserStatusActive,
		}, nil)
		hasher.EXPECT().Verify("old-hash", "current-password").Return(nil)
		hasher.EXPECT().Hash("new-password").Return("new-hash", nil)
		userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)

		req := connect.NewRequest(&ssov1.ChangePasswordRequest{
			UserId:      "target-user",
			OldPassword: "current-password",
			NewPassword: "new-password",
		})
		_, err := service.ChangePassword(selfCtx, req)
		assert.NoError(t, err)
	})
}

func TestUserServer_ResetFailedLoginAttempts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().ResetFailedLoginAttempts(gomock.Any(), "user-123").Return(nil)

	req := connect.NewRequest(&ssov1.ResetFailedLoginAttemptsRequest{UserId: "user-123"})
	resp, err := service.ResetFailedLoginAttempts(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, &emptypb.Empty{}, resp.Msg)
}

func TestUserServer_SetEmailAsVerified(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	existingUser := &domain.User{
		ID:              "user-123",
		Email:           "test@example.com",
		IsEmailVerified: false,
	}

	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(existingUser, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.True(t, u.IsEmailVerified)
		return nil
	})

	req := connect.NewRequest(&ssov1.SetEmailAsVerifiedRequest{UserId: "user-123"})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.SetEmailAsVerified(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, &emptypb.Empty{}, resp.Msg)
}

func TestUserServer_StorePasswordResetToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().StorePasswordResetToken(gomock.Any(), "user-123", "token-123", gomock.Any()).Return(nil)

	req := connect.NewRequest(&ssov1.StorePasswordResetTokenRequest{
		UserId:    "user-123",
		Token:     "token-123",
		ExpiresAt: timestamppb.New(time.Now().Add(1 * time.Hour)),
	})
	resp, err := service.StorePasswordResetToken(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, &emptypb.Empty{}, resp.Msg)
}

func TestUserServer_GetUserByPasswordResetToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	existingUser := &domain.User{
		ID:     "user-123",
		Email:  "test@example.com",
		Status: domain.UserStatusActive,
	}

	userRepo.EXPECT().GetUserByPasswordResetToken(gomock.Any(), "token-123").Return(existingUser, nil)

	req := connect.NewRequest(&ssov1.GetUserByPasswordResetTokenRequest{Token: "token-123"})
	resp, err := service.GetUserByPasswordResetToken(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.NotNil(t, resp.Msg.User)
	assert.Equal(t, "user-123", resp.Msg.User.Id)
}

func TestUserServer_StoreLoginOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().StoreLoginOtp(gomock.Any(), "user-123", "123456", "MFA_METHOD_TYPE_SMS", gomock.Any()).Return(nil)

	req := connect.NewRequest(&ssov1.StoreLoginOtpRequest{
		UserId:     "user-123",
		Otp:        "123456",
		MethodType: ssov1.MfaMethodType_MFA_METHOD_TYPE_SMS,
		ExpiresAt:  timestamppb.New(time.Now().Add(5 * time.Minute)),
	})
	resp, err := service.StoreLoginOtp(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, &emptypb.Empty{}, resp.Msg)
}

func TestUserServer_SetPhoneNumber(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	userRepo.EXPECT().SetPhoneNumber(gomock.Any(), "user-123", "+1234567890").Return(nil)

	req := connect.NewRequest(&ssov1.SetPhoneNumberRequest{
		UserId:      "user-123",
		PhoneNumber: "+1234567890",
	})
	resp, err := service.SetPhoneNumber(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, &emptypb.Empty{}, resp.Msg)
}

func TestUserServer_SendSmsOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	existingUser := &domain.User{
		ID:          "user-123",
		Email:       "test@example.com",
		PhoneNumber: "+1234567890",
	}

	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(existingUser, nil)
	userRepo.EXPECT().StoreLoginOtp(gomock.Any(), "user-123", gomock.Any(), "MFA_METHOD_TYPE_SMS", gomock.Any()).Return(nil)

	req := connect.NewRequest(&ssov1.SendSmsOtpRequest{UserId: "user-123"})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.SendSmsOtp(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	assert.True(t, resp.Msg.Success)
}

func TestUserServer_VerifyLoginOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	expiresAt := time.Now().Add(5 * time.Minute)
	existingUser := &domain.User{
		ID:                "user-123",
		Email:             "test@example.com",
		LoginOtp:          "123456",
		LoginOtpExpiresAt: &expiresAt,
	}

	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(existingUser, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.Empty(t, u.LoginOtp)
		return nil
	})

	req := connect.NewRequest(&ssov1.VerifyLoginOtpRequest{
		UserId: "user-123",
		Otp:    "123456",
	})
	resp, err := service.VerifyLoginOtp(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	assert.True(t, resp.Msg.Success)
}

func TestUserServer_SetupTotp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	existingUser := &domain.User{
		ID:    "user-123",
		Email: "test@example.com",
	}

	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(existingUser, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)

	req := connect.NewRequest(&ssov1.SetupTotpRequest{UserId: "user-123"})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	resp, err := service.SetupTotp(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	assert.Empty(t, resp.Msg.Secret, "Secret must not be returned in API response")
	assert.NotEmpty(t, resp.Msg.QrCodeUri, "QrCodeUri must still be returned")
}

func TestUserServer_VerifyEmail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	expiresAt := time.Now().Add(1 * time.Hour)
	existingUser := &domain.User{
		ID:                              "user-123",
		Email:                           "test@example.com",
		EmailVerificationToken:          "token-123",
		EmailVerificationTokenExpiresAt: &expiresAt,
		IsEmailVerified:                 false,
	}

	userRepo.EXPECT().GetUserByEmailVerificationToken(gomock.Any(), "token-123").Return(existingUser, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.True(t, u.IsEmailVerified)
		assert.Empty(t, u.EmailVerificationToken)
		return nil
	})

	req := connect.NewRequest(&ssov1.VerifyEmailRequest{Token: "token-123"})
	resp, err := service.VerifyEmail(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	assert.True(t, resp.Msg.Success)
}

func TestUserServer_ResetPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	hasher := mock_domain.NewMockPasswordHasher(ctrl)
	hasher.EXPECT().Hash(gomock.Any()).Return("new-hashed-password", nil)
	service := NewUserServer(userRepo, hasher, nil)

	expiresAt := time.Now().Add(1 * time.Hour)
	existingUser := &domain.User{
		ID:                          "user-123",
		Email:                       "test@example.com",
		PasswordHash:                "old-hash",
		PasswordResetToken:          "token-123",
		PasswordResetTokenExpiresAt: &expiresAt,
	}

	userRepo.EXPECT().GetUserByPasswordResetToken(gomock.Any(), "token-123").Return(existingUser, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.NotEqual(t, "old-hash", u.PasswordHash)
		assert.Empty(t, u.PasswordResetToken)
		return nil
	})

	req := connect.NewRequest(&ssov1.ResetPasswordRequest{
		Token:       "token-123",
		NewPassword: "new-hashed-password",
	})
	resp, err := service.ResetPassword(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	assert.True(t, resp.Msg.Success)
}

func TestUserServer_RegisterUser_DefaultRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	hasher := mock_domain.NewMockPasswordHasher(ctrl)
	service := NewUserServer(userRepo, hasher, nil)

	hasher.EXPECT().Hash("secret-password").Return("hashed", nil)
	userRepo.EXPECT().GetUserByEmail(gomock.Any(), "new@example.com").Return(nil, domain.ErrUserNotFound)
	userRepo.EXPECT().CreateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.Equal(t, []string{"ROLE_USER"}, u.Roles, "default role should be ROLE_USER")
		return nil
	})

	req := connect.NewRequest(&ssov1.RegisterUserRequest{
		Email:     "new@example.com",
		Password:  "secret-password",
		FirstName: "New",
		LastName:  "User",
	})
	ctx := createAuthenticatedContext(context.Background(), "admin-1")
	resp, err := service.RegisterUser(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg.User)
	assert.Equal(t, []string{"ROLE_USER"}, resp.Msg.User.Roles)
}

func TestUserServer_RegisterUser_RejectsWeakPasswordPerRealmPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	hasher := mock_domain.NewMockPasswordHasher(ctrl)
	realmSettingsRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	service := NewUserServer(userRepo, hasher, nil, WithUserRealmSettings(realmSettingsRepo))

	userRepo.EXPECT().GetUserByEmail(gomock.Any(), "new@example.com").Return(nil, domain.ErrUserNotFound)
	realmSettingsRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:             "master",
		PasswordMinLength: 12,
		PasswordUpperCase: 1,
		PasswordDigits:    1,
	}, nil)

	req := connect.NewRequest(&ssov1.RegisterUserRequest{
		Email:    "new@example.com",
		Password: "weak",
	})
	ctx := createAuthenticatedContext(context.Background(), "admin-1")
	_, err := service.RegisterUser(ctx, req)

	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestUserServer_RegisterUser_AcceptsPasswordMeetingRealmPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	hasher := mock_domain.NewMockPasswordHasher(ctrl)
	realmSettingsRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	service := NewUserServer(userRepo, hasher, nil, WithUserRealmSettings(realmSettingsRepo))

	realmSettingsRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:             "master",
		PasswordMinLength: 8,
		PasswordUpperCase: 1,
		PasswordDigits:    1,
	}, nil)
	userRepo.EXPECT().GetUserByEmail(gomock.Any(), "new@example.com").Return(nil, domain.ErrUserNotFound)
	hasher.EXPECT().Hash("StrongPass1").Return("hashed", nil)
	userRepo.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(nil)

	req := connect.NewRequest(&ssov1.RegisterUserRequest{
		Email:    "new@example.com",
		Password: "StrongPass1",
	})
	ctx := createAuthenticatedContext(context.Background(), "admin-1")
	resp, err := service.RegisterUser(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg.User)
}

func TestUserServer_ChangePassword_RejectsWeakPasswordPerRealmPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	hasher := mock_domain.NewMockPasswordHasher(ctrl)
	realmSettingsRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	service := NewUserServer(userRepo, hasher, nil, WithUserRealmSettings(realmSettingsRepo))

	existingUser := &domain.User{ID: "user-123", Email: "user@example.com", PasswordHash: "hashed-old"}
	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(existingUser, nil)
	hasher.EXPECT().Verify("hashed-old", "old-password").Return(nil)
	realmSettingsRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:             "master",
		PasswordMinLength: 12,
	}, nil)

	req := connect.NewRequest(&ssov1.ChangePasswordRequest{
		UserId:      "user-123",
		OldPassword: "old-password",
		NewPassword: "short",
	})
	ctx := createAuthenticatedContext(context.Background(), "user-123")
	_, err := service.ChangePassword(ctx, req)

	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestResolveUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	service := NewUserServer(userRepo, nil, nil)

	t.Run("returns user by ID when found", func(t *testing.T) {
		expected := &domain.User{ID: "mongo-id-123", Email: "user@example.com"}
		userRepo.EXPECT().GetUserByID(gomock.Any(), "mongo-id-123").Return(expected, nil)

		user, err := service.resolveUser(context.Background(), "mongo-id-123")
		require.NoError(t, err)
		assert.Equal(t, expected, user)
	})

	t.Run("falls back to email when ID not found", func(t *testing.T) {
		expected := &domain.User{ID: "mongo-id-456", Email: "fallback@example.com"}
		userRepo.EXPECT().GetUserByID(gomock.Any(), "fallback@example.com").Return(nil, domain.ErrUserNotFound)
		userRepo.EXPECT().GetUserByEmail(gomock.Any(), "fallback@example.com").Return(expected, nil)

		user, err := service.resolveUser(context.Background(), "fallback@example.com")
		require.NoError(t, err)
		assert.Equal(t, expected, user)
	})

	t.Run("propagates not-found when both ID and email miss", func(t *testing.T) {
		userRepo.EXPECT().GetUserByID(gomock.Any(), "nobody@example.com").Return(nil, domain.ErrUserNotFound)
		userRepo.EXPECT().GetUserByEmail(gomock.Any(), "nobody@example.com").Return(nil, domain.ErrUserNotFound)

		user, err := service.resolveUser(context.Background(), "nobody@example.com")
		require.Nil(t, user)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})
}
