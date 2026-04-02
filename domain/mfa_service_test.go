package domain_test

import (
	"context"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	mocks "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNewMFAService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)
	require.NotNil(t, service)
	// Test that service is created (internal fields are not accessible from test package)
	assert.NotNil(t, service)
}

func TestNewMFAServiceWithConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)

	config := domain.MFAConfig{
		MaxOTPRequestsPerHour: 10,
		MaxOTPAttemptsPerHour: 20,
		OTPRequestWindow:      30 * time.Minute,
		OTPAttemptWindow:      30 * time.Minute,
		OTPExpiryDuration:     10 * time.Minute,
	}

	service := domain.NewMFAServiceWithConfig(mockUserRepo, mockEmailService, config)
	require.NotNil(t, service)
	// Test that service is created with config (internal fields are not accessible from test package)
	assert.NotNil(t, service)
}

func TestMFAService_InitiateEmailMFASetup_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:              userID,
		Email:           "test@example.com",
		FirstName:       "Test",
		LastName:        "User",
		EmailMFAEnabled: false,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().StoreEmailMFAOtp(ctx, userID, gomock.Any(), gomock.Any()).Return(nil)
	mockEmailService.EXPECT().SendMFAEmail("test@example.com", "Test User", gomock.Any(), "EMAIL").Return(nil)

	err := service.InitiateEmailMFASetup(ctx, userID)
	assert.NoError(t, err)
}

func TestMFAService_InitiateEmailMFASetup_AlreadyEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:              userID,
		EmailMFAEnabled: true,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.InitiateEmailMFASetup(ctx, userID)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrEmailMFAAlreadyEnabled, err)
}

func TestMFAService_InitiateEmailMFASetup_RateLimit(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	now := time.Now()
	recentTime := now.Add(-30 * time.Second)
	user := &domain.User{
		ID:                 userID,
		EmailMFAEnabled:    false,
		EmailMFALastSentAt: &recentTime,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.InitiateEmailMFASetup(ctx, userID)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrRateLimitExceeded, err)
}

func TestMFAService_VerifyAndEnableEmailMFA_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	otp := "123456"
	expiresAt := time.Now().Add(5 * time.Minute)
	user := &domain.User{
		ID:                   userID,
		EmailMFAEnabled:      false,
		EmailMFAOTP:          otp,
		EmailMFAOTPExpiresAt: &expiresAt,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().EnableEmailMFA(ctx, userID).Return(nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)
	mockUserRepo.EXPECT().ClearEmailMFAOtp(ctx, userID).Return(nil)

	err := service.VerifyAndEnableEmailMFA(ctx, userID, otp)
	assert.NoError(t, err)
}

func TestMFAService_VerifyAndEnableEmailMFA_InvalidOTP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	expiresAt := time.Now().Add(5 * time.Minute)
	user := &domain.User{
		ID:                   userID,
		EmailMFAEnabled:      false,
		EmailMFAOTP:          "123456",
		EmailMFAOTPExpiresAt: &expiresAt,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.VerifyAndEnableEmailMFA(ctx, userID, "wrong-otp")
	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidEmailOTP, err)
}

func TestMFAService_VerifyAndEnableEmailMFA_ExpiredOTP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	expiredTime := time.Now().Add(-10 * time.Minute)
	user := &domain.User{
		ID:                   userID,
		EmailMFAEnabled:      false,
		EmailMFAOTP:          "123456",
		EmailMFAOTPExpiresAt: &expiredTime,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().ClearEmailMFAOtp(ctx, userID).Return(nil)

	err := service.VerifyAndEnableEmailMFA(ctx, userID, "123456")
	assert.Error(t, err)
	assert.Equal(t, domain.ErrEmailOTPExpired, err)
}

func TestMFAService_SendMFAChallenge_Email(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                 userID,
		Email:              "test@example.com",
		FirstName:          "Test",
		LastName:           "User",
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "EMAIL",
		EmailMFAEnabled:    true,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().StoreEmailMFAOtp(ctx, userID, gomock.Any(), gomock.Any()).Return(nil)
	mockEmailService.EXPECT().SendMFAEmail("test@example.com", "Test User", gomock.Any(), "EMAIL").Return(nil)

	method, counter, challengeID, err := service.SendMFAChallenge(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, "EMAIL", method)
	assert.Equal(t, uint64(0), counter)
	assert.Empty(t, challengeID)
}

func TestMFAService_SendMFAChallenge_TOTP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                 userID,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	method, counter, challengeID, err := service.SendMFAChallenge(ctx, userID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TOTP challenges are handled by authenticator apps")
	assert.Equal(t, "TOTP", method)
	assert.Equal(t, uint64(0), counter)
	assert.Empty(t, challengeID)
}

func TestMFAService_SendMFAChallenge_Push(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mockPushService)

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                  userID,
		IsTwoFactorEnabled:  true,
		TwoFactorMethod:     "PUSH",
		PushMFAEnabled:      true,
		PushMFADeviceTokens: []string{"device-token-1"},
		PushMFAChallenges:   []domain.PushMFAChallenge{},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil).Times(2)
	mockPushService.EXPECT().SendMFAPushChallenge("device-token-1", gomock.Any(), "unknown", "unknown").Return(nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	method, counter, challengeID, err := service.SendMFAChallenge(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, "PUSH", method)
	assert.Equal(t, uint64(0), counter)
	assert.NotEmpty(t, challengeID)
}

func TestMFAService_VerifyMFAChallenge_Email_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	otp := "123456"
	expiresAt := time.Now().Add(5 * time.Minute)
	user := &domain.User{
		ID:                   userID,
		IsTwoFactorEnabled:   true,
		TwoFactorMethod:      "EMAIL",
		EmailMFAEnabled:      true,
		EmailMFAOTP:          otp,
		EmailMFAOTPExpiresAt: &expiresAt,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().ClearEmailMFAOtp(ctx, userID).Return(nil)

	valid, err := service.VerifyMFAChallenge(ctx, userID, otp, 0)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestMFAService_VerifyMFAChallenge_Email_Invalid(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	expiresAt := time.Now().Add(5 * time.Minute)
	user := &domain.User{
		ID:                   userID,
		IsTwoFactorEnabled:   true,
		TwoFactorMethod:      "EMAIL",
		EmailMFAEnabled:      true,
		EmailMFAOTP:          "123456",
		EmailMFAOTPExpiresAt: &expiresAt,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	valid, err := service.VerifyMFAChallenge(ctx, userID, "wrong-otp", 0)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestMFAService_DisableEmailMFA_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                 userID,
		EmailMFAEnabled:    true,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "EMAIL",
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().DisableEmailMFA(ctx, userID).Return(nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	err := service.DisableEmailMFA(ctx, userID)
	assert.NoError(t, err)
}

func TestMFAService_DisableEmailMFA_NotEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:              userID,
		EmailMFAEnabled: false,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.DisableEmailMFA(ctx, userID)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrEmailMFANotEnabled, err)
}

func TestMFAService_GenerateOTP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	// generateOTP is unexported, test through public methods
	// This is tested indirectly through InitiateEmailMFASetup and SendMFAChallenge
	_ = service
}

func TestMFAService_VerifyMFAChallenge_2FANotEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                 userID,
		IsTwoFactorEnabled: false,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	valid, err := service.VerifyMFAChallenge(ctx, userID, "123456", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "2FA is not enabled")
	assert.False(t, valid)
}

func TestMFAService_SendMFAChallenge_2FANotEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                 userID,
		IsTwoFactorEnabled: false,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	method, counter, challengeID, err := service.SendMFAChallenge(ctx, userID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "2FA is not enabled")
	assert.Empty(t, method)
	assert.Equal(t, uint64(0), counter)
	assert.Empty(t, challengeID)
}

func TestMFAService_VerifyMFAChallenge_UnsupportedMethod(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEmailService := mocks.NewMockEmailService(ctrl)
	mockPushMFAService := domain.NewPushMFAService(mockUserRepo, mocks.NewMockPushNotificationService(ctrl))

	service := domain.NewMFAService(mockUserRepo, mockEmailService, mockPushMFAService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                 userID,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "UNSUPPORTED",
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	valid, err := service.VerifyMFAChallenge(ctx, userID, "code", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported MFA method")
	assert.False(t, valid)
}
