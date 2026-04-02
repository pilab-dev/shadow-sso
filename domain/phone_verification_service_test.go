package domain_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	mocks "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNewPhoneVerificationService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)
	require.NotNil(t, service)
	// Test that service is created (internal fields are not accessible from test package)
	assert.NotNil(t, service)
}

func TestNewPhoneVerificationServiceWithConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	config := domain.PhoneVerificationConfig{
		MaxOTPRequestsPerHour: 10,
		MaxOTPAttemptsPerHour: 20,
		OTPRequestWindow:      30 * time.Minute,
		OTPAttemptWindow:      30 * time.Minute,
	}

	service := domain.NewPhoneVerificationServiceWithConfig(mockUserRepo, mockSMSService, config)
	require.NotNil(t, service)
	// Test that service is created with config (internal fields are not accessible from test package)
	assert.NotNil(t, service)
}

func TestPhoneVerificationService_SendVerificationOTP_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                    userID,
		PhoneNumber:           "+1234567890",
		IsPhoneNumberVerified: false,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().StorePhoneVerificationOtp(ctx, userID, gomock.Any(), gomock.Any()).Return(nil)
	mockSMSService.EXPECT().SendOTP("+1234567890", gomock.Any()).Return(nil)

	err := service.SendVerificationOTP(ctx, userID)
	assert.NoError(t, err)
}

func TestPhoneVerificationService_SendVerificationOTP_NoPhoneNumber(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:          userID,
		PhoneNumber: "",
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.SendVerificationOTP(ctx, userID)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrUserHasNoPhoneNumber, err)
}

func TestPhoneVerificationService_SendVerificationOTP_AlreadyVerified(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                    userID,
		PhoneNumber:           "+1234567890",
		IsPhoneNumberVerified: true,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.SendVerificationOTP(ctx, userID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already verified")
}

func TestPhoneVerificationService_SendVerificationOTP_RateLimit(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	expiresAt := time.Now().Add(5 * time.Minute)
	user := &domain.User{
		ID:                            userID,
		PhoneNumber:                   "+1234567890",
		IsPhoneNumberVerified:         false,
		PhoneVerificationOtpExpiresAt: &expiresAt,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.SendVerificationOTP(ctx, userID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "please wait")
}

func TestPhoneVerificationService_SendVerificationOTP_SMSError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                    userID,
		PhoneNumber:           "+1234567890",
		IsPhoneNumberVerified: false,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().StorePhoneVerificationOtp(ctx, userID, gomock.Any(), gomock.Any()).Return(nil)
	mockSMSService.EXPECT().SendOTP("+1234567890", gomock.Any()).Return(errors.New("SMS service error"))
	mockUserRepo.EXPECT().ClearPhoneVerificationOtp(ctx, userID).Return(nil)

	err := service.SendVerificationOTP(ctx, userID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send SMS")
}

func TestPhoneVerificationService_VerifyPhoneNumber_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	otp := "123456"
	expiresAt := time.Now().Add(10 * time.Minute)
	user := &domain.User{
		ID:                            userID,
		PhoneNumber:                   "+1234567890",
		IsPhoneNumberVerified:         false,
		PhoneVerificationOtp:          otp,
		PhoneVerificationOtpExpiresAt: &expiresAt,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	err := service.VerifyPhoneNumber(ctx, userID, otp)
	assert.NoError(t, err)
}

func TestPhoneVerificationService_VerifyPhoneNumber_AlreadyVerified(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                    userID,
		PhoneNumber:           "+1234567890",
		IsPhoneNumberVerified: true,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.VerifyPhoneNumber(ctx, userID, "123456")
	assert.NoError(t, err) // Already verified is considered success
}

func TestPhoneVerificationService_VerifyPhoneNumber_NoOTP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                    userID,
		PhoneNumber:           "+1234567890",
		IsPhoneNumberVerified: false,
		PhoneVerificationOtp:  "",
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, user).Return(nil)

	err := service.VerifyPhoneNumber(ctx, userID, "123456")
	assert.Error(t, err)
	assert.Equal(t, domain.ErrNoOTPFound, err)
}

func TestPhoneVerificationService_VerifyPhoneNumber_ExpiredOTP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	expiredTime := time.Now().Add(-10 * time.Minute)
	user := &domain.User{
		ID:                            userID,
		PhoneNumber:                   "+1234567890",
		IsPhoneNumberVerified:         false,
		PhoneVerificationOtp:          "123456",
		PhoneVerificationOtpExpiresAt: &expiredTime,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().ClearPhoneVerificationOtp(ctx, userID).Return(nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, user).Return(nil)

	err := service.VerifyPhoneNumber(ctx, userID, "123456")
	assert.Error(t, err)
	assert.Equal(t, domain.ErrOTPExpired, err)
}

func TestPhoneVerificationService_VerifyPhoneNumber_InvalidOTP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	expiresAt := time.Now().Add(10 * time.Minute)
	user := &domain.User{
		ID:                            userID,
		PhoneNumber:                   "+1234567890",
		IsPhoneNumberVerified:         false,
		PhoneVerificationOtp:          "123456",
		PhoneVerificationOtpExpiresAt: &expiresAt,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, user).Return(nil)

	err := service.VerifyPhoneNumber(ctx, userID, "wrong-otp")
	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidOTP, err)
}

func TestPhoneVerificationService_VerifyPhoneNumber_RateLimit(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	now := time.Now()
	recentTime := now.Add(-30 * time.Minute)
	expiresAt := time.Now().Add(10 * time.Minute)
	user := &domain.User{
		ID:                             userID,
		PhoneNumber:                    "+1234567890",
		IsPhoneNumberVerified:          false,
		PhoneVerificationOtp:           "123456",
		PhoneVerificationOtpExpiresAt:  &expiresAt,
		PhoneVerificationAttempts:      10,
		PhoneVerificationLastAttemptAt: &recentTime,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.VerifyPhoneNumber(ctx, userID, "123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many verification attempts")
}

func TestPhoneVerificationService_VerifyPhoneNumber_NoPhoneNumber(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:          userID,
		PhoneNumber: "",
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.VerifyPhoneNumber(ctx, userID, "123456")
	assert.Error(t, err)
	assert.Equal(t, domain.ErrUserHasNoPhoneNumber, err)
}

func TestPhoneVerificationService_GenerateOTP(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSMSService := mocks.NewMockSMSService(ctrl)

	service := domain.NewPhoneVerificationService(mockUserRepo, mockSMSService)

	// generateOTP is unexported, test through public methods
	// This is tested indirectly through SendVerificationOTP
	_ = service
}
