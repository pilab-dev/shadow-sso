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

func TestNewPushMFAService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)
	require.NotNil(t, service)
	// Test that service is created (internal fields are not accessible from test package)
	assert.NotNil(t, service)
}

func TestNewPushMFAServiceWithConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	config := domain.PushMFAConfig{
		ChallengeExpiryTime: 10 * time.Minute,
		MaxActiveChallenges: 10,
	}

	service := domain.NewPushMFAServiceWithConfig(mockUserRepo, mockPushService, config)
	require.NotNil(t, service)
	// Test that service is created with config (internal fields are not accessible from test package)
	assert.NotNil(t, service)
}

func TestPushMFAService_RegisterDeviceToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	deviceToken := "device-token-123"
	user := &domain.User{
		ID:                  userID,
		PushMFADeviceTokens: []string{},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	err := service.RegisterDeviceToken(ctx, userID, deviceToken)
	assert.NoError(t, err)
}

func TestPushMFAService_RegisterDeviceToken_AlreadyRegistered(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	deviceToken := "device-token-123"
	user := &domain.User{
		ID:                  userID,
		PushMFADeviceTokens: []string{deviceToken},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.RegisterDeviceToken(ctx, userID, deviceToken)
	assert.NoError(t, err) // Already registered is considered success
}

func TestPushMFAService_UnregisterDeviceToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	deviceToken := "device-token-123"
	user := &domain.User{
		ID:                  userID,
		PushMFADeviceTokens: []string{deviceToken, "other-token"},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	err := service.UnregisterDeviceToken(ctx, userID, deviceToken)
	assert.NoError(t, err)
}

func TestPushMFAService_CreatePushMFAChallenge_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	ipAddress := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	user := &domain.User{
		ID:                  userID,
		PushMFAEnabled:      true,
		PushMFADeviceTokens: []string{"device-token-1"},
		PushMFAChallenges:   []domain.PushMFAChallenge{},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockPushService.EXPECT().SendMFAPushChallenge("device-token-1", gomock.Any(), ipAddress, userAgent).Return(nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	challengeID, err := service.CreatePushMFAChallenge(ctx, userID, ipAddress, userAgent)
	assert.NoError(t, err)
	assert.NotEmpty(t, challengeID)
}

func TestPushMFAService_CreatePushMFAChallenge_NotEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:             userID,
		PushMFAEnabled: false,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	challengeID, err := service.CreatePushMFAChallenge(ctx, userID, "192.168.1.1", "Mozilla/5.0")
	assert.Error(t, err)
	assert.Equal(t, domain.ErrPushMFANotEnabled, err)
	assert.Empty(t, challengeID)
}

func TestPushMFAService_CreatePushMFAChallenge_NoDeviceTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                  userID,
		PushMFAEnabled:      true,
		PushMFADeviceTokens: []string{},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	challengeID, err := service.CreatePushMFAChallenge(ctx, userID, "192.168.1.1", "Mozilla/5.0")
	assert.Error(t, err)
	assert.Equal(t, domain.ErrNoDeviceTokens, err)
	assert.Empty(t, challengeID)
}

func TestPushMFAService_CreatePushMFAChallenge_TooManyActiveChallenges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	futureTime := time.Now().Add(5 * time.Minute)
	challenges := make([]domain.PushMFAChallenge, 5)
	for i := range challenges {
		challenges[i] = domain.PushMFAChallenge{
			ChallengeID: "challenge-" + string(rune(i)),
			Status:      "pending",
			ExpiresAt:   futureTime,
		}
	}
	user := &domain.User{
		ID:                  userID,
		PushMFAEnabled:      true,
		PushMFADeviceTokens: []string{"device-token-1"},
		PushMFAChallenges:   challenges,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	challengeID, err := service.CreatePushMFAChallenge(ctx, userID, "192.168.1.1", "Mozilla/5.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many active push MFA challenges")
	assert.Empty(t, challengeID)
}

func TestPushMFAService_VerifyPushMFAChallenge_Success_Approved(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	challengeID := "challenge-123"
	expiresAt := time.Now().Add(5 * time.Minute)
	challenge := domain.PushMFAChallenge{
		ChallengeID: challengeID,
		Status:      "pending",
		ExpiresAt:   expiresAt,
	}
	user := &domain.User{
		ID:                userID,
		PushMFAEnabled:    true,
		PushMFAChallenges: []domain.PushMFAChallenge{challenge},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	err := service.VerifyPushMFAChallenge(ctx, userID, challengeID, true)
	assert.NoError(t, err)
}

func TestPushMFAService_VerifyPushMFAChallenge_Success_Denied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	challengeID := "challenge-123"
	expiresAt := time.Now().Add(5 * time.Minute)
	challenge := domain.PushMFAChallenge{
		ChallengeID: challengeID,
		Status:      "pending",
		ExpiresAt:   expiresAt,
	}
	user := &domain.User{
		ID:                userID,
		PushMFAEnabled:    true,
		PushMFAChallenges: []domain.PushMFAChallenge{challenge},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	err := service.VerifyPushMFAChallenge(ctx, userID, challengeID, false)
	assert.NoError(t, err)
}

func TestPushMFAService_VerifyPushMFAChallenge_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                userID,
		PushMFAEnabled:    true,
		PushMFAChallenges: []domain.PushMFAChallenge{},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.VerifyPushMFAChallenge(ctx, userID, "non-existent", true)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrChallengeNotFound, err)
}

func TestPushMFAService_VerifyPushMFAChallenge_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	challengeID := "challenge-123"
	expiredTime := time.Now().Add(-10 * time.Minute)
	challenge := domain.PushMFAChallenge{
		ChallengeID: challengeID,
		Status:      "pending",
		ExpiresAt:   expiredTime,
	}
	user := &domain.User{
		ID:                userID,
		PushMFAEnabled:    true,
		PushMFAChallenges: []domain.PushMFAChallenge{challenge},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	err := service.VerifyPushMFAChallenge(ctx, userID, challengeID, true)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrChallengeExpired, err)
}

func TestPushMFAService_VerifyPushMFAChallenge_AlreadyUsed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	challengeID := "challenge-123"
	expiresAt := time.Now().Add(5 * time.Minute)
	challenge := domain.PushMFAChallenge{
		ChallengeID: challengeID,
		Status:      "approved",
		ExpiresAt:   expiresAt,
	}
	user := &domain.User{
		ID:                userID,
		PushMFAEnabled:    true,
		PushMFAChallenges: []domain.PushMFAChallenge{challenge},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	err := service.VerifyPushMFAChallenge(ctx, userID, challengeID, true)
	assert.Error(t, err)
	assert.Equal(t, domain.ErrChallengeAlreadyUsed, err)
}

func TestPushMFAService_GetPushMFAChallengeStatus_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	challengeID := "challenge-123"
	expiresAt := time.Now().Add(5 * time.Minute)
	challenge := domain.PushMFAChallenge{
		ChallengeID: challengeID,
		Status:      "pending",
		ExpiresAt:   expiresAt,
	}
	user := &domain.User{
		ID:                userID,
		PushMFAChallenges: []domain.PushMFAChallenge{challenge},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	status, err := service.GetPushMFAChallengeStatus(ctx, userID, challengeID)
	assert.NoError(t, err)
	assert.Equal(t, "pending", status)
}

func TestPushMFAService_GetPushMFAChallengeStatus_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                userID,
		PushMFAChallenges: []domain.PushMFAChallenge{},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	status, err := service.GetPushMFAChallengeStatus(ctx, userID, "non-existent")
	assert.Error(t, err)
	assert.Equal(t, domain.ErrChallengeNotFound, err)
	assert.Empty(t, status)
}

func TestPushMFAService_EnablePushMFA_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:             userID,
		PushMFAEnabled: false,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	err := service.EnablePushMFA(ctx, userID)
	assert.NoError(t, err)
}

func TestPushMFAService_DisablePushMFA_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	user := &domain.User{
		ID:                  userID,
		PushMFAEnabled:      true,
		PushMFADeviceTokens: []string{"token1"},
		PushMFAChallenges:   []domain.PushMFAChallenge{{ChallengeID: "ch1"}},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	err := service.DisablePushMFA(ctx, userID)
	assert.NoError(t, err)
}

func TestPushMFAService_CleanupExpiredChallenges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	expiredTime := time.Now().Add(-10 * time.Minute)
	futureTime := time.Now().Add(10 * time.Minute)
	user := &domain.User{
		ID:                  userID,
		PushMFAEnabled:      true,
		PushMFADeviceTokens: []string{"device-token-1"},
		PushMFAChallenges: []domain.PushMFAChallenge{
			{ChallengeID: "expired", Status: "pending", ExpiresAt: expiredTime},
			{ChallengeID: "active", Status: "pending", ExpiresAt: futureTime},
			{ChallengeID: "approved", Status: "approved", ExpiresAt: expiredTime},
		},
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockPushService.EXPECT().SendMFAPushChallenge(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	// Call CreatePushMFAChallenge which internally calls cleanupExpiredChallenges
	challengeID, err := service.CreatePushMFAChallenge(ctx, userID, "192.168.1.1", "Mozilla/5.0")
	assert.NoError(t, err)
	assert.NotEmpty(t, challengeID)

	// After cleanup, the user should have 2 challenges (active and approved) plus the new one
	assert.Len(t, user.PushMFAChallenges, 3)
	assert.Equal(t, "active", user.PushMFAChallenges[0].ChallengeID)
	assert.Equal(t, "approved", user.PushMFAChallenges[1].ChallengeID)
}

func TestPushMFAService_CreatePushMFAChallenge_MultipleDevices_RespectsMaxActiveChallenges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	futureTime := time.Now().Add(5 * time.Minute)
	// User has 3 active challenges already and 2 device tokens
	// maxActiveChallenges is 5, so 3 + 2 = 5 should be allowed, but 3 + 2 > 5 would not
	challenges := make([]domain.PushMFAChallenge, 3)
	for i := range challenges {
		challenges[i] = domain.PushMFAChallenge{
			ChallengeID: "challenge-" + string(rune(i)),
			Status:      "pending",
			ExpiresAt:   futureTime,
		}
	}
	user := &domain.User{
		ID:                  userID,
		PushMFAEnabled:      true,
		PushMFADeviceTokens: []string{"device-token-1", "device-token-2"},
		PushMFAChallenges:   challenges,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)

	// Should succeed since 3 existing + 2 new = 5, which equals maxActiveChallenges
	mockPushService.EXPECT().SendMFAPushChallenge("device-token-1", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	mockPushService.EXPECT().SendMFAPushChallenge("device-token-2", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	challengeID, err := service.CreatePushMFAChallenge(ctx, userID, "192.168.1.1", "Mozilla/5.0")
	assert.NoError(t, err)
	assert.NotEmpty(t, challengeID)

	// Should have created 2 new challenges (one per device) with the same challengeID
	newChallenges := 0
	for _, challenge := range user.PushMFAChallenges {
		if challenge.ChallengeID == challengeID {
			newChallenges++
		}
	}
	assert.Equal(t, 2, newChallenges)
}

func TestPushMFAService_VerifyPushMFAChallenge_MultipleDevices_UpdatesAll(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	challengeID := "challenge-123"
	expiresAt := time.Now().Add(5 * time.Minute)

	// Create challenges for 3 devices with the same challengeID
	challenges := []domain.PushMFAChallenge{
		{
			ChallengeID: challengeID,
			DeviceToken: "device-1",
			Status:      "pending",
			ExpiresAt:   expiresAt,
		},
		{
			ChallengeID: challengeID,
			DeviceToken: "device-2",
			Status:      "pending",
			ExpiresAt:   expiresAt,
		},
		{
			ChallengeID: challengeID,
			DeviceToken: "device-3",
			Status:      "pending",
			ExpiresAt:   expiresAt,
		},
	}
	user := &domain.User{
		ID:                userID,
		PushMFAEnabled:    true,
		PushMFAChallenges: challenges,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	// Verify the challenge as approved
	err := service.VerifyPushMFAChallenge(ctx, userID, challengeID, true)
	assert.NoError(t, err)

	// All challenges with the same ChallengeID should be updated to "approved"
	for _, challenge := range user.PushMFAChallenges {
		if challenge.ChallengeID == challengeID {
			assert.Equal(t, "approved", challenge.Status)
		}
	}
}

func TestPushMFAService_VerifyPushMFAChallenge_MultipleDevices_Denied_UpdatesAll(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockPushService := mocks.NewMockPushNotificationService(ctrl)

	service := domain.NewPushMFAService(mockUserRepo, mockPushService)

	ctx := context.Background()
	userID := "user123"
	challengeID := "challenge-123"
	expiresAt := time.Now().Add(5 * time.Minute)

	// Create challenges for 2 devices with the same challengeID
	challenges := []domain.PushMFAChallenge{
		{
			ChallengeID: challengeID,
			DeviceToken: "device-1",
			Status:      "pending",
			ExpiresAt:   expiresAt,
		},
		{
			ChallengeID: challengeID,
			DeviceToken: "device-2",
			Status:      "pending",
			ExpiresAt:   expiresAt,
		},
	}
	user := &domain.User{
		ID:                userID,
		PushMFAEnabled:    true,
		PushMFAChallenges: challenges,
	}

	mockUserRepo.EXPECT().GetUserByID(ctx, userID).Return(user, nil)
	mockUserRepo.EXPECT().UpdateUser(ctx, gomock.Any()).Return(nil)

	// Verify the challenge as denied
	err := service.VerifyPushMFAChallenge(ctx, userID, challengeID, false)
	assert.NoError(t, err)

	// All challenges with the same ChallengeID should be updated to "denied"
	for _, challenge := range user.PushMFAChallenges {
		if challenge.ChallengeID == challengeID {
			assert.Equal(t, "denied", challenge.Status)
		}
	}
}
