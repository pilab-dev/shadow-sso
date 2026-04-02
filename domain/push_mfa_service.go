package domain

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrPushMFANotEnabled    = errors.New("push MFA is not enabled")
	ErrNoDeviceTokens       = errors.New("no device tokens registered for push notifications")
	ErrChallengeNotFound    = errors.New("push MFA challenge not found")
	ErrChallengeExpired     = errors.New("push MFA challenge has expired")
	ErrChallengeAlreadyUsed = errors.New("push MFA challenge has already been used")
	ErrInvalidChallengeID   = errors.New("invalid challenge ID")
)

// PushMFAService handles push-based MFA challenges
type PushMFAService struct {
	userRepo            UserRepository
	pushService         PushNotificationService
	challengeExpiryTime time.Duration
	maxActiveChallenges int
}

// PushMFAConfig holds configuration for push MFA
type PushMFAConfig struct {
	ChallengeExpiryTime time.Duration
	MaxActiveChallenges int
}

// NewPushMFAService creates a new push MFA service
func NewPushMFAService(userRepo UserRepository, pushService PushNotificationService) *PushMFAService {
	return &PushMFAService{
		userRepo:            userRepo,
		pushService:         pushService,
		challengeExpiryTime: 5 * time.Minute, // 5 minutes to respond
		maxActiveChallenges: 5,               // Max 5 active challenges per user
	}
}

// NewPushMFAServiceWithConfig creates a new push MFA service with custom config
func NewPushMFAServiceWithConfig(userRepo UserRepository, pushService PushNotificationService, config PushMFAConfig) *PushMFAService {
	return &PushMFAService{
		userRepo:            userRepo,
		pushService:         pushService,
		challengeExpiryTime: config.ChallengeExpiryTime,
		maxActiveChallenges: config.MaxActiveChallenges,
	}
}

// RegisterDeviceToken registers a device token for push notifications
func (s *PushMFAService) RegisterDeviceToken(ctx context.Context, userID, deviceToken string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Check if token is already registered
	for _, token := range user.PushMFADeviceTokens {
		if token == deviceToken {
			return nil // Already registered
		}
	}

	// Add new token
	user.PushMFADeviceTokens = append(user.PushMFADeviceTokens, deviceToken)

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user with device token: %w", err)
	}

	return nil
}

// UnregisterDeviceToken removes a device token
func (s *PushMFAService) UnregisterDeviceToken(ctx context.Context, userID, deviceToken string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Remove token
	newTokens := make([]string, 0, len(user.PushMFADeviceTokens))
	for _, token := range user.PushMFADeviceTokens {
		if token != deviceToken {
			newTokens = append(newTokens, token)
		}
	}

	user.PushMFADeviceTokens = newTokens

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user after removing device token: %w", err)
	}

	return nil
}

// CreatePushMFAChallenge creates a new push MFA challenge
func (s *PushMFAService) CreatePushMFAChallenge(ctx context.Context, userID, ipAddress, userAgent string) (string, error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	if !user.PushMFAEnabled {
		return "", ErrPushMFANotEnabled
	}

	if len(user.PushMFADeviceTokens) == 0 {
		return "", ErrNoDeviceTokens
	}

	// Clean up expired challenges
	s.cleanupExpiredChallenges(user)

	// Check if we have too many active challenges
	activeChallenges := 0
	for _, challenge := range user.PushMFAChallenges {
		if challenge.Status == "pending" {
			activeChallenges++
		}
	}
	if activeChallenges+len(user.PushMFADeviceTokens) > s.maxActiveChallenges {
		return "", errors.New("too many active push MFA challenges")
	}

	// Generate unique challenge ID
	challengeID := s.generateChallengeID()

	// Create challenge for each device token
	now := time.Now()
	expiresAt := now.Add(s.challengeExpiryTime)

	for _, deviceToken := range user.PushMFADeviceTokens {
		challenge := PushMFAChallenge{
			ChallengeID: challengeID,
			DeviceToken: deviceToken,
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			CreatedAt:   now,
			ExpiresAt:   expiresAt,
			Status:      "pending",
		}

		user.PushMFAChallenges = append(user.PushMFAChallenges, challenge)

		// Send push notification
		err = s.sendPushChallengeNotification(deviceToken, challengeID, ipAddress, userAgent)
		if err != nil {
			// Log error but continue with other tokens
			fmt.Printf("Failed to send push notification to device %s: %v\n", deviceToken, err)
		}
	}

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return "", fmt.Errorf("failed to save push MFA challenge: %w", err)
	}

	return challengeID, nil
}

// VerifyPushMFAChallenge verifies a push MFA challenge response
func (s *PushMFAService) VerifyPushMFAChallenge(ctx context.Context, userID, challengeID string, approved bool) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if !user.PushMFAEnabled {
		return ErrPushMFANotEnabled
	}

	// Find all challenges with the same ChallengeID
	challengeIndices := make([]int, 0)
	for i, challenge := range user.PushMFAChallenges {
		if challenge.ChallengeID == challengeID {
			challengeIndices = append(challengeIndices, i)
		}
	}

	if len(challengeIndices) == 0 {
		return ErrChallengeNotFound
	}

	// Check the first challenge for expiration and status
	firstChallenge := user.PushMFAChallenges[challengeIndices[0]]

	// Check if challenge is expired
	if time.Now().After(firstChallenge.ExpiresAt) {
		// Mark all challenges with this ID as expired
		for _, idx := range challengeIndices {
			user.PushMFAChallenges[idx].Status = "expired"
		}
		_ = s.userRepo.UpdateUser(ctx, user)
		return ErrChallengeExpired
	}

	// Check if challenge is already used
	if firstChallenge.Status != "pending" {
		return ErrChallengeAlreadyUsed
	}

	// Update all challenges with this ChallengeID
	status := "approved"
	if !approved {
		status = "denied"
	}
	for _, idx := range challengeIndices {
		user.PushMFAChallenges[idx].Status = status
	}

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update challenge status: %w", err)
	}

	return nil
}

// GetPushMFAChallengeStatus gets the status of a push MFA challenge
func (s *PushMFAService) GetPushMFAChallengeStatus(ctx context.Context, userID, challengeID string) (string, error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	// Find the challenge
	for _, challenge := range user.PushMFAChallenges {
		if challenge.ChallengeID == challengeID {
			// Check if expired
			if time.Now().After(challenge.ExpiresAt) && challenge.Status == "pending" {
				return "expired", nil
			}
			return challenge.Status, nil
		}
	}

	return "", ErrChallengeNotFound
}

// EnablePushMFA enables push MFA for a user
func (s *PushMFAService) EnablePushMFA(ctx context.Context, userID string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	user.PushMFAEnabled = true

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to enable push MFA: %w", err)
	}

	return nil
}

// DisablePushMFA disables push MFA for a user
func (s *PushMFAService) DisablePushMFA(ctx context.Context, userID string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	user.PushMFAEnabled = false
	user.PushMFADeviceTokens = nil
	user.PushMFAChallenges = nil

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to disable push MFA: %w", err)
	}

	return nil
}

// sendPushChallengeNotification sends a push notification for MFA challenge
func (s *PushMFAService) sendPushChallengeNotification(deviceToken, challengeID, ipAddress, userAgent string) error {
	return s.pushService.SendMFAPushChallenge(deviceToken, challengeID, ipAddress, userAgent)
}

// cleanupExpiredChallenges removes expired challenges from user's challenge list
func (s *PushMFAService) cleanupExpiredChallenges(user *User) {
	now := time.Now()
	activeChallenges := make([]PushMFAChallenge, 0, len(user.PushMFAChallenges))

	for _, challenge := range user.PushMFAChallenges {
		if now.After(challenge.ExpiresAt) && challenge.Status == "pending" {
			// Mark as expired (don't keep expired challenges)
			continue
		}
		activeChallenges = append(activeChallenges, challenge)
	}

	user.PushMFAChallenges = activeChallenges
}

// generateChallengeID generates a unique challenge ID
func (s *PushMFAService) generateChallengeID() string {
	// Use UUID for uniqueness
	return uuid.New().String()
}
