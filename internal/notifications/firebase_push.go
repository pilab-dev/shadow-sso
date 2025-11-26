package notifications

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"firebase.google.com/go/v4/messaging"
)

// FirebasePushService implements domain.PushNotificationService using Firebase Cloud Messaging
type FirebasePushService struct {
	client *messaging.Client
}

// NewFirebasePushService creates a new Firebase push notification service
func NewFirebasePushService(projectID, credentialsPath string) *FirebasePushService {
	if projectID == "" || credentialsPath == "" {
		// Return service with nil client - will fail gracefully when used
		return &FirebasePushService{}
	}

	// TODO: Initialize Firebase app with credentials
	// This would require proper Firebase SDK initialization
	// For now, return service that logs notifications
	return &FirebasePushService{}
}

// SendPushNotification sends a push notification to a specific device token
func (s *FirebasePushService) SendPushNotification(deviceToken, title, body string, data map[string]interface{}) error {
	return s.SendPushNotificationWithActions(deviceToken, title, body, data, nil)
}

// SendPushNotificationWithActions sends a push notification with action buttons
func (s *FirebasePushService) SendPushNotificationWithActions(deviceToken, title, body string, data map[string]interface{}, actions []string) error {
	if s.client == nil {
		// For now, just log the notification (in production, integrate with Firebase SDK)
		fmt.Printf("[PUSH] Would send notification to %s: %s - %s\n", deviceToken, title, body)
		if len(data) > 0 {
			dataJSON, _ := json.Marshal(data)
			fmt.Printf("[PUSH] Data: %s\n", string(dataJSON))
		}
		if len(actions) > 0 {
			fmt.Printf("[PUSH] Actions: %v\n", actions)
		}
		return nil
	}

	// Convert data map to string map for Firebase
	var dataStrings map[string]string
	if data != nil {
		dataStrings = make(map[string]string)
		for k, v := range data {
			if str, ok := v.(string); ok {
				dataStrings[k] = str
			} else {
				// Convert to string if not already
				dataStrings[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	message := &messaging.Message{
		Token: deviceToken,
		Notification: &messaging.Notification{
			Title: title,
			Body:  body,
		},
		Data: dataStrings,
	}

	// Add Android-specific configuration for high priority
	message.Android = &messaging.AndroidConfig{
		Priority: "high",
		Notification: &messaging.AndroidNotification{
			Title:       title,
			Body:        body,
			ClickAction: "FLUTTER_NOTIFICATION_CLICK",
			ChannelID:   "mfa_channel",
			Priority:    messaging.PriorityHigh,
		},
	}

	_, err := s.client.Send(context.Background(), message)
	if err != nil {
		return fmt.Errorf("failed to send push notification via Firebase: %w", err)
	}

	return nil
}

// SendMFAPushChallenge sends a push notification for MFA challenge with approve/deny actions
func (s *FirebasePushService) SendMFAPushChallenge(deviceToken, challengeID, ipAddress, userAgent string) error {
	title := "🔐 Login Verification Required"
	body := fmt.Sprintf("Login attempt from %s. Tap to approve or deny this login.", ipAddress)

	data := map[string]interface{}{
		"type":         "mfa_challenge",
		"challenge_id": challengeID,
		"ip_address":   ipAddress,
		"user_agent":   userAgent,
		"timestamp":    time.Now().Unix(),
	}

	return s.SendPushNotification(deviceToken, title, body, data)
}

// SendPushNotificationToUser sends a push notification to all devices of a user
func (s *FirebasePushService) SendPushNotificationToUser(userID, title, body string, data map[string]interface{}) error {
	// This would require querying the database for user's device tokens
	// For now, just log (in production, implement device token storage and retrieval)
	fmt.Printf("[PUSH] Would send notification to user %s: %s - %s\n", userID, title, body)
	if data != nil && len(data) > 0 {
		dataJSON, _ := json.Marshal(data)
		fmt.Printf("[PUSH] Data: %s\n", string(dataJSON))
	}
	return nil
}
