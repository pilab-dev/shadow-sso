package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"firebase.google.com/go/v4/messaging"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const fcmScope = "https://www.googleapis.com/auth/firebase.messaging"

// fcmEndpoint is the FCM HTTP v1 send URL template; the project ID is substituted in.
var fcmEndpoint = "https://fcm.googleapis.com/v1/projects/%s/messages:send"

// FirebasePushService implements domain.PushNotificationService using Firebase Cloud Messaging
//
// It talks to the FCM HTTP v1 API directly (reusing the SDK's message types) so the heavy
// firebase admin SDK dependency tree is not needed.
type FirebasePushService struct {
	client  *http.Client // authenticated via the service-account credentials
	sendURL string
}

// ErrPushNotConfigured is returned when push delivery is requested but Firebase is not configured.
var ErrPushNotConfigured = errors.New("firebase push notifications are not configured")

// NewFirebasePushService creates a new Firebase push notification service.
// When projectID or credentialsPath is empty, or initialisation fails, the returned service
// is unconfigured and every send returns ErrPushNotConfigured instead of pretending to succeed.
func NewFirebasePushService(projectID, credentialsPath string) *FirebasePushService {
	if projectID == "" || credentialsPath == "" {
		return &FirebasePushService{}
	}

	raw, err := os.ReadFile(credentialsPath)
	if err != nil {
		log.Error().Err(err).Msg("firebase: cannot read credentials file; push notifications disabled")
		return &FirebasePushService{}
	}
	creds, err := google.CredentialsFromJSON(context.Background(), raw, fcmScope)
	if err != nil {
		log.Error().Err(err).Msg("firebase: invalid credentials; push notifications disabled")
		return &FirebasePushService{}
	}
	return &FirebasePushService{
		client:  oauth2.NewClient(context.Background(), creds.TokenSource),
		sendURL: fmt.Sprintf(fcmEndpoint, projectID),
	}
}

// SendPushNotification sends a push notification to a specific device token
func (s *FirebasePushService) SendPushNotification(deviceToken, title, body string, data map[string]interface{}) error {
	return s.SendPushNotificationWithActions(deviceToken, title, body, data, nil)
}

// SendPushNotificationWithActions sends a push notification with action buttons
func (s *FirebasePushService) SendPushNotificationWithActions(deviceToken, title, body string, data map[string]interface{}, actions []string) error {
	if s.client == nil {
		return ErrPushNotConfigured
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

	payload, err := json.Marshal(map[string]any{"message": message})
	if err != nil {
		return fmt.Errorf("failed to encode push notification: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.sendURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send push notification via Firebase: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("firebase push failed: status %d: %s", resp.StatusCode, body)
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

// SendPushNotificationToUser is not supported yet: device tokens are not stored per user.
func (s *FirebasePushService) SendPushNotificationToUser(userID, title, body string, data map[string]interface{}) error {
	if s.client == nil {
		return ErrPushNotConfigured
	}
	return errors.New("sending to a user is not implemented: no device token store")
}
