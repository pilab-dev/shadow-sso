package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/pilab-dev/shadow-sso/domain"
)

// pushSessionNotifier delivers risk notifications via the configured push
// service. It is a no-op when no push service is available.
type pushSessionNotifier struct {
	push domain.PushNotificationService
}

// NewSessionNotifier wraps a push service for session risk notifications.
func NewSessionNotifier(push domain.PushNotificationService) domain.SessionNotifier {
	return &pushSessionNotifier{push: push}
}

func (n *pushSessionNotifier) NotifyRisk(ctx context.Context, userID string, session *domain.Session, flags []string) error {
	if n == nil || n.push == nil || len(flags) == 0 {
		return nil
	}
	title := "New sign-in detected"
	body := fmt.Sprintf("New sign-in from %s on %s (%s)", valueOrUnknown(session.IPCountry), valueOrUnknown(session.DeviceName), strings.Join(flags, ", "))
	data := map[string]interface{}{
		"session_id": session.ID,
		"risk_flags": flags,
	}
	return n.push.SendPushNotificationToUser(userID, title, body, data)
}

func valueOrUnknown(v string) string {
	if v == "" {
		return "unknown location/device"
	}
	return v
}
