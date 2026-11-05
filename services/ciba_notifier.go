package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
)

// WebhookCIBANotifier POSTs CIBA requests as JSON to a push service.
type WebhookCIBANotifier struct {
	url    string
	secret string
	http   *http.Client
}

// NewWebhookCIBANotifier returns a notifier; secret, when set, is sent as a
// Bearer credential.
func NewWebhookCIBANotifier(url, secret string) *WebhookCIBANotifier {
	return &WebhookCIBANotifier{url: url, secret: secret, http: &http.Client{Timeout: 5 * time.Second}}
}

func (n *WebhookCIBANotifier) NotifyAuthenticationRequest(ctx context.Context, note domain.CIBANotification) error {
	body, err := json.Marshal(note)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.secret != "" {
		req.Header.Set("Authorization", "Bearer "+n.secret)
	}
	resp, err := n.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ciba notification endpoint returned status %d", resp.StatusCode)
	}
	return nil
}
