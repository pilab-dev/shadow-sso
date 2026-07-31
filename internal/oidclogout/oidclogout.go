package oidclogout

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/domain"
)

// BackChannelLogoutEvent is the OIDC back-channel logout event URI that must be
// present in the `events` claim of a logout token.
const BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutTokenParams carries the claims required to build an OIDC back-channel
// logout token (OIDC Back-Channel Logout 1.0, section 2.5).
type LogoutTokenParams struct {
	Issuer   string
	Audience string
	SID      string
	Subject  string
}

// SignFunc signs the given claims and returns a compact JWS string.
type SignFunc func(claims jwt.Claims) (string, error)

// BuildLogoutToken constructs a signed logout token. It always includes the
// backchannel-logout event claim and requires at least one of SID or Subject.
func BuildLogoutToken(p LogoutTokenParams, sign SignFunc) (string, error) {
	if p.Issuer == "" || p.Audience == "" {
		return "", fmt.Errorf("issuer and audience are required for logout token")
	}
	if p.SID == "" && p.Subject == "" {
		return "", fmt.Errorf("either sid or sub is required for logout token")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":    p.Issuer,
		"aud":    p.Audience,
		"iat":    now.Unix(),
		"exp":    now.Add(5 * time.Minute).Unix(),
		"events": map[string]interface{}{BackChannelLogoutEvent: struct{}{}},
	}
	if p.SID != "" {
		claims["sid"] = p.SID
	}
	if p.Subject != "" {
		claims["sub"] = p.Subject
	}

	return sign(claims)
}

// Notifier dispatches logout tokens to a client's back-channel logout endpoint.
type Notifier struct {
	httpClient *http.Client
	issuer     string
	sign       SignFunc
}

// NewNotifier creates a Notifier with a bounded HTTP client. The issuer is
// embedded in every logout token it dispatches.
func NewNotifier(issuer string, sign SignFunc) *Notifier {
	return &Notifier{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		issuer:     issuer,
		sign:       sign,
	}
}

// NotifyLogout POSTs the given logout token to the client's back-channel
// logout URI. Clients without a BackchannelLogoutURI are skipped. The call
// returns when the endpoint responds or the HTTP client timeout elapses.
func (n *Notifier) NotifyLogout(ctx context.Context, client *domain.Client, logoutToken string) error {
	if client == nil || client.BackchannelLogoutURI == "" {
		return nil
	}

	form := url.Values{}
	form.Set("logout_token", logoutToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BackchannelLogoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to build backchannel logout request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("backchannel logout request to %s failed: %w", client.BackchannelLogoutURI, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("backchannel logout endpoint %s returned status %d", client.BackchannelLogoutURI, resp.StatusCode)
	}
	return nil
}
