package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

const (
	deviceCodeAuthPending  = "authorization_pending"
	deviceCodeSlowDown     = "slow_down"
	deviceCodeExpiredToken = "expired_token"
	deviceCodeAccessDenied = "access_denied"
	deviceCodeInvalidGrant = "invalid_grant"
)

// deviceLoginClientID and deviceLoginScope carry the --client-id/--scope flag
// values from loginCmd's RunE into runDeviceLogin. runDeviceLogin cannot read
// them from loginCmd directly: that would create a package initialization
// cycle (loginCmd's initializer references runDeviceLogin).
var (
	deviceLoginClientID string
	deviceLoginScope    string
)

type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func runDeviceLogin(currentCtx *config.Context) error {
	clientID := deviceLoginClientID
	scope := deviceLoginScope

	base := strings.TrimRight(currentCtx.ServerEndpoint, "/")
	if base == "" {
		return errors.New("server endpoint is empty; set one with 'ssoctl config set-context <name> --server <endpoint>'")
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}

	authResp, err := initiateDeviceAuthorization(context.Background(), base, clientID, scope, httpClient.Do)
	if err != nil {
		return err
	}

	uri := authResp.VerificationURI
	if authResp.VerificationURIComplete != "" {
		uri = authResp.VerificationURIComplete
	}
	fmt.Printf("Open the following URL in your browser:\n  %s\nand enter the code: %s\n", uri, authResp.UserCode)
	openBrowser(uri)

	interval := time.Duration(authResp.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	pollCtx, cancel := context.WithTimeout(context.Background(), time.Duration(authResp.ExpiresIn+30)*time.Second)
	defer cancel()
	tokenResp, err := pollForTokenResponse(pollCtx, base, authResp.DeviceCode, clientID, interval, "", httpClient.Do)
	if err != nil {
		return err
	}

	currentCtx.UserAuthToken = tokenResp.AccessToken
	config.GlobalConfig.Contexts[config.GlobalConfig.CurrentContext] = currentCtx
	if err := config.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save token to config: %w", err)
	}

	fmt.Printf("Login successful. Token saved for context '%s'.\n", config.GlobalConfig.CurrentContext)
	if email := idTokenEmail(tokenResp.IDToken); email != "" {
		fmt.Printf("Logged in as: %s\n", email)
	}
	return nil
}

func initiateDeviceAuthorization(ctx context.Context, base, clientID, scope string, httpDo func(*http.Request) (*http.Response, error)) (*deviceAuthResponse, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	if scope != "" {
		form.Set("scope", scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/oauth2/device_authorization", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build device authorization request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpDo(req)
	if err != nil {
		return nil, fmt.Errorf("failed to contact device authorization endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read device authorization response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		var errResp tokenErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("device authorization failed: %s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("device authorization failed (HTTP %s): %s", resp.Status, bodyExcerpt(body))
	}

	var authResp deviceAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("invalid device authorization response: %w (body: %s)", err, bodyExcerpt(body))
	}
	if authResp.DeviceCode == "" || authResp.UserCode == "" {
		return nil, errors.New("device authorization response is missing device_code or user_code")
	}
	return &authResp, nil
}

func pollForToken(ctx context.Context, base, deviceCode, clientID string, interval time.Duration, tokenURL string, httpDo func(*http.Request) (*http.Response, error)) (string, error) {
	tokenResp, err := pollForTokenResponse(ctx, base, deviceCode, clientID, interval, tokenURL, httpDo)
	if err != nil {
		return "", err
	}
	return tokenResp.AccessToken, nil
}

func pollForTokenResponse(ctx context.Context, base, deviceCode, clientID string, interval time.Duration, tokenURL string, httpDo func(*http.Request) (*http.Response, error)) (*tokenResponse, error) {
	if tokenURL == "" {
		tokenURL = strings.TrimRight(base, "/") + "/oauth2/token"
	}
	for {
		tokenResp, errResp, err := pollOnce(ctx, tokenURL, deviceCode, clientID, httpDo)
		if err != nil {
			return nil, err
		}
		if tokenResp != nil {
			return tokenResp, nil
		}

		switch errResp.Error {
		case deviceCodeAuthPending:
			if err := sleepWithContext(ctx, interval); err != nil {
				return nil, err
			}
		case deviceCodeSlowDown:
			interval += 5 * time.Second
			if err := sleepWithContext(ctx, interval); err != nil {
				return nil, err
			}
		case deviceCodeExpiredToken, deviceCodeInvalidGrant:
			return nil, fmt.Errorf("device code expired - please try again")
		case deviceCodeAccessDenied:
			return nil, errors.New("access denied by user")
		default:
			return nil, fmt.Errorf("token endpoint error: %s: %s", errResp.Error, errResp.ErrorDescription)
		}
	}
}

func pollOnce(ctx context.Context, tokenURL, deviceCode, clientID string, httpDo func(*http.Request) (*http.Response, error)) (*tokenResponse, *tokenErrorResponse, error) {
	form := url.Values{}
	form.Set("grant_type", deviceGrantType)
	form.Set("device_code", deviceCode)
	form.Set("client_id", clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpDo(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to poll token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read token response: %w", err)
	}

	var tokenResp tokenResponse
	if json.Unmarshal(body, &tokenResp) == nil && tokenResp.AccessToken != "" {
		return &tokenResp, nil, nil
	}

	var errResp tokenErrorResponse
	if json.Unmarshal(body, &errResp) != nil || errResp.Error == "" {
		return nil, nil, fmt.Errorf("unexpected token endpoint response: %s", bodyExcerpt(body))
	}
	return nil, &errResp, nil
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errors.New("timed out waiting for device authorization - please try again")
	case <-timer.C:
		return nil
	}
}

func openBrowser(uri string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", uri)
	} else {
		cmd = exec.Command("xdg-open", uri)
	}
	_ = cmd.Start()
}

func idTokenEmail(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Email
}

func bodyExcerpt(body []byte) string {
	const maxLen = 200
	if len(body) > maxLen {
		return string(body[:maxLen]) + "..."
	}
	return string(body)
}
