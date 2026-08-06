package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func tokenSuccessBody(accessToken string) map[string]any {
	return map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "rt-1",
		"id_token":      "header.payload.signature",
	}
}

// (a) happy: first poll authorization_pending, second access_token -> returns token.
func TestPollForToken_HappyPath(t *testing.T) {
	var mu sync.Mutex
	polls := 0
	var bodies []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		if r.URL.Path != "/oauth2/token" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
			return
		}
		mu.Lock()
		polls++
		first := polls == 1
		mu.Unlock()
		if first {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "authorization_pending",
				"error_description": "authorization pending",
			})
			return
		}
		writeJSON(w, http.StatusOK, tokenSuccessBody("at-1"))
	}))
	defer srv.Close()

	token, err := pollForToken(context.Background(), "", "dev-code-1", "sssoctl", time.Millisecond, srv.URL+"/oauth2/token", srv.Client().Do)
	if err != nil {
		t.Fatalf("pollForToken returned error: %v", err)
	}
	if token != "at-1" {
		t.Fatalf("expected token at-1, got %q", token)
	}

	mu.Lock()
	defer mu.Unlock()
	if polls != 2 {
		t.Fatalf("expected 2 polls, got %d", polls)
	}
	for _, b := range bodies {
		form, err := url.ParseQuery(b)
		if err != nil {
			t.Fatalf("poll body is not a valid form: %q: %v", b, err)
		}
		if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("expected device_code grant_type in %q", b)
		}
		if form.Get("device_code") != "dev-code-1" || form.Get("client_id") != "sssoctl" {
			t.Errorf("expected device_code and client_id in %q", b)
		}
	}
}

// (b) slow_down increments the polling interval by 5s before the retry.
func TestPollForToken_SlowDownIncrementsInterval(t *testing.T) {
	var mu sync.Mutex
	requestTimes := []time.Time{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		first := len(requestTimes) == 1
		mu.Unlock()
		if first {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "slow_down",
				"error_description": "slow down",
			})
			return
		}
		writeJSON(w, http.StatusOK, tokenSuccessBody("at-2"))
	}))
	defer srv.Close()

	token, err := pollForToken(context.Background(), "", "dev-code-1", "sssoctl", time.Millisecond, srv.URL+"/oauth2/token", srv.Client().Do)
	if err != nil {
		t.Fatalf("pollForToken returned error: %v", err)
	}
	if token != "at-2" {
		t.Fatalf("expected token at-2, got %q", token)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requestTimes) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requestTimes))
	}
	// slow_down adds 5s to the (1ms) interval, so the retry must arrive >= 5s later.
	if elapsed := requestTimes[1].Sub(requestTimes[0]); elapsed < 5*time.Second {
		t.Errorf("expected retry at least 5s after slow_down, got %v", elapsed)
	}
}

// (c) expired_token and invalid_grant fail with an error mentioning "expired".
func TestPollForToken_ExpiredCode(t *testing.T) {
	for _, serverErr := range []string{"expired_token", "invalid_grant"} {
		t.Run(serverErr, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error":             serverErr,
					"error_description": "the code has expired",
				})
			}))
			defer srv.Close()

			_, err := pollForToken(context.Background(), "", "dev-code-1", "sssoctl", time.Millisecond, srv.URL+"/oauth2/token", srv.Client().Do)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "expired") {
				t.Errorf("expected error mentioning 'expired', got: %v", err)
			}
		})
	}
}

// (d) access_denied fails with an error mentioning "denied".
func TestPollForToken_AccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "access_denied",
			"error_description": "user denied the request",
		})
	}))
	defer srv.Close()

	_, err := pollForToken(context.Background(), "", "dev-code-1", "sssoctl", time.Millisecond, srv.URL+"/oauth2/token", srv.Client().Do)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected error mentioning 'denied', got: %v", err)
	}
}

// (e) device_authorization returning 401 invalid_client yields a friendly error.
func TestInitiateDeviceAuthorization_InvalidClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/device_authorization" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "unknown client",
		})
	}))
	defer srv.Close()

	_, err := initiateDeviceAuthorization(context.Background(), srv.URL, "sssoctl", "openid profile email", srv.Client().Do)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	for _, want := range []string{"invalid_client", "unknown client"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error mentioning %q, got: %v", want, err)
		}
	}
}

// Sanity: happy device_authorization returns the parsed RFC 8628 response.
func TestInitiateDeviceAuthorization_HappyPath(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("invalid form body: %v", err)
		}
		if form.Get("client_id") != "sssoctl" {
			t.Errorf("expected client_id=sssoctl, got %q", form.Get("client_id"))
		}
		if form.Get("scope") != "openid profile email" {
			t.Errorf("expected scope, got %q", form.Get("scope"))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"device_code":               "dc-1",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          srv.URL + "/oauth2/device/verify",
			"verification_uri_complete": srv.URL + "/oauth2/device/verify?user_code=ABCD-EFGH",
			"expires_in":                600,
			"interval":                  5,
		})
	}))
	defer srv.Close()

	resp, err := initiateDeviceAuthorization(context.Background(), srv.URL+"/", "sssoctl", "openid profile email", srv.Client().Do)
	if err != nil {
		t.Fatalf("initiateDeviceAuthorization returned error: %v", err)
	}
	if resp.DeviceCode != "dc-1" || resp.UserCode != "ABCD-EFGH" {
		t.Errorf("unexpected response: %+v", resp)
	}
	if resp.ExpiresIn != 600 || resp.Interval != 5 {
		t.Errorf("unexpected expiry/interval: %+v", resp)
	}
}

func TestPollForToken_UnexpectedResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "this is not json")
	}))
	defer srv.Close()

	_, err := pollForToken(context.Background(), "", "dev-code-1", "sssoctl", time.Millisecond, srv.URL+"/oauth2/token", srv.Client().Do)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "this is not json") {
		t.Errorf("expected error to include the body excerpt, got: %v", err)
	}
}

func TestIDTokenEmail(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"alice@example.com","sub":"u1"}`))
	got := idTokenEmail("header." + payload + ".sig")
	if got != "alice@example.com" {
		t.Errorf("expected alice@example.com, got %q", got)
	}
	if idTokenEmail("garbage") != "" {
		t.Error("expected empty email for malformed id_token")
	}
	if idTokenEmail("") != "" {
		t.Error("expected empty email for empty id_token")
	}
}
