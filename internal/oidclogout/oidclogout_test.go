package oidclogout

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/require"
)

func testSign(claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
}

func TestBuildLogoutToken_RequiredClaims(t *testing.T) {
	token, err := BuildLogoutToken(LogoutTokenParams{
		Issuer:   "https://sso.example.com",
		Audience: "rp-client",
		SID:      "session-1",
		Subject:  "user-1",
	}, testSign)
	require.NoError(t, err)

	parsed, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) {
		return jwt.UnsafeAllowNoneSignatureType, nil
	}, jwt.WithoutClaimsValidation())
	require.NoError(t, err)

	claims := parsed.Claims.(jwt.MapClaims)
	require.Equal(t, "https://sso.example.com", claims["iss"])
	require.Equal(t, "rp-client", claims["aud"])
	require.Equal(t, "session-1", claims["sid"])
	require.Equal(t, "user-1", claims["sub"])
	require.NotEmpty(t, claims["iat"])
	require.NotEmpty(t, claims["exp"])
	events, ok := claims["events"].(map[string]interface{})
	require.True(t, ok, "events claim must be a map")
	_, ok = events[BackChannelLogoutEvent]
	require.True(t, ok, "backchannel-logout event must be present")
}

func TestBuildLogoutToken_RequiresSidOrSub(t *testing.T) {
	_, err := BuildLogoutToken(LogoutTokenParams{Issuer: "https://sso.example.com", Audience: "rp-client"}, testSign)
	require.Error(t, err, "logout token without sid or sub must be rejected")
}

func TestBuildLogoutToken_RequiresIssuerAndAudience(t *testing.T) {
	_, err := BuildLogoutToken(LogoutTokenParams{SID: "s", Subject: "u"}, testSign)
	require.Error(t, err)
}

func TestNotifier_PostsToBackchannelURI(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		require.NoError(t, r.ParseForm())
		received = r.Form.Get("logout_token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewNotifier("https://sso.example.com", testSign)
	err := notifier.NotifyLogout(context.Background(), &domain.Client{
		ID:                   "rp-client",
		BackchannelLogoutURI: srv.URL,
	}, "logout-token-value")
	require.NoError(t, err)
	require.Equal(t, "logout-token-value", received)
}

func TestNotifier_SkipsClientWithoutBackchannelURI(t *testing.T) {
	notifier := NewNotifier("https://sso.example.com", testSign)
	err := notifier.NotifyLogout(context.Background(), &domain.Client{ID: "public-client"}, "token")
	require.NoError(t, err)
}

func TestNotifier_ReturnsEndpointErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	notifier := NewNotifier("https://sso.example.com", testSign)
	err := notifier.NotifyLogout(context.Background(), &domain.Client{
		ID:                   "rp-client",
		BackchannelLogoutURI: srv.URL,
	}, "token")
	require.Error(t, err, "non-2xx backchannel response must surface as an error")
}
