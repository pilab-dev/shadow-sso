package webauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sessionTestSecret = "session-endpoint-test-secret-32-bytes!!"

type sessionResponse struct {
	Authenticated bool `json:"authenticated"`
	User          struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	} `json:"user"`
}

func setupSessionTest(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	wa := webauth.New(&webauth.Options{
		Config:          webauth.DefaultConfig(),
		SSOCookieSecret: sessionTestSecret,
	})
	router := gin.New()
	router.GET("/api/session", wa.SessionHandler)
	return router
}

func signedSessionCookie(t *testing.T, accounts ...ssosession.Account) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	require.NoError(t, ssosession.SetCookie(rec, &ssosession.Session{
		SessionID: ssosession.NewID(),
		Accounts:  accounts,
	}, false, sessionTestSecret))

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

func TestSessionHandler_Authenticated(t *testing.T) {
	router := setupSessionTest(t)
	cookie := signedSessionCookie(t, ssosession.Account{
		UserID:   "user-1",
		Email:    "user@example.com",
		Name:     "Test User",
		Picture:  "https://example.com/avatar.png",
		LastUsed: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "Cookie", w.Header().Get("Vary"))

	var resp sessionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Authenticated)
	assert.Equal(t, "user-1", resp.User.ID)
	assert.Equal(t, "user@example.com", resp.User.Email)
	assert.Equal(t, "Test User", resp.User.Name)
	assert.Equal(t, "https://example.com/avatar.png", resp.User.Picture)
}

func TestSessionHandler_PicksMostRecentlyUsedAccount(t *testing.T) {
	router := setupSessionTest(t)
	cookie := signedSessionCookie(t,
		ssosession.Account{UserID: "old", Email: "old@example.com", LastUsed: time.Now().Add(-time.Hour)},
		ssosession.Account{UserID: "new", Email: "new@example.com", LastUsed: time.Now()},
	)

	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp sessionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Authenticated)
	assert.Equal(t, "new", resp.User.ID)
}

func TestSessionHandler_NoCookie(t *testing.T) {
	router := setupSessionTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp sessionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Authenticated)
	assert.Empty(t, resp.User.ID)
}

func TestSessionHandler_TamperedCookie(t *testing.T) {
	router := setupSessionTest(t)
	cookie := signedSessionCookie(t, ssosession.Account{
		UserID:   "user-1",
		Email:    "user@example.com",
		LastUsed: time.Now(),
	})
	cookie.Value += "tampered"

	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp sessionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Authenticated)
	assert.Empty(t, resp.User.ID)
}
