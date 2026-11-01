package ssosession

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeUserSessionStore struct {
	saved *domain.UserSession
	err   error
}

func (f *fakeUserSessionStore) StoreUserSession(_ context.Context, session *domain.UserSession) error {
	if f.err != nil {
		return f.err
	}
	f.saved = session
	return nil
}

func (f *fakeUserSessionStore) GetUserSession(_ context.Context, _ string) (*domain.UserSession, error) {
	return nil, domain.ErrSessionNotFound
}

func (f *fakeUserSessionStore) DeleteUserSession(_ context.Context, _ string) error {
	return nil
}

func (f *fakeUserSessionStore) CleanupExpiredSessions() {}

func TestEstablishOPSession_StoresSessionAndSetsCookie(t *testing.T) {
	store := &fakeUserSessionStore{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("User-Agent", "test-agent")

	session, err := EstablishOPSession(context.Background(), store, rec, req, "user-1", true)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotNil(t, store.saved)

	assert.Equal(t, "user-1", store.saved.UserID)
	assert.Equal(t, "test-agent", store.saved.UserAgent)
	assert.Equal(t, session.SessionID, store.saved.SessionID)
	assert.WithinDuration(t, time.Now().Add(OPSessionTTL), store.saved.ExpiresAt, 5*time.Second)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	cookie := cookies[0]
	assert.Equal(t, OPSessionCookieName, cookie.Name)
	assert.Equal(t, session.SessionID, cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.Greater(t, cookie.MaxAge, 0)
}

func TestEstablishOPSession_NilStoreIsNoop(t *testing.T) {
	rec := httptest.NewRecorder()
	session, err := EstablishOPSession(context.Background(), nil, rec, nil, "user-1", false)
	require.NoError(t, err)
	assert.Nil(t, session)
	assert.Empty(t, rec.Result().Cookies())
}

func TestEstablishOPSession_StoreErrorReturnsError(t *testing.T) {
	store := &fakeUserSessionStore{err: errors.New("db down")}
	rec := httptest.NewRecorder()

	session, err := EstablishOPSession(context.Background(), store, rec, nil, "user-1", false)
	require.Error(t, err)
	assert.Nil(t, session)
	assert.Empty(t, rec.Result().Cookies(), "no cookie must be issued when the session cannot be stored")
}

func TestClearOPSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearOPSessionCookie(rec, true)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	cookie := cookies[0]
	assert.Equal(t, OPSessionCookieName, cookie.Name)
	assert.Empty(t, cookie.Value)
	assert.LessOrEqual(t, cookie.MaxAge, 0)
	assert.True(t, cookie.Secure)
	assert.True(t, cookie.HttpOnly)
}
