package webauth

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

func TestRateLimiter_Allow_InitiallyTrue(t *testing.T) {
	rl := NewRateLimiter(5, 15*time.Minute)
	assert.True(t, rl.Allow("test-key"))
}

func TestRateLimiter_BlockedAfterMaxAttempts(t *testing.T) {
	rl := NewRateLimiter(3, 15*time.Minute)
	for i := 0; i < 3; i++ {
		rl.RecordFailure("test-key")
	}
	// 3 failures == maxAttempts (3), should be locked
	assert.False(t, rl.Allow("test-key"))
}

func TestRateLimiter_ResetClearsFailures(t *testing.T) {
	rl := NewRateLimiter(3, 15*time.Minute)
	rl.RecordFailure("test-key")
	rl.RecordFailure("test-key")
	rl.Reset("test-key")
	assert.True(t, rl.Allow("test-key"))
}

func TestRateLimiter_LockoutExpires(t *testing.T) {
	rl := NewRateLimiter(2, 1*time.Millisecond) // 1ms lockout
	rl.RecordFailure("test-key")
	rl.RecordFailure("test-key") // locked now
	assert.False(t, rl.Allow("test-key"))

	time.Sleep(5 * time.Millisecond)
	assert.True(t, rl.Allow("test-key"))
}

func TestRateLimiter_DifferentKeysAreIndependent(t *testing.T) {
	rl := NewRateLimiter(2, 15*time.Minute)
	rl.RecordFailure("key1")
	rl.RecordFailure("key1") // key1 locked
	assert.False(t, rl.Allow("key1"))
	assert.True(t, rl.Allow("key2"))
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

func TestGenerateCSRFToken_NonEmpty(t *testing.T) {
	token, err := generateCSRFToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGenerateCSRFToken_Unique(t *testing.T) {
	t1, err := generateCSRFToken()
	require.NoError(t, err)
	t2, err := generateCSRFToken()
	require.NoError(t, err)
	assert.NotEqual(t, t1, t2)
}

func TestGenerateCSRFToken_Length(t *testing.T) {
	// 32 random bytes → 64 hex chars
	token, err := generateCSRFToken()
	require.NoError(t, err)
	assert.Len(t, token, 64)
}

func TestIsSecureRequest_WithTLS(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{}
	assert.True(t, IsSecureRequest(req))
}

func TestIsSecureRequest_WithoutTLS(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	assert.False(t, IsSecureRequest(req))
}

func TestIsSecureRequest_ForwardedProto(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	assert.True(t, IsSecureRequest(req))
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

func TestSetCSRFCookie_SetsCookie(t *testing.T) {
	w := httptest.NewRecorder()
	setCSRFCookie(w, "tok123", 30*time.Minute, true)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	c := cookies[0]
	assert.Equal(t, CSRFCookieName, c.Name)
	assert.Equal(t, "tok123", c.Value)
	assert.Equal(t, "/", c.Path)
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
	assert.Equal(t, 1800, c.MaxAge)
}

func TestSetCSRFCookie_Insecure(t *testing.T) {
	w := httptest.NewRecorder()
	setCSRFCookie(w, "tok456", 10*time.Minute, false)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.False(t, cookies[0].Secure)
}

func TestCSRFCookieNameConstant(t *testing.T) {
	assert.Equal(t, "sso_csrf_token", CSRFCookieName)
}

// ---------------------------------------------------------------------------
// Persistent brute-force lockout (accountLockedOut / recordLoginFailure)
// ---------------------------------------------------------------------------

func TestAccountLockedOut_WhenRealmBruteForceDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	realmRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	realmRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:               "master",
		BruteForceProtected: false,
	}, nil)

	wa := &WebAuth{
		realmSettingsRepo: realmRepo,
		config:            DefaultConfig(),
	}
	user := &domain.User{
		ID:                 "user-1",
		FailedLoginAttempts: 99,
		LastFailedLoginTime: ptrTime(time.Now().Add(-time.Minute)),
	}

	assert.False(t, wa.accountLockedOut(context.Background(), user))
}

func TestAccountLockedOut_WhenBelowMaxAttempts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	realmRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	realmRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:               "master",
		BruteForceProtected: true,
	}, nil)

	wa := &WebAuth{
		realmSettingsRepo: realmRepo,
		config:            DefaultConfig(),
	}
	user := &domain.User{
		ID:                  "user-1",
		FailedLoginAttempts: 4,
		LastFailedLoginTime: ptrTime(time.Now()),
	}

	assert.False(t, wa.accountLockedOut(context.Background(), user))
}

func TestAccountLockedOut_WhenNeverFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	realmRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	realmRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:               "master",
		BruteForceProtected: true,
	}, nil)

	wa := &WebAuth{
		realmSettingsRepo: realmRepo,
		config:            DefaultConfig(),
	}
	user := &domain.User{ID: "user-1", FailedLoginAttempts: 0}

	assert.False(t, wa.accountLockedOut(context.Background(), user))
}

func TestAccountLockedOut_WhenLockoutExpired(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	realmRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	realmRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:               "master",
		BruteForceProtected: true,
	}, nil)

	wa := &WebAuth{
		realmSettingsRepo: realmRepo,
		config:            DefaultConfig(),
	}
	user := &domain.User{
		ID:                  "user-1",
		FailedLoginAttempts: 5,
		LastFailedLoginTime: ptrTime(time.Now().Add(-16 * time.Minute)),
	}

	assert.False(t, wa.accountLockedOut(context.Background(), user))
}

func TestAccountLockedOut_WhenAtMaxAttempts_WithinLockoutWindow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	realmRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	realmRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:               "master",
		BruteForceProtected: true,
	}, nil)

	wa := &WebAuth{
		realmSettingsRepo: realmRepo,
		config:            DefaultConfig(),
	}
	user := &domain.User{
		ID:                  "user-1",
		FailedLoginAttempts: 5,
		LastFailedLoginTime: ptrTime(time.Now()),
	}

	assert.True(t, wa.accountLockedOut(context.Background(), user))
}

func TestAccountLockedOut_NilRepoNeverLocks(t *testing.T) {
	wa := &WebAuth{config: DefaultConfig()}
	user := &domain.User{
		ID:                  "user-1",
		FailedLoginAttempts: 100,
		LastFailedLoginTime: ptrTime(time.Now()),
	}

	assert.False(t, wa.accountLockedOut(context.Background(), user))
}

func TestRecordLoginFailure_WhenBruteForceEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	realmRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	realmRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:               "master",
		BruteForceProtected: true,
	}, nil)
	userRepo := mock_domain.NewMockUserRepository(ctrl)
	userRepo.EXPECT().IncrementFailedLoginAttempts(gomock.Any(), "user-1").Return(int32(5), nil)

	wa := &WebAuth{
		realmSettingsRepo: realmRepo,
		userRepo:          userRepo,
	}

	wa.recordLoginFailure(context.Background(), "user-1")
}

func TestRecordLoginFailure_WhenBruteForceDisabled_DoesNotTouchRepo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	realmRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	realmRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:               "master",
		BruteForceProtected: false,
	}, nil)
	userRepo := mock_domain.NewMockUserRepository(ctrl)

	wa := &WebAuth{
		realmSettingsRepo: realmRepo,
		userRepo:          userRepo,
	}

	wa.recordLoginFailure(context.Background(), "user-1")
}

func TestResetLoginFailures_WhenBruteForceEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	realmRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	realmRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		Realm:               "master",
		BruteForceProtected: true,
	}, nil)
	userRepo := mock_domain.NewMockUserRepository(ctrl)
	userRepo.EXPECT().ResetFailedLoginAttempts(gomock.Any(), "user-1").Return(nil)

	wa := &WebAuth{
		realmSettingsRepo: realmRepo,
		userRepo:          userRepo,
	}

	wa.resetLoginFailures(context.Background(), "user-1")
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
