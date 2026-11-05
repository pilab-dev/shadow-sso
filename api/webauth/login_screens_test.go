package webauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	authtotp "github.com/pilab-dev/shadow-sso/internal/auth/totp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type lsEnv struct {
	router *gin.Engine
	flows  *mock_domain.MockFlowStore
	users  *mock_domain.MockUserRepository
	hasher *mock_domain.MockPasswordHasher
	realm  *mock_domain.MockRealmSettingsRepository
	mail   *mock_domain.MockEmailService
}

// setupLoginScreensTest wires the email-driven screens. withMail=false simulates "no mail provider".
func setupLoginScreensTest(t *testing.T, withMail bool, realm *domain.RealmSettings) *lsEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)
	e := &lsEnv{
		flows:  mock_domain.NewMockFlowStore(ctrl),
		users:  mock_domain.NewMockUserRepository(ctrl),
		hasher: mock_domain.NewMockPasswordHasher(ctrl),
		realm:  mock_domain.NewMockRealmSettingsRepository(ctrl),
		mail:   mock_domain.NewMockEmailService(ctrl),
	}
	e.realm.EXPECT().GetRealmSettings(gomock.Any()).Return(realm, nil).AnyTimes()
	opts := &webauth.Options{
		UserRepo:          e.users,
		PasswordHasher:    e.hasher,
		FlowStore:         e.flows,
		RealmSettingsRepo: e.realm,
		Config:            webauth.DefaultConfig(),
		SSOCookieSecret:   raSecret,
		PublicBaseURL:     "https://sso.test",
	}
	if withMail {
		opts.EmailService = e.mail
	}
	wa := webauth.New(opts)
	e.router = gin.New()
	e.router.LoadHTMLGlob("templates/*.html")
	e.router.GET("/forgot-password", wa.ForgotPasswordPageHandler)
	e.router.POST("/forgot-password", wa.ForgotPasswordSubmitHandler)
	e.router.GET("/reset-password", wa.ResetPasswordPageHandler)
	e.router.POST("/reset-password", wa.ResetPasswordSubmitHandler)
	e.router.GET("/register", wa.RegisterPageHandler)
	e.router.POST("/register", wa.RegisterSubmitHandler)
	e.router.GET("/verify-email", wa.VerifyEmailHandler)
	e.router.GET("/required-action", wa.RequiredActionPageHandler)
	e.router.POST("/required-action", wa.RequiredActionSubmitHandler)
	return e
}

func (e *lsEnv) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// ---- forgot / reset password --------------------------------------------------------------

func TestForgotPassword_UnavailableWhenRealmDisallowsOrNoMail(t *testing.T) {
	e := setupLoginScreensTest(t, true, &domain.RealmSettings{ResetPasswordAllowed: false})
	assert.Equal(t, http.StatusNotFound, e.do(httptest.NewRequest("GET", "/forgot-password", nil)).Code)

	e = setupLoginScreensTest(t, false, &domain.RealmSettings{ResetPasswordAllowed: true})
	assert.Equal(t, http.StatusNotFound, e.do(httptest.NewRequest("GET", "/forgot-password", nil)).Code)
}

func TestForgotPassword_SendsLinkAndStoresOnlyDigest(t *testing.T) {
	e := setupLoginScreensTest(t, true, &domain.RealmSettings{ResetPasswordAllowed: true})
	e.users.EXPECT().GetUserByEmail(gomock.Any(), "a@b.c").Return(&domain.User{ID: "u1", Email: "a@b.c", Status: domain.UserStatusActive}, nil)

	var stored string
	e.users.EXPECT().StorePasswordResetToken(gomock.Any(), "u1", gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ any, _ string, digest string, exp time.Time) error {
			stored = digest
			assert.WithinDuration(t, time.Now().Add(30*time.Minute), exp, time.Minute)
			return nil
		})
	var link string
	e.mail.EXPECT().SendPasswordResetEmail("a@b.c", gomock.Any(), gomock.Any()).DoAndReturn(
		func(_, _, l string) error { link = l; return nil })

	w := e.do(raPost("/forgot-password", url.Values{"email": {"A@B.c "}}))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "If an account exists")
	require.True(t, strings.HasPrefix(link, "https://sso.test/reset-password?token="))
	token := strings.TrimPrefix(link, "https://sso.test/reset-password?token=")
	assert.NotEqual(t, token, stored, "the database must hold a digest, never the emailed token")
	assert.Len(t, stored, 64)
}

func TestForgotPassword_UnknownEmailGivesSameResponse(t *testing.T) {
	e := setupLoginScreensTest(t, true, &domain.RealmSettings{ResetPasswordAllowed: true})
	e.users.EXPECT().GetUserByEmail(gomock.Any(), "nobody@b.c").Return(nil, domain.ErrUserNotFound)
	w := e.do(raPost("/forgot-password", url.Values{"email": {"nobody@b.c"}}))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "If an account exists")
}

func TestResetPassword_Flow(t *testing.T) {
	exp := time.Now().Add(10 * time.Minute)
	user := func() *domain.User {
		return &domain.User{ID: "u1", Status: domain.UserStatusActive, PasswordHash: "old",
			PasswordResetToken: "digest", PasswordResetTokenExpiresAt: &exp,
			RequiredActions: []string{domain.RequiredActionUpdatePassword}}
	}

	t.Run("expired or unknown token", func(t *testing.T) {
		e := setupLoginScreensTest(t, true, &domain.RealmSettings{ResetPasswordAllowed: true})
		e.users.EXPECT().GetUserByPasswordResetToken(gomock.Any(), gomock.Any()).Return(nil, domain.ErrUserNotFound)
		assert.Equal(t, http.StatusBadRequest, e.do(httptest.NewRequest("GET", "/reset-password?token=zzz", nil)).Code)
	})

	t.Run("valid token resets password, is single use", func(t *testing.T) {
		e := setupLoginScreensTest(t, true, &domain.RealmSettings{ResetPasswordAllowed: true})
		e.users.EXPECT().GetUserByPasswordResetToken(gomock.Any(), gomock.Any()).Return(user(), nil)
		e.hasher.EXPECT().Hash("Sup3rSecret!").Return("new-hash", nil)
		var persisted *domain.User
		e.users.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, u *domain.User) error { persisted = u; return nil })

		w := e.do(raPost("/reset-password", url.Values{"token": {"tok"}, "new_password": {"Sup3rSecret!"}, "confirm_password": {"Sup3rSecret!"}}))

		require.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, persisted)
		assert.Equal(t, "new-hash", persisted.PasswordHash)
		assert.Empty(t, persisted.PasswordResetToken)
		assert.Nil(t, persisted.PasswordResetTokenExpiresAt)
		assert.Empty(t, persisted.RequiredActions)
		assert.True(t, persisted.IsEmailVerified)
	})

	t.Run("validation errors keep the token usable", func(t *testing.T) {
		e := setupLoginScreensTest(t, true, &domain.RealmSettings{ResetPasswordAllowed: true})
		e.users.EXPECT().GetUserByPasswordResetToken(gomock.Any(), gomock.Any()).Return(user(), nil)
		w := e.do(raPost("/reset-password", url.Values{"token": {"tok"}, "new_password": {"abc"}, "confirm_password": {"abc"}}))
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

// ---- register -------------------------------------------------------------------------------

func TestRegister_DisabledByDefault(t *testing.T) {
	e := setupLoginScreensTest(t, true, &domain.RealmSettings{RegistrationAllowed: false})
	assert.Equal(t, http.StatusNotFound, e.do(httptest.NewRequest("GET", "/register", nil)).Code)
	assert.Equal(t, http.StatusNotFound, e.do(raPost("/register", url.Values{"email": {"a@b.c"}})).Code)
}

func TestRegister_CreatesUserWithoutAdminRoleAndRequiresEmailVerification(t *testing.T) {
	e := setupLoginScreensTest(t, true, &domain.RealmSettings{RegistrationAllowed: true, VerifyEmail: true})
	e.users.EXPECT().GetUserByEmail(gomock.Any(), "new@b.c").Return(nil, domain.ErrUserNotFound)
	e.hasher.EXPECT().Hash("Sup3rSecret!").Return("hash", nil)
	var created *domain.User
	e.users.EXPECT().CreateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, u *domain.User) error { created = u; return nil })
	e.users.EXPECT().StoreEmailVerificationToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	e.mail.EXPECT().SendVerificationEmail(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	w := e.do(raPost("/register", url.Values{"email": {"new@b.c"}, "first_name": {"N"}, "password": {"Sup3rSecret!"}, "confirm_password": {"Sup3rSecret!"}}))

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, created)
	assert.Equal(t, []string{"ROLE_USER"}, created.Roles, "registration must never yield an admin")
	assert.Equal(t, "hash", created.PasswordHash)
	assert.True(t, created.HasRequiredAction(domain.RequiredActionVerifyEmail))
}

func TestRegister_RejectsDuplicateAndBadInput(t *testing.T) {
	e := setupLoginScreensTest(t, true, &domain.RealmSettings{RegistrationAllowed: true})
	e.users.EXPECT().GetUserByEmail(gomock.Any(), "dup@b.c").Return(&domain.User{ID: "x", PasswordHash: "hash"}, nil)
	w := e.do(raPost("/register", url.Values{"email": {"dup@b.c"}, "password": {"Sup3rSecret!"}, "confirm_password": {"Sup3rSecret!"}}))
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "already exists")

	for name, form := range map[string]url.Values{
		"bad email": {"email": {"nope"}, "password": {"Sup3rSecret!"}, "confirm_password": {"Sup3rSecret!"}},
		"mismatch":  {"email": {"a@b.c"}, "password": {"Sup3rSecret!"}, "confirm_password": {"x"}},
		"weak":      {"email": {"a@b.c"}, "password": {"abc"}, "confirm_password": {"abc"}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, http.StatusUnprocessableEntity, e.do(raPost("/register", form)).Code)
		})
	}
}

// ---- verify email ---------------------------------------------------------------------------

func TestVerifyEmail_Link(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	e := setupLoginScreensTest(t, true, &domain.RealmSettings{})
	e.users.EXPECT().GetUserByEmailVerificationToken(gomock.Any(), gomock.Any()).Return(&domain.User{
		ID: "u1", EmailVerificationToken: "d", EmailVerificationTokenExpiresAt: &exp,
		RequiredActions: []string{domain.RequiredActionVerifyEmail}}, nil)
	var persisted *domain.User
	e.users.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, u *domain.User) error { persisted = u; return nil })

	w := e.do(httptest.NewRequest("GET", "/verify-email?token=abc", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, persisted)
	assert.True(t, persisted.IsEmailVerified)
	assert.Empty(t, persisted.EmailVerificationToken)
	assert.Empty(t, persisted.RequiredActions)

	// expired
	past := time.Now().Add(-time.Minute)
	e = setupLoginScreensTest(t, true, &domain.RealmSettings{})
	e.users.EXPECT().GetUserByEmailVerificationToken(gomock.Any(), gomock.Any()).Return(&domain.User{ID: "u1", EmailVerificationTokenExpiresAt: &past}, nil)
	assert.Equal(t, http.StatusBadRequest, e.do(httptest.NewRequest("GET", "/verify-email?token=abc", nil)).Code)
}

func TestVerifyEmailAction_SendsLinkOnFirstVisit(t *testing.T) {
	e := setupLoginScreensTest(t, true, &domain.RealmSettings{})
	e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(raFlow("action:VERIFY_EMAIL"), nil)
	e.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", Email: "a@b.c", Status: domain.UserStatusActive,
		RequiredActions: []string{domain.RequiredActionVerifyEmail}}, nil)
	e.users.EXPECT().StoreEmailVerificationToken(gomock.Any(), "u1", gomock.Any(), gomock.Any()).Return(nil)
	e.mail.EXPECT().SendVerificationEmail("a@b.c", gomock.Any(), gomock.Regex(`^https://sso\.test/verify-email\?token=`)).Return(nil)

	w := e.do(httptest.NewRequest("GET", "/required-action?flow_id=f1", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Verify your email")
}

func TestVerifyEmailAction_SkippedWithoutMailProvider(t *testing.T) {
	// No mail provider: the action cannot be completed, so login must not park on it.
	e := setupLoginScreensTest(t, false, &domain.RealmSettings{})
	e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(raFlow("action:VERIFY_EMAIL"), nil)
	w := e.do(httptest.NewRequest("GET", "/required-action?flow_id=f1", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code, "an action without a usable handler is not served")
}

// ---- configure TOTP -------------------------------------------------------------------------

func TestConfigureTOTP_EnrolmentShowsRecoveryCodesThenContinues(t *testing.T) {
	e := setupLoginScreensTest(t, true, &domain.RealmSettings{})
	key, _, err := authtotp.GenerateTOTPSecret("Shadow SSO", "a@b.c")
	require.NoError(t, err)
	user := &domain.User{ID: "u1", Email: "a@b.c", Status: domain.UserStatusActive,
		TwoFactorSecret: key.Secret(), TwoFactorMethod: "TOTP",
		RequiredActions: []string{domain.RequiredActionConfigureTOTP}}

	// GET shows the QR (secret already pending, so no UpdateUser).
	e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(raFlow("action:CONFIGURE_TOTP"), nil).Times(3)
	e.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(user, nil).Times(3)
	w := e.do(httptest.NewRequest("GET", "/required-action?flow_id=f1", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "data:image/png;base64,")
	assert.Contains(t, w.Body.String(), key.Secret())

	// Wrong code is rejected and nothing is enabled.
	w = e.do(raPost("/required-action", url.Values{"flow_id": {"f1"}, "otp": {"000000"}}))
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.False(t, user.IsTwoFactorEnabled)

	// Right code enables TOTP, persists hashed recovery codes, shows plaintext once.
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	e.users.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)
	w = e.do(raPost("/required-action", url.Values{"flow_id": {"f1"}, "otp": {code}}))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Save your recovery codes")
	assert.True(t, user.IsTwoFactorEnabled)
	assert.False(t, user.HasRequiredAction(domain.RequiredActionConfigureTOTP))
	assert.Len(t, user.TwoFactorRecoveryCodes, 10)
	for _, h := range user.TwoFactorRecoveryCodes {
		assert.NotContains(t, w.Body.String(), h, "hashes are never shown")
	}
}
