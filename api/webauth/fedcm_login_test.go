package webauth_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestLoginPage_FedCMStartsIsolatedFlow verifies the active-mode FedCM login
// URL works without an OIDC flow and does not overwrite the regular flow
// cookie.
func TestLoginPage_FedCMStartsIsolatedFlow(t *testing.T) {
	router, ctrl, mockFlowStore, _, mockIdPRepo, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	var storedFlowID string
	mockFlowStore.EXPECT().StoreFlow(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, flowID string, _ domain.LoginFlowState) error {
			storedFlowID = flowID
			return nil
		},
	).Times(1)
	mockIdPRepo.EXPECT().ListIdPs(gomock.Any(), true).Return([]*domain.IdentityProvider{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/login?fedcm=1", nil)
	// Simulate an in-progress OIDC login in another window.
	req.AddCookie(&http.Cookie{Name: webauth.FlowCookieName, Value: "oidc-flow-in-progress"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Sign in to your account")
	require.NotEmpty(t, storedFlowID)

	cookies := w.Result().Cookies()
	fedcmMarker := findCookie(cookies, webauth.FedCMLoginCookieName)
	require.NotNil(t, fedcmMarker)
	assert.Equal(t, "1", fedcmMarker.Value)

	fedcmFlow := findCookie(cookies, webauth.FedCMFlowCookieName)
	require.NotNil(t, fedcmFlow)
	assert.Equal(t, storedFlowID, fedcmFlow.Value)

	// The OIDC flow cookie must not be touched.
	assert.Nil(t, findCookie(cookies, webauth.FlowCookieName))

	rtCookie := findCookie(cookies, webauth.ReturnToCookieName)
	require.NotNil(t, rtCookie)
	parts := strings.Split(rtCookie.Value, ".")
	require.Len(t, parts, 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	assert.Equal(t, "/fedcm/close", string(payload))
}

// TestGetFlowIDFromCookie_FedCMPrecedesOIDC verifies the FedCM flow cookie is
// used while the FedCM marker is present.
func TestGetFlowIDFromCookie_FedCMPrecedesOIDC(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: webauth.FedCMLoginCookieName, Value: "1"})
	req.AddCookie(&http.Cookie{Name: webauth.FedCMFlowCookieName, Value: "fedcm-flow"})
	req.AddCookie(&http.Cookie{Name: webauth.FlowCookieName, Value: "oidc-flow"})

	assert.Equal(t, "fedcm-flow", webauth.GetFlowIDFromCookie(req))

	req = httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: webauth.FlowCookieName, Value: "oidc-flow"})
	assert.Equal(t, "oidc-flow", webauth.GetFlowIDFromCookie(req))
}

// TestFedCMClosePageClearsFlow verifies the FedCM close page clears the
// isolated flow cookies and renders the close script.
func TestFedCMClosePageClearsFlow(t *testing.T) {
	router, ctrl, _, _, _, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	req := httptest.NewRequest(http.MethodGet, "/fedcm/close", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/static/fedcm-close.js")

	cookies := w.Result().Cookies()
	for _, name := range []string{webauth.FedCMLoginCookieName, webauth.FedCMFlowCookieName} {
		cookie := findCookie(cookies, name)
		require.NotNil(t, cookie, "expected %s to be cleared", name)
		assert.Equal(t, -1, cookie.MaxAge)
	}
}
