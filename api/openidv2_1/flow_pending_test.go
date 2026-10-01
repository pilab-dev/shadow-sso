package openidv2_1_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// A flow that has a user ID but is still waiting on MFA or a required action
// must never be turned into an authorization code.
func TestAuthorizeFlow_PendingStepsBlockCodeIssuance(t *testing.T) {
	cases := map[string]struct{ pending, location string }{
		"mfa pending":             {domain.FlowPendingMFA, "/login?flow_id=f1"},
		"required action pending": {"action:UPDATE_PASSWORD", "/required-action?flow_id=f1"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			ctrl := gomock.NewController(t)
			flows := mock_domain.NewMockFlowStore(ctrl)
			flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(&domain.LoginFlowState{
				FlowID: "f1", ClientID: "c1", UserID: "u1", Pending: tc.pending,
				ExpiresAt: time.Now().Add(time.Minute),
			}, nil)

			// All other collaborators are nil: reaching them would panic, proving no code is issued.
			api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
				Config:    &sssoapi.OpenIDProviderConfig{},
				FlowStore: flows,
			})
			router := gin.New()
			router.GET("/oauth2/authorize", api.AuthorizeHandler)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", "/oauth2/authorize?flow_id=f1", nil))

			assert.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, tc.location, w.Header().Get("Location"))
		})
	}
}
