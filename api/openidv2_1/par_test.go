package openidv2_1_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/pilab-dev/shadow-sso/cache/parstore"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func setupPARTest(t *testing.T) (*gin.Engine, *mock_domain.MockClientRepository, domain.PARStore) {
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockClientRepository(ctrl)
	store := parstore.NewMemory()
	t.Cleanup(store.Close)
	api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		PARStore:      store,
		Config:        &sssoapi.OpenIDProviderConfig{Issuer: "http://localhost"},
		ClientService: client.NewClientService(repo),
	})
	router := gin.New()
	api.RegisterRoutes(router)
	return router, repo, store
}

func postPAR(router *gin.Engine, form url.Values, basicID, basicSecret string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/oauth2/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func parForm(clientID string) url.Values {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("response_type", "code")
	form.Set("scope", "openid")
	return form
}

func TestPAR_PublicClientReturnsSingleUseBoundRequestURI(t *testing.T) {
	router, repo, store := setupPARTest(t)
	repo.EXPECT().GetClient(gomock.Any(), "c1").AnyTimes().Return(&domain.Client{ID: "c1"}, nil)

	w := postPAR(router, parForm("c1"), "", "")
	require.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(60), resp["expires_in"])
	uri := resp["request_uri"].(string)
	assert.True(t, strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:"))

	ctx := context.Background()
	_, err := store.Consume(ctx, uri, "other-client")
	assert.ErrorIs(t, err, domain.ErrPARNotFound, "request_uri must be bound to the pushing client")

	// the mismatched attempt burned it; push again to verify the happy path
	w = postPAR(router, parForm("c1"), "", "")
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	uri = resp["request_uri"].(string)

	params, err := store.Consume(ctx, uri, "c1")
	require.NoError(t, err)
	assert.Equal(t, "c1", params["client_id"])

	_, err = store.Consume(ctx, uri, "c1")
	assert.ErrorIs(t, err, domain.ErrPARNotFound, "request_uri must be single use")
}

func TestPAR_ConfidentialClientMustAuthenticate(t *testing.T) {
	router, repo, _ := setupPARTest(t)
	repo.EXPECT().GetClient(gomock.Any(), "conf").AnyTimes().Return(&domain.Client{ID: "conf", IsConfidential: true}, nil)

	w := postPAR(router, parForm("conf"), "", "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPAR_ConfidentialClientWithBasicAuth(t *testing.T) {
	router, repo, _ := setupPARTest(t)
	cli := &domain.Client{ID: "conf", IsConfidential: true}
	repo.EXPECT().GetClient(gomock.Any(), "conf").AnyTimes().Return(cli, nil)
	repo.EXPECT().ValidateClient(gomock.Any(), "conf", "s3cret").Return(cli, nil)

	w := postPAR(router, parForm("conf"), "conf", "s3cret")
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestPAR_RejectsNestedRequestURI(t *testing.T) {
	router, repo, _ := setupPARTest(t)
	repo.EXPECT().GetClient(gomock.Any(), "c1").AnyTimes().Return(&domain.Client{ID: "c1"}, nil)

	form := parForm("c1")
	form.Set("request_uri", "urn:ietf:params:oauth:request_uri:abc")
	assert.Equal(t, http.StatusBadRequest, postPAR(router, form, "", "").Code)
}
