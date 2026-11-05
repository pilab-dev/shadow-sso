package openidv2_1_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPAR_EndpointReturnsRequestURI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		Config: &sssoapi.OpenIDProviderConfig{Issuer: "http://localhost"},
	})
	router := gin.New()
	api.RegisterRoutes(router)

	form := url.Values{}
	form.Set("client_id", "c1")
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("response_type", "code")
	form.Set("scope", "openid")
	body := strings.NewReader(form.Encode())
	req := httptest.NewRequest("POST", "/oauth2/par", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp, "request_uri")
	assert.Equal(t, float64(60), resp["expires_in"])
	uri := resp["request_uri"].(string)
	assert.True(t, strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:"))

	// LookupPAR should resolve it
	params, ok := sssogin.LookupPAR(uri)
	require.True(t, ok)
	assert.Equal(t, "c1", params["client_id"])
}

func TestPAR_LookupMissingReturnsFalse(t *testing.T) {
	params, ok := sssogin.LookupPAR("urn:ietf:params:oauth:request_uri:doesnotexist")
	assert.False(t, ok)
	assert.Nil(t, params)
}