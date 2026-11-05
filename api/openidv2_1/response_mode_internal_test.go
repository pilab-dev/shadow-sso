package openidv2_1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedirectToClient_ResponseModes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oa := &OAuth2API{config: &sssoapi.OpenIDProviderConfig{Issuer: "https://sso.example"}}

	run := func(mode string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		oa.redirectToClient(c, "client", "https://rp.example/cb", "the-code", "st", mode)
		c.Writer.WriteHeaderNow()
		return w
	}

	t.Run("query", func(t *testing.T) {
		w := run("")
		require.Equal(t, http.StatusFound, w.Code)
		loc := w.Header().Get("Location")
		assert.Contains(t, loc, "?code=the-code")
		assert.Contains(t, loc, "iss=")
	})
	t.Run("fragment", func(t *testing.T) {
		w := run("fragment")
		require.Equal(t, http.StatusFound, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "https://rp.example/cb#code=the-code")
	})
	t.Run("form_post", func(t *testing.T) {
		w := run("form_post")
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `action="https://rp.example/cb"`)
		assert.Contains(t, w.Body.String(), `name="code" value="the-code"`)
	})
}
