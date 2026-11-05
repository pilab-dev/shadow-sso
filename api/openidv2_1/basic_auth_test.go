package openidv2_1

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func basicAuthContext(body, user, pass string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		c.Request.SetBasicAuth(user, pass)
	}
	return c
}

func TestApplyBasicClientAuth(t *testing.T) {
	t.Run("maps credentials onto form values", func(t *testing.T) {
		c := basicAuthContext("grant_type=client_credentials", url.QueryEscape("my client"), url.QueryEscape("s3:cr+t"))
		applyBasicClientAuth(c)
		assert.Equal(t, "my client", c.PostForm("client_id"))
		assert.Equal(t, "s3:cr+t", c.PostForm("client_secret"))
		assert.Equal(t, "client_credentials", c.PostForm("grant_type"))
	})

	t.Run("mismatching body client_id is left untouched", func(t *testing.T) {
		c := basicAuthContext("client_id=other", "basic-id", "secret")
		applyBasicClientAuth(c)
		assert.Equal(t, "other", c.PostForm("client_id"))
		assert.Empty(t, c.PostForm("client_secret"))
	})

	t.Run("no header is a no-op", func(t *testing.T) {
		c := basicAuthContext("client_id=x", "", "")
		applyBasicClientAuth(c)
		assert.Equal(t, "x", c.PostForm("client_id"))
	})
}
