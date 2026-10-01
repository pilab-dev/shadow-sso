package openidv2_1_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders_CSPAllowsQRDataURIsButNoInlineScripts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sssogin.SecurityHeadersMiddleware())
	r.GET("/", func(c *gin.Context) { c.Status(200) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	csp := w.Header().Get("Content-Security-Policy")
	img := csp[strings.Index(csp, "img-src"):]
	img = img[:strings.Index(img, ";")]
	assert.Contains(t, img, "data:", "TOTP QR codes are embedded as data: URIs")
	assert.Contains(t, csp, "script-src 'self';")
	assert.NotContains(t, csp, "unsafe-inline'; img", "scripts must not allow inline")
	assert.NotContains(t, csp[strings.Index(csp, "script-src"):strings.Index(csp, "style-src")], "unsafe-inline")
}
