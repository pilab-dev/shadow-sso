package webauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupStaticTest(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler, err := webauth.StaticHandler()
	require.NoError(t, err)

	router := gin.New()
	router.GET("/static/*filepath", handler)
	return router
}

func TestStaticHandler_ServesCSS(t *testing.T) {
	router := setupStaticTest(t)
	req := httptest.NewRequest(http.MethodGet, "/static/fonts/inter.css", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/css; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=86400", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Body.String(), "@font-face")
	assert.Contains(t, w.Body.String(), "inter-latin.woff2")
}

func TestStaticHandler_ServesFont(t *testing.T) {
	router := setupStaticTest(t)
	req := httptest.NewRequest(http.MethodGet, "/static/fonts/inter-latin.woff2", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "font/woff2", w.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=86400", w.Header().Get("Cache-Control"))
	assert.NotEmpty(t, w.Body.Bytes())
}
