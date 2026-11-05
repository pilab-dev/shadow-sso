package webauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveLocale(t *testing.T) {
	tests := []struct {
		name, url, cookie, accept, want string
	}{
		{"default", "/", "", "", "en"},
		{"accept-language with q", "/", "", "fr-CH, de;q=0.9, en;q=0.5", "fr"},
		{"unsupported accept falls back", "/", "", "ja, zh;q=0.8", "en"},
		{"ui_locales", "/?ui_locales=xx%20hu-HU%20de", "", "fr", "hu"},
		{"cookie beats ui_locales", "/?ui_locales=hu", "de", "", "de"},
		{"query beats cookie", "/?lang=fr", "de", "", "fr"},
		{"invalid query ignored", "/?lang=zz", "de", "", "de"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.url, nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: localeCookieName, Value: tc.cookie})
			}
			if tc.accept != "" {
				req.Header.Set("Accept-Language", tc.accept)
			}
			assert.Equal(t, tc.want, resolveLocale(req))
		})
	}
}

func TestCatalogPatterns(t *testing.T) {
	de := catalogs["de"]
	got, ok := de.lookup("Last used 5 minutes ago")
	require.True(t, ok)
	assert.Equal(t, "Zuletzt verwendet: vor 5 Minuten", got)

	got, ok = catalogs["fr"].lookup("to continue to Acme")
	require.True(t, ok)
	assert.Equal(t, "pour continuer vers Acme", got)

	_, ok = de.lookup("Some untranslated sentence")
	assert.False(t, ok)
}

func TestLocalesHaveSameKeys(t *testing.T) {
	for _, code := range []string{"hu", "de", "fr"} {
		require.NotNil(t, catalogs[code], code)
	}
	for src := range catalogs["hu"].exact {
		for _, code := range []string{"de", "fr"} {
			_, ok := catalogs[code].exact[src]
			assert.True(t, ok, "%s missing %q", code, src)
		}
	}
	assert.Len(t, catalogs["de"].patterns, len(catalogs["hu"].patterns))
	assert.Len(t, catalogs["fr"].patterns, len(catalogs["hu"].patterns))
}

func TestTranslateHTML(t *testing.T) {
	src := `<!DOCTYPE html><html lang="en"><head><title>Sign In — Shadow SSO</title><style>.x{content:"Deny"}</style></head>` +
		`<body><h2>Deny</h2><input placeholder="Enter your password" value="Deny"><p>  Allow Access </p><p>Brand&amp;Co</p></body></html>`
	out := string(translateHTML([]byte(src), catalogs["de"], "de", `<nav>SW</nav>`))

	assert.Contains(t, out, `<html lang="de">`)
	assert.Contains(t, out, "<title>Anmelden — Shadow SSO</title>")
	assert.Contains(t, out, `content:"Deny"`, "style content must stay untouched")
	assert.Contains(t, out, "<h2>Ablehnen</h2>")
	assert.Contains(t, out, `placeholder="Geben Sie Ihr Passwort ein"`)
	assert.Contains(t, out, `value="Deny"`)
	assert.Contains(t, out, "<p>  Zugriff erlauben </p>")
	assert.Contains(t, out, "<p>Brand&amp;Co</p>")
	assert.Contains(t, out, "<nav>SW</nav></body>")
}

func TestI18nMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	wa := &WebAuth{}
	r := gin.New()
	r.Use(wa.i18nMiddleware())
	r.GET("/page", func(c *gin.Context) {
		c.Data(http.StatusTeapot, "text/html; charset=utf-8", []byte(`<html lang="en"><body><h1>Request denied</h1></body></html>`))
	})
	r.GET("/json", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"m": "Request denied"}) })
	r.GET("/go", func(c *gin.Context) { c.Redirect(http.StatusFound, "/page") })

	t.Run("translates html and keeps status", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/page?user_code=AB", nil)
		req.Header.Set("Accept-Language", "hu")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTeapot, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "<h1>Kérés elutasítva</h1>")
		assert.Contains(t, body, `lang="hu"`)
		assert.Contains(t, body, `href="/page?lang=de&amp;user_code=AB"`, "switcher keeps the query")
		assert.Contains(t, w.Header().Get("Vary"), "Accept-Language")
	})

	t.Run("lang param persists in cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/page?lang=fr", nil))
		assert.Contains(t, w.Body.String(), "Demande refusée")
		var saved string
		for _, c := range w.Result().Cookies() {
			if c.Name == localeCookieName {
				saved = c.Value
			}
		}
		assert.Equal(t, "fr", saved)
	})

	t.Run("json untouched", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/json", nil)
		req.Header.Set("Accept-Language", "de")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.JSONEq(t, `{"m":"Request denied"}`, w.Body.String())
	})

	t.Run("redirect preserved", func(t *testing.T) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/go", nil))
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/page", w.Header().Get("Location"))
	})

	t.Run("english leaves text alone", func(t *testing.T) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/page", nil))
		assert.True(t, strings.Contains(w.Body.String(), "<h1>Request denied</h1>"))
	})
}
