package webauth

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	xhtml "golang.org/x/net/html"
)

// The web UI is translated at the response boundary: templates and handlers keep
// the English source text, and each locale file maps English strings to their
// translation. "{}" in a key matches any text and is carried into the
// translation, which covers sentences that embed dynamic values.

//go:embed locales/*.json
var localesFS embed.FS

const (
	defaultLocale    = "en"
	localeCookieName = "sso_lang"
	localeQueryParam = "lang"
	localeContextKey = "webauth.locale"
)

// supportedLocales lists the UI languages in switcher order.
var supportedLocales = []struct{ Code, Name string }{
	{"en", "English"},
	{"hu", "Magyar"},
	{"de", "Deutsch"},
	{"fr", "Français"},
}

type localePattern struct {
	re    *regexp.Regexp
	parts []string
	// prefix is the length of the source's leading literal.
	prefix int
}

type catalog struct {
	exact    map[string]string
	patterns []localePattern
}

var catalogs = loadCatalogs()

func loadCatalogs() map[string]*catalog {
	out := map[string]*catalog{}
	for _, l := range supportedLocales {
		raw, err := localesFS.ReadFile("locales/" + l.Code + ".json")
		if err != nil {
			continue
		}
		entries := map[string]string{}
		if err := json.Unmarshal(raw, &entries); err != nil {
			panic(fmt.Sprintf("webauth: invalid locale file %s: %v", l.Code, err))
		}
		out[l.Code] = newCatalog(entries)
	}
	return out
}

func newCatalog(entries map[string]string) *catalog {
	c := &catalog{exact: map[string]string{}}
	for src, dst := range entries {
		if !strings.Contains(src, "{}") {
			c.exact[src] = dst
			continue
		}
		pieces := strings.Split(src, "{}")
		quoted := make([]string, len(pieces))
		for i, p := range pieces {
			quoted[i] = regexp.QuoteMeta(p)
		}
		c.patterns = append(c.patterns, localePattern{
			re:     regexp.MustCompile("^" + strings.Join(quoted, "(.+?)") + "$"),
			parts:  strings.Split(dst, "{}"),
			prefix: len(pieces[0]),
		})
	}
	// Patterns anchored by a leading literal win over open-ended ones ("Last used {}" before "{} ago").
	sort.SliceStable(c.patterns, func(i, j int) bool { return c.patterns[i].prefix > c.patterns[j].prefix })
	return c
}

// lookup translates a whitespace-normalised string, reporting whether a translation exists.
func (c *catalog) lookup(s string) (string, bool) {
	if c == nil {
		return "", false
	}
	if t, ok := c.exact[s]; ok {
		return t, true
	}
	for _, p := range c.patterns {
		m := p.re.FindStringSubmatch(s)
		if m == nil || len(m)-1 != len(p.parts)-1 {
			continue
		}
		var b strings.Builder
		for i, part := range p.parts {
			b.WriteString(part)
			if i < len(m)-1 {
				if inner, ok := c.lookup(m[i+1]); ok {
					b.WriteString(inner)
				} else {
					b.WriteString(m[i+1])
				}
			}
		}
		return b.String(), true
	}
	return "", false
}

func supportedLocale(code string) (string, bool) {
	code = strings.ToLower(strings.TrimSpace(code))
	if i := strings.IndexAny(code, "-_"); i > 0 {
		code = code[:i]
	}
	for _, l := range supportedLocales {
		if l.Code == code {
			return code, true
		}
	}
	return "", false
}

// firstSupported returns the first supported language of an ordered list such as ui_locales.
func firstSupported(list string) (string, bool) {
	for _, tag := range strings.Fields(strings.ReplaceAll(list, ",", " ")) {
		if i := strings.Index(tag, ";"); i >= 0 {
			tag = tag[:i]
		}
		if code, ok := supportedLocale(tag); ok {
			return code, true
		}
	}
	return "", false
}

// acceptLanguage picks the best supported language of an Accept-Language header.
func acceptLanguage(header string) (string, bool) {
	type cand struct {
		code string
		q    float64
	}
	var cands []cand
	for _, part := range strings.Split(header, ",") {
		tag, q := part, 1.0
		if i := strings.Index(part, ";"); i >= 0 {
			tag = part[:i]
			if v := strings.TrimSpace(part[i+1:]); strings.HasPrefix(v, "q=") {
				if f, err := strconv.ParseFloat(v[2:], 64); err == nil {
					q = f
				}
			}
		}
		if code, ok := supportedLocale(tag); ok && q > 0 {
			cands = append(cands, cand{code, q})
		}
	}
	if len(cands) == 0 {
		return "", false
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].q > cands[j].q })
	return cands[0].code, true
}

// resolveLocale chooses the UI language: explicit ?lang=, saved cookie, OIDC ui_locales,
// Accept-Language, then English.
func resolveLocale(r *http.Request) string {
	if code, ok := supportedLocale(r.URL.Query().Get(localeQueryParam)); ok && r.URL.Query().Get(localeQueryParam) != "" {
		return code
	}
	if ck, err := r.Cookie(localeCookieName); err == nil {
		if code, ok := supportedLocale(ck.Value); ok {
			return code
		}
	}
	if code, ok := firstSupported(r.URL.Query().Get("ui_locales")); ok {
		return code
	}
	if code, ok := acceptLanguage(r.Header.Get("Accept-Language")); ok {
		return code
	}
	return defaultLocale
}

// i18nMiddleware translates HTML responses into the request's language and appends a
// language switcher to GET pages.
func (wa *WebAuth) i18nMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		locale := resolveLocale(c.Request)
		if code, ok := supportedLocale(c.Query(localeQueryParam)); ok && c.Query(localeQueryParam) != "" {
			http.SetCookie(c.Writer, &http.Cookie{
				Name:     localeCookieName,
				Value:    code,
				Path:     "/",
				MaxAge:   365 * 24 * 3600,
				HttpOnly: true,
				Secure:   IsSecureRequest(c.Request),
				SameSite: http.SameSiteLaxMode,
			})
		}
		c.Set(localeContextKey, locale)

		orig := c.Writer
		bw := &i18nWriter{ResponseWriter: orig}
		c.Writer = bw
		c.Next()
		c.Writer = orig

		body := bw.buf.Bytes()
		orig.Header().Add("Vary", "Accept-Language")
		orig.Header().Add("Vary", "Cookie")
		if len(body) > 0 && strings.HasPrefix(orig.Header().Get("Content-Type"), "text/html") {
			switcher := ""
			if c.Request.Method == http.MethodGet {
				switcher = languageSwitcher(c.Request.URL, locale)
			}
			body = translateHTML(body, catalogs[locale], locale, switcher)
			orig.Header().Del("Content-Length")
		}
		if len(body) > 0 {
			_, _ = orig.Write(body)
		} else {
			orig.WriteHeaderNow()
		}
	}
}

// i18nWriter buffers the response so it can be translated before it is sent.
type i18nWriter struct {
	gin.ResponseWriter
	buf bytes.Buffer
}

func (w *i18nWriter) Write(b []byte) (int, error)       { return w.buf.Write(b) }
func (w *i18nWriter) WriteString(s string) (int, error) { return w.buf.WriteString(s) }
func (w *i18nWriter) WriteHeaderNow()                   {}
func (w *i18nWriter) Written() bool                     { return w.buf.Len() > 0 || w.ResponseWriter.Written() }
func (w *i18nWriter) Flush()                            {}

func languageSwitcher(u *url.URL, current string) string {
	var b strings.Builder
	b.WriteString(`<nav class="lang-switch" aria-label="Language" style="position:relative;z-index:1;display:flex;gap:14px;justify-content:center;flex-wrap:wrap;margin-top:12px;font-size:0.75rem;">`)
	for _, l := range supportedLocales {
		q := u.Query()
		q.Set(localeQueryParam, l.Code)
		href := html.EscapeString(u.Path + "?" + q.Encode())
		if l.Code == current {
			fmt.Fprintf(&b, `<span aria-current="true" style="color:var(--text);font-weight:600;">%s</span>`, l.Name)
			continue
		}
		fmt.Fprintf(&b, `<a href="%s" hreflang="%s" lang="%s" style="color:var(--text-subtle);text-decoration:none;">%s</a>`, href, l.Code, l.Code, l.Name)
	}
	b.WriteString(`</nav>`)
	return b.String()
}

var translatableAttrs = map[string]bool{"placeholder": true, "title": true, "aria-label": true, "alt": true}

func normalizeSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// translateText translates s while keeping its surrounding whitespace.
func translateText(cat *catalog, s string) (string, bool) {
	core := normalizeSpace(s)
	if core == "" {
		return s, false
	}
	t, ok := cat.lookup(core)
	if !ok {
		return s, false
	}
	lead := s[:len(s)-len(strings.TrimLeft(s, " \t\r\n"))]
	trail := s[len(strings.TrimRight(s, " \t\r\n")):]
	return lead + t + trail, true
}

// translateHTML rewrites the text nodes and user-visible attributes of an HTML document.
func translateHTML(src []byte, cat *catalog, locale, switcher string) []byte {
	var out bytes.Buffer
	z := xhtml.NewTokenizer(bytes.NewReader(src))
	rawElement, inTitle := "", false
	for {
		tt := z.Next()
		if tt == xhtml.ErrorToken {
			out.Write(z.Raw())
			return out.Bytes()
		}
		switch tt {
		case xhtml.TextToken:
			raw := append([]byte(nil), z.Raw()...)
			if rawElement != "" {
				out.Write(raw)
				continue
			}
			text := string(z.Text())
			if inTitle {
				first, rest, found := strings.Cut(text, " — ")
				if t, ok := translateText(cat, first); ok {
					if found {
						t += " — " + rest
					}
					out.WriteString(html.EscapeString(t))
					continue
				}
			} else if t, ok := translateText(cat, text); ok {
				out.WriteString(html.EscapeString(t))
				continue
			}
			out.Write(raw)
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			raw := append([]byte(nil), z.Raw()...)
			nameB, hasAttr := z.TagName()
			name := string(nameB)
			if tt == xhtml.StartTagToken {
				switch name {
				case "script", "style":
					rawElement = name
				case "title":
					inTitle = true
				}
			}
			if !hasAttr || (name != "html" && !hasTranslatable(raw)) {
				if name == "html" && !hasAttr {
					out.WriteString(`<html lang="` + locale + `">`)
					continue
				}
				out.Write(raw)
				continue
			}
			type attr struct{ k, v string }
			var attrs []attr
			changed := false
			for {
				k, v, more := z.TagAttr()
				key, val := string(k), string(v)
				if name == "html" && key == "lang" {
					val, changed = locale, true
				} else if translatableAttrs[key] {
					if t, ok := translateText(cat, val); ok {
						val, changed = t, true
					}
				}
				attrs = append(attrs, attr{key, val})
				if !more {
					break
				}
			}
			if !changed {
				out.Write(raw)
				continue
			}
			out.WriteString("<" + name)
			for _, a := range attrs {
				out.WriteString(" " + a.k + `="` + html.EscapeString(a.v) + `"`)
			}
			if tt == xhtml.SelfClosingTagToken {
				out.WriteString("/")
			}
			out.WriteString(">")
		case xhtml.EndTagToken:
			raw := append([]byte(nil), z.Raw()...)
			name, _ := z.TagName()
			switch string(name) {
			case string(rawElement):
				rawElement = ""
			case "title":
				inTitle = false
			case "body":
				out.WriteString(switcher)
			}
			out.Write(raw)
		default:
			out.Write(z.Raw())
		}
	}
}

func hasTranslatable(rawTag []byte) bool {
	s := strings.ToLower(string(rawTag))
	for k := range translatableAttrs {
		if strings.Contains(s, k+"=") {
			return true
		}
	}
	return false
}
