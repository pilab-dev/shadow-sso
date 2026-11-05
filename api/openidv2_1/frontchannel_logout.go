package openidv2_1

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
)

var frontchannelLogoutTmpl = template.Must(template.New("frontchannel").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signing out</title>
{{if .Next}}<meta http-equiv="refresh" content="2;url={{.Next}}">{{end}}</head>
<body><p>Signing out…</p>
<iframe src="{{.Frame}}" style="display:none" referrerpolicy="no-referrer" sandbox="allow-scripts allow-same-origin" title="logout"></iframe>
</body></html>`))

// frontchannelLogoutURL builds the client's front-channel logout URL, adding
// iss and sid when the client requires them (OIDC Front-Channel Logout 1.0 §3).
func frontchannelLogoutURL(client *domain.Client, issuer, sid string) (string, bool) {
	if client == nil || client.FrontchannelLogoutURI == "" {
		return "", false
	}
	u, err := url.Parse(client.FrontchannelLogoutURI)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", false
	}
	if client.FrontchannelLogoutSessionRequired {
		if sid == "" || issuer == "" {
			return "", false
		}
		q := u.Query()
		q.Set("iss", issuer)
		q.Set("sid", sid)
		u.RawQuery = q.Encode()
	}
	return u.String(), true
}

// renderFrontchannelLogout writes a page that loads the client's logout URI in
// a hidden iframe and then continues to next (if set) via a meta refresh.
func renderFrontchannelLogout(c *gin.Context, frameURL, next string) {
	u, _ := url.Parse(frameURL)
	c.Header("Content-Security-Policy", "default-src 'none'; frame-src "+u.Scheme+"://"+u.Host+"; style-src 'unsafe-inline'")
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = frontchannelLogoutTmpl.Execute(c.Writer, struct {
		Frame, Next string
	}{frameURL, strings.TrimSpace(next)})
}
