package webauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	"github.com/rs/zerolog/log"
)

// renderTemplate is a global helper that sets security headers and renders an
// HTML template with the provided data. It generates a fresh CSRF token and
// stores it both in a cookie and in the template data so the form can include
// it as a hidden field.
func (wa *WebAuth) renderTemplate(c *gin.Context, templateName string, data gin.H) {
	csrfToken, err := generateCSRFToken()
	if err != nil {
		log.Error().Err(err).Msg("renderTemplate: failed to generate CSRF token")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"Message": "Internal error. Please try again.",
		})
		return
	}

	isSecure := IsSecureRequest(c.Request)
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, isSecure)

	if data == nil {
		data = gin.H{}
	}
	data["CSRFToken"] = csrfToken
	data["BrandLogo"] = wa.config.BrandLogoURL
	data["BrandName"] = wa.config.BrandOrganizationName
	data["BrandColor"] = wa.config.BrandPrimaryColor

	if _, ok := data["PageTitle"]; !ok {
		data["PageTitle"] = "Shadow SSO"
	}

	c.HTML(http.StatusOK, templateName, data)
}

// ConsentPageHandler renders the OAuth consent screen.
func (wa *WebAuth) ConsentPageHandler(c *gin.Context) {
	flowID := c.Query("flow_id")
	if flowID == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Missing consent request identifier.",
		})
		return
	}

	flowState, err := wa.flowStore.GetFlow(flowID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("consent: flow not found")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired consent request.",
		})
		return
	}
	if time.Now().After(flowState.ExpiresAt) {
		log.Warn().Str("flow_id", flowID).Msg("consent: flow expired")
		_ = wa.flowStore.DeleteFlow(flowID)
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Consent request has expired. Please try again.",
		})
		return
	}

	ctx := c.Request.Context()
	client, err := wa.clientService.GetClient(ctx, flowState.ClientID)
	if err != nil {
		log.Error().Err(err).Str("client_id", flowState.ClientID).Msg("consent: failed to load client")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Failed to load application details.",
		})
		return
	}

	scopes := strings.Split(flowState.Scope, " ")

	wa.renderTemplate(c, "consent.html", gin.H{
		"PageTitle":       "Authorization Required",
		"FlowID":          flowID,
		"ClientID":        flowState.ClientID,
		"ClientName":      client.Name,
		"ClientLogo":      client.LogoURI,
		"ClientDescription": "",
		"Scopes":          scopes,
		"RedirectURI":     flowState.RedirectURI,
	})
}

// ConsentSubmitHandler processes the user's consent decision (approve / deny).
func (wa *WebAuth) ConsentSubmitHandler(c *gin.Context) {
	if !validateCSRFTokenForm(c) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid form submission. Please try again.",
		})
		return
	}

	flowID := c.PostForm("flow_id")
	decision := c.PostForm("decision")

	if flowID == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Missing consent request identifier.",
		})
		return
	}

	flowState, err := wa.flowStore.GetFlow(flowID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("consent: flow not found on submit")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired consent request.",
		})
		return
	}
	if time.Now().After(flowState.ExpiresAt) {
		log.Warn().Str("flow_id", flowID).Msg("consent: flow expired on submit")
		_ = wa.flowStore.DeleteFlow(flowID)
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Consent request has expired. Please try again.",
		})
		return
	}

	if decision != "approve" {
		log.Info().Str("flow_id", flowID).Str("client_id", flowState.ClientID).Msg("consent: user denied")
		_ = wa.flowStore.DeleteFlow(flowID)
		if flowState.RedirectURI == "" {
			c.HTML(http.StatusOK, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Access denied.",
			})
			return
		}
		parsedURI, parseErr := url.Parse(flowState.RedirectURI)
		if parseErr != nil {
			log.Error().Err(parseErr).Str("redirect_uri", flowState.RedirectURI).Msg("consent: failed to parse redirect URI")
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Internal error.",
			})
			return
		}
		params := url.Values{}
		params.Set("error", "access_denied")
		params.Set("error_description", "The user denied the authorization request.")
		if flowState.State != "" {
			params.Set("state", flowState.State)
		}
		parsedURI.RawQuery = params.Encode()
		c.Redirect(http.StatusFound, parsedURI.String())
		return
	}

	ctx := c.Request.Context()
	authTime := flowState.UserAuthenticatedAt
	if authTime.IsZero() {
		authTime = time.Now()
	}

	authCode, err := wa.oauthService.GenerateAuthCode(
		ctx,
		flowState.ClientID,
		flowState.UserID,
		flowState.RedirectURI,
		flowState.Scope,
		flowState.CodeChallenge,
		flowState.CodeChallengeMethod,
		flowState.Nonce,
		authTime,
	)
	if err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Msg("consent: failed to generate auth code")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Failed to complete authorization. Please try again.",
		})
		return
	}

	_ = wa.flowStore.DeleteFlow(flowID)

	isSecure := IsSecureRequest(c.Request)
	displayName := flowState.UserID
	ssoSession := &ssosession.Session{
		SessionID: ssosession.NewID(),
		Accounts: []ssosession.Account{{
			UserID:   flowState.UserID,
			LastUsed: time.Now(),
		}},
	}
	if existingSession, sessErr := GetSSOSession(c.Request, wa.ssoCookieSecret); sessErr == nil && existingSession != nil {
		ssoSession.Accounts = existingSession.Accounts
		for i := range ssoSession.Accounts {
			if ssoSession.Accounts[i].UserID == flowState.UserID {
				ssoSession.Accounts[i].LastUsed = time.Now()
				if ssoSession.Accounts[i].Name != "" {
					displayName = ssoSession.Accounts[i].Name
				}
				break
			}
		}
	}
	_ = displayName

	if setErr := SetSSOSessionCookie(c.Writer, ssoSession, isSecure, wa.ssoCookieSecret); setErr != nil {
		log.Error().Err(setErr).Msg("consent: failed to update SSO session cookie")
	}

	redirectURL, err := RedirectURIForFlow(flowState.RedirectURI, authCode, flowState.State)
	if err != nil {
		log.Error().Err(err).Str("redirect_uri", flowState.RedirectURI).Msg("consent: failed to build redirect URI")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Internal error.",
		})
		return
	}

	log.Info().
		Str("flow_id", flowID).
		Str("client_id", flowState.ClientID).
		Str("user_id", flowState.UserID).
		Msg("consent: authorization approved")

	c.Redirect(http.StatusFound, redirectURL)
}

// RedirectURIForFlow builds a redirect URI with code and state query params.
func RedirectURIForFlow(baseURI, code, state string) (string, error) {
	parsed, err := url.Parse(baseURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}
	params := url.Values{}
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	parsed.RawQuery = params.Encode()
	return parsed.String(), nil
}
