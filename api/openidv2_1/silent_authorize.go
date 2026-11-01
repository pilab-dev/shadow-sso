package openidv2_1

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

const silentAuthorizeMessageType = "sso-silent-result"

// silentAuthorizeResult is the postMessage payload delivered to the parent
// application by the silent authorization iframe.
type silentAuthorizeResult struct {
	Type             string `json:"type"`
	State            string `json:"state,omitempty"`
	Code             string `json:"code,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// SilentAuthorizeHandler implements iframe-based silent login. It performs the
// same client/redirect/PKCE validation as /oauth2/authorize, then posts either
// an authorization code or an OAuth error to the parent window.
//
// The parent origin is derived from the client's registered redirect_uri, which
// must be an absolute http(s) URL on the application's origin. The response is
// frameable only by that origin.
func (oa *OAuth2API) SilentAuthorizeHandler(c *gin.Context) {
	ctx := c.Request.Context()

	if c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
		oa.handleSilentPreflight(c)
		return
	}

	data := &authorizeRequestData{
		clientID:            c.Query("client_id"),
		redirectURI:         c.Query("redirect_uri"),
		responseType:        c.Query("response_type"),
		scopeQuery:          c.Query("scope"),
		state:               c.Query("state"),
		nonce:               c.Query("nonce"),
		prompt:              c.Query("prompt"),
		codeChallenge:       c.Query("code_challenge"),
		codeChallengeMethod: c.Query("code_challenge_method"),
	}

	if data.clientID == "" || data.redirectURI == "" || data.responseType == "" {
		oa.sendJSONError(c, http.StatusBadRequest, domain.NewInvalidRequest("client_id, redirect_uri, and response_type are required"))
		return
	}
	if data.responseType != "code" {
		oa.sendJSONError(c, http.StatusBadRequest, domain.NewInvalidRequest("unsupported response_type, only 'code' is supported"))
		return
	}

	redirectParentOrigin, ok := redirectOrigin(data.redirectURI)
	if !ok {
		oa.sendJSONError(c, http.StatusBadRequest, domain.NewInvalidRequest("redirect_uri must be an absolute http(s) URL"))
		return
	}

	parentOrigin := redirectParentOrigin
	if requestedParentOrigin := c.Query("parent_origin"); requestedParentOrigin != "" {
		normalized, valid := parentOriginFromParam(requestedParentOrigin)
		if !valid {
			oa.sendJSONError(c, http.StatusBadRequest, domain.NewInvalidRequest("parent_origin must be an absolute http(s) origin"))
			return
		}
		parentOrigin = normalized
	}

	if err := oa.validateClientDetails(ctx, data.clientID, data.redirectURI, data.scopeQuery); err != nil {
		if oauthErr, isOAuthErr := err.(*domain.OAuth2Error); isOAuthErr {
			oa.sendJSONError(c, http.StatusBadRequest, oauthErr)
			return
		}
		log.Error().Err(err).Msg("SilentAuthorizeHandler: client validation failed")
		oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("internal validation error"))
		return
	}
	if err := oa.validatePKCE(ctx, data.clientID, data.codeChallenge, data.codeChallengeMethod); err != nil {
		if oauthErr, isOAuthErr := err.(*domain.OAuth2Error); isOAuthErr {
			oa.sendJSONError(c, http.StatusBadRequest, oauthErr)
			return
		}
		log.Error().Err(err).Msg("SilentAuthorizeHandler: PKCE validation failed")
		oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("internal PKCE validation error"))
		return
	}

	// The iframe may load (so it can report a useful error), but a parent
	// origin that differs from the registered redirect URI origin must never
	// receive an authorization code.
	if parentOrigin != redirectParentOrigin {
		oa.renderSilentResult(c, parentOrigin, silentAuthorizeResult{
			Type:             silentAuthorizeMessageType,
			State:            data.state,
			Error:            "origin_not_allowed",
			ErrorDescription: "The parent origin is not allowed to use silent login for this client.",
		})
		return
	}

	userID, authenticatedAt, authenticated := oa.currentOPUser(c)
	if !authenticated {
		oa.renderSilentResult(c, parentOrigin, silentAuthorizeResult{
			Type:             silentAuthorizeMessageType,
			State:            data.state,
			Error:            "login_required",
			ErrorDescription: "User is not authenticated.",
		})
		return
	}

	client, err := oa.clientService.GetClient(ctx, data.clientID)
	if err != nil {
		log.Error().Err(err).Str("clientID", data.clientID).Msg("SilentAuthorizeHandler: failed to load client")
		oa.renderSilentResult(c, parentOrigin, silentAuthorizeResult{
			Type:             silentAuthorizeMessageType,
			State:            data.state,
			Error:            "server_error",
			ErrorDescription: "Failed to load application information.",
		})
		return
	}
	if client.RequireConsent {
		oa.renderSilentResult(c, parentOrigin, silentAuthorizeResult{
			Type:             silentAuthorizeMessageType,
			State:            data.state,
			Error:            "consent_required",
			ErrorDescription: "User consent is required.",
		})
		return
	}

	authCode, err := oa.service.GenerateAuthCode(
		ctx,
		data.clientID,
		userID,
		data.redirectURI,
		data.scopeQuery,
		data.codeChallenge,
		data.codeChallengeMethod,
		data.nonce,
		authenticatedAt,
	)
	if err != nil {
		log.Error().Err(err).Str("clientID", data.clientID).Msg("SilentAuthorizeHandler: failed to generate authorization code")
		oa.renderSilentResult(c, parentOrigin, silentAuthorizeResult{
			Type:             silentAuthorizeMessageType,
			State:            data.state,
			Error:            "server_error",
			ErrorDescription: "Failed to complete authorization.",
		})
		return
	}
	oa.persistCodeChallenge(ctx, authCode, data.codeChallenge)

	oa.renderSilentResult(c, parentOrigin, silentAuthorizeResult{
		Type:  silentAuthorizeMessageType,
		State: data.state,
		Code:  authCode,
	})
}

// currentOPUser reads the server-side OP session cookie and returns the
// authenticated user ID plus the authentication time.
func (oa *OAuth2API) currentOPUser(c *gin.Context) (string, time.Time, bool) {
	cookie, err := c.Cookie(SessionCookieName)
	if err != nil || cookie == "" || oa.userSessionStore == nil {
		return "", time.Time{}, false
	}
	session, err := oa.userSessionStore.GetUserSession(c.Request.Context(), cookie)
	if err != nil || session == nil || session.UserID == "" {
		return "", time.Time{}, false
	}
	authenticatedAt := session.AuthenticatedAt
	if authenticatedAt.IsZero() {
		authenticatedAt = time.Now()
	}
	return session.UserID, authenticatedAt, true
}

// renderSilentResult renders the postMessage bridge page. The CSP allows the
// inline script by nonce and permits framing only by the application origin.
func (oa *OAuth2API) renderSilentResult(c *gin.Context, parentOrigin string, result silentAuthorizeResult) {
	message, err := json.Marshal(result)
	if err != nil {
		oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("failed to encode silent login result"))
		return
	}
	targetOrigin, err := json.Marshal(parentOrigin)
	if err != nil {
		oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("failed to encode silent login target"))
		return
	}
	nonce, err := generateCSRFToken()
	if err != nil {
		oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("failed to create silent login page"))
		return
	}

	c.Header("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; script-src 'nonce-%s'; frame-ancestors %s; base-uri 'none'",
		nonce, parentOrigin,
	))
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Writer.Header().Del("X-Frame-Options")

	c.HTML(http.StatusOK, "silent_authorize.html", gin.H{
		"Nonce":        nonce,
		"Message":      template.JS(string(message)),      //nolint:gosec // message is json.Marshal output
		"TargetOrigin": template.JS(string(targetOrigin)), //nolint:gosec // origin is json.Marshal output
	})
}

// redirectOrigin derives the parent window origin from a validated redirect
// URI. Only absolute http(s) URLs with a safe host are accepted.
func redirectOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if !validOriginHost(parsed.Host) {
		return "", false
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), true
}

// parentOriginFromParam accepts an origin-only URL (no path, query, fragment
// or userinfo) supplied by the iframe host.
func parentOriginFromParam(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", false
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if !validOriginHost(parsed.Host) {
		return "", false
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), true
}

// validOriginHost rejects characters that could break out of the CSP
// frame-ancestors source expression.
func validOriginHost(host string) bool {
	if host == "" {
		return false
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '-', r == ':', r == '[', r == ']':
		default:
			return false
		}
	}
	return true
}

// handleSilentPreflight answers HEAD and OPTIONS requests for the silent
// authorize endpoint. It exposes the frame policy headers to the SDK so the
// library can detect CSP/X-Frame-Options blocking before inserting an iframe.
func (oa *OAuth2API) handleSilentPreflight(c *gin.Context) {
	claimedParent, claimedOK := parentOriginFromParam(c.Query("parent_origin"))
	requestOrigin := c.GetHeader("Origin")
	allowOrigin := ""
	if claimedOK && requestOrigin != "" && strings.EqualFold(requestOrigin, claimedParent) {
		allowOrigin = requestOrigin
	}
	setSilentPreflightCORS(c, allowOrigin)

	if !claimedOK {
		oa.sendJSONError(c, http.StatusBadRequest, domain.NewInvalidRequest("parent_origin must be an absolute http(s) origin"))
		return
	}

	// Set the frame policy before client validation so validation errors are
	// not misreported by the SDK as frame-blocked responses.
	applySilentFrameHeaders(c, claimedParent)

	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	scope := c.Query("scope")
	if scope == "" {
		scope = "openid"
	}
	if clientID == "" || redirectURI == "" {
		oa.sendJSONError(c, http.StatusBadRequest, domain.NewInvalidRequest("client_id and redirect_uri are required"))
		return
	}
	if _, ok := redirectOrigin(redirectURI); !ok {
		oa.sendJSONError(c, http.StatusBadRequest, domain.NewInvalidRequest("redirect_uri must be an absolute http(s) URL"))
		return
	}
	if err := oa.validateClientDetails(c.Request.Context(), clientID, redirectURI, scope); err != nil {
		if oauthErr, isOAuthErr := err.(*domain.OAuth2Error); isOAuthErr {
			oa.sendJSONError(c, http.StatusBadRequest, oauthErr)
			return
		}
		log.Error().Err(err).Msg("SilentAuthorizeHandler: preflight client validation failed")
		oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("internal validation error"))
		return
	}

	if c.Request.Method == http.MethodOptions {
		c.Status(http.StatusNoContent)
		return
	}
	c.Status(http.StatusOK)
}

func setSilentPreflightCORS(c *gin.Context, allowOrigin string) {
	if allowOrigin != "" {
		c.Header("Access-Control-Allow-Origin", allowOrigin)
	}
	c.Header("Vary", "Origin")
	c.Header("Access-Control-Allow-Methods", "HEAD, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type")
	c.Header("Access-Control-Expose-Headers", "Content-Security-Policy, X-Frame-Options")
	c.Header("Access-Control-Max-Age", "600")
}

func applySilentFrameHeaders(c *gin.Context, parentOrigin string) {
	c.Header("Content-Security-Policy", "frame-ancestors "+parentOrigin)
	c.Writer.Header().Del("X-Frame-Options")
	c.Header("Cache-Control", "no-store")
}
