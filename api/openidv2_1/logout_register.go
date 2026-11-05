package openidv2_1

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/oidclogout"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	"github.com/rs/zerolog/log"
)

// LogoutHandler implements the OIDC RP-initiated logout endpoint
// (GET /oauth2/logout). It verifies the id_token_hint, correlates the session
// via the sid (preferred) or jti claim, revokes it, clears the OP session
// cookie, dispatches OIDC back-channel logout tokens, and redirects the user
// agent back to an allow-listed post_logout_redirect_uri.
func (oa *OAuth2API) LogoutHandler(c *gin.Context) {
	ctx := c.Request.Context()

	idTokenHint := c.Query("id_token_hint")
	if idTokenHint == "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("id_token_hint is required"))
		return
	}
	if oa.tokenSigner == nil {
		log.Error().Msg("LogoutHandler: token signer is not configured")
		c.JSON(http.StatusInternalServerError, domain.NewServerError("server is not configured for logout"))
		return
	}

	claims, err := oa.tokenSigner.VerifyToken(idTokenHint)
	if err != nil {
		log.Warn().Err(err).Msg("LogoutHandler: failed to verify id_token_hint")
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("id_token_hint is invalid"))
		return
	}

	if oa.config.Issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != oa.config.Issuer {
			c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("id_token_hint issuer does not match"))
			return
		}
	}

	var clientID string
	switch aud := claims["aud"].(type) {
	case string:
		clientID = aud
	case []any:
		if len(aud) > 0 {
			clientID, _ = aud[0].(string)
		}
	}
	if clientID == "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("id_token_hint is missing the aud claim"))
		return
	}

	client, err := oa.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		log.Warn().Err(err).Str("clientID", clientID).Msg("LogoutHandler: failed to load client")
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("unknown client"))
		return
	}

	postLogoutURI := c.Query("post_logout_redirect_uri")
	if postLogoutURI != "" && !containsString(client.PostLogoutURIs, postLogoutURI) {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("post_logout_redirect_uri is not allow-listed"))
		return
	}

	sid, _ := claims["sid"].(string)
	jti, _ := claims["jti"].(string)
	lookupKey := sid
	if lookupKey == "" {
		lookupKey = jti
	}

	if lookupKey != "" && oa.sessionRepo != nil {
		if session, sErr := oa.sessionRepo.GetSessionByTokenID(ctx, lookupKey); sErr == nil && session != nil && !session.IsRevoked {
			session.IsRevoked = true
			if uErr := oa.sessionRepo.UpdateSession(ctx, session); uErr != nil {
				log.Warn().Err(uErr).Str("sessionID", session.ID).Msg("LogoutHandler: failed to revoke session")
			}
		}
	}

	isSecure := c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")

	// Delete every server-side OP session recorded in the login-UI account
	// history, not only the currently active one.
	if oa.userSessionStore != nil && oa.cookieSigningSecret != "" {
		if ssoCookie, cookieErr := c.Cookie(ssosession.CookieName); cookieErr == nil && ssoCookie != "" {
			if session, verifyErr := ssosession.VerifyAndDecode(ssoCookie, oa.cookieSigningSecret); verifyErr == nil && session != nil {
				for _, account := range session.Accounts {
					if account.OPSessionID == "" {
						continue
					}
					if delErr := oa.userSessionStore.DeleteUserSession(ctx, account.OPSessionID); delErr != nil && !errors.Is(delErr, domain.ErrSessionNotFound) {
						log.Warn().Err(delErr).Str("sessionID", account.OPSessionID).Msg("LogoutHandler: failed to delete account OP session")
					}
				}
			}
		}
	}

	// Delete the server-side OP session referenced by the active cookie so it
	// cannot be replayed after logout, then expire both the OP and login-UI
	// cookies.
	if opSessionID, cookieErr := c.Cookie(SessionCookieName); cookieErr == nil && opSessionID != "" && oa.userSessionStore != nil {
		if delErr := oa.userSessionStore.DeleteUserSession(ctx, opSessionID); delErr != nil && !errors.Is(delErr, domain.ErrSessionNotFound) {
			log.Warn().Err(delErr).Str("sessionID", opSessionID).Msg("LogoutHandler: failed to delete OP user session")
		}
	}
	oa.clearUserSessionCookie(c)
	ssosession.ClearCookie(c.Writer, isSecure)

	if client.BackchannelLogoutURI != "" && oa.backchannelNotifier != nil {
		sub, _ := claims["sub"].(string)
		logoutToken, tErr := oidclogout.BuildLogoutToken(oidclogout.LogoutTokenParams{
			Issuer:   oa.config.Issuer,
			Audience: clientID,
			SID:      sid,
			Subject:  sub,
		}, func(claims jwt.Claims) (string, error) {
			return oa.tokenSigner.Sign(claims, "")
		})
		if tErr != nil {
			log.Warn().Err(tErr).Str("clientID", clientID).Msg("LogoutHandler: failed to build logout token")
		} else {
			// Detach from the request context: it is cancelled as soon as this
			// handler returns (which happens right after this call), which
			// would otherwise abort the fire-and-forget HTTP dispatch below.
			notifyCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			go func() {
				defer cancel()
				if nErr := oa.backchannelNotifier.NotifyLogout(notifyCtx, client, logoutToken); nErr != nil {
					log.Warn().Err(nErr).Str("clientID", clientID).Msg("LogoutHandler: backchannel logout notification failed")
				}
			}()
		}
	}

	frontURL, hasFront := frontchannelLogoutURL(client, oa.config.Issuer, sid)

	if postLogoutURI != "" {
		redirectURI := postLogoutURI
		if state := c.Query("state"); state != "" {
			if u, pErr := url.Parse(postLogoutURI); pErr == nil {
				q := u.Query()
				q.Set("state", state)
				u.RawQuery = q.Encode()
				redirectURI = u.String()
			}
		}
		if hasFront {
			renderFrontchannelLogout(c, frontURL, redirectURI)
			return
		}
		c.Redirect(http.StatusFound, redirectURI)
		return
	}

	if hasFront {
		renderFrontchannelLogout(c, frontURL, "")
		return
	}
	c.Status(http.StatusOK)
}

type registerClientRequest struct {
	ClientName           string   `json:"client_name"`
	ClientType           string   `json:"client_type"`
	RedirectURIs         []string `json:"redirect_uris"`
	PostLogoutURIs       []string `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI string   `json:"backchannel_logout_uri"`
	TokenEndpointAuth    string   `json:"token_endpoint_auth_method"`
}

// RegisterHandler implements RFC 7591 dynamic client registration
// (POST /oauth2/register). It authenticates the caller via a shared bootstrap
// token and persists a new OAuth2 client through the client service, returning
// the generated client_id and plaintext client_secret.
func (oa *OAuth2API) RegisterHandler(c *gin.Context) {
	ctx := c.Request.Context()

	if !oa.bootstrapAuthorized(c.GetHeader("Authorization")) {
		c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("invalid or missing initial access token"))
		return
	}

	var req registerClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("invalid client metadata"))
		return
	}

	if len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("redirect_uris is required"))
		return
	}
	for _, uri := range append(append([]string{}, req.RedirectURIs...), req.PostLogoutURIs...) {
		if !validRegistrationURI(uri) {
			c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("invalid redirect uri: "+uri))
			return
		}
	}

	clientType := domain.ClientTypeConfidential
	if req.ClientType == "public" {
		clientType = domain.ClientTypePublic
	}

	newClient := &domain.Client{
		ID:                   uuid.NewString(),
		Type:                 clientType,
		IsConfidential:       clientType == domain.ClientTypeConfidential,
		Name:                 req.ClientName,
		RedirectURIs:         req.RedirectURIs,
		PostLogoutURIs:       req.PostLogoutURIs,
		BackchannelLogoutURI: req.BackchannelLogoutURI,
		TokenEndpointAuth:    req.TokenEndpointAuth,
		IsActive:             true,
		CreatedAt:            time.Now().UTC(),
		UpdatedAt:            time.Now().UTC(),
	}

	if clientType == domain.ClientTypeConfidential {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			c.JSON(http.StatusInternalServerError, domain.NewServerError("failed to register client"))
			return
		}
		newClient.Secret = base64.RawURLEncoding.EncodeToString(secret)
		if newClient.TokenEndpointAuth == "" {
			newClient.TokenEndpointAuth = "client_secret_basic"
		}
		newClient.AllowedGrantTypes = []string{"authorization_code", "client_credentials", "refresh_token"}
	} else {
		newClient.RequirePKCE = true
		if newClient.TokenEndpointAuth == "" {
			newClient.TokenEndpointAuth = "none"
		}
		newClient.AllowedGrantTypes = []string{"authorization_code", "refresh_token"}
	}

	created, err := oa.clientService.CreateClient(ctx, newClient)
	if err != nil {
		log.Error().Err(err).Str("clientID", newClient.ID).Msg("RegisterHandler: failed to create client")
		c.JSON(http.StatusInternalServerError, domain.NewServerError("failed to register client"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"client_id":     created.ID,
		"client_secret": created.Secret,
		"client_name":   created.Name,
	})
}

func (oa *OAuth2API) bootstrapAuthorized(authHeader string) bool {
	if oa.bootstrapToken == "" {
		return false
	}
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return false
	}
	token := strings.TrimPrefix(authHeader, bearerPrefix)
	return subtle.ConstantTimeCompare([]byte(token), []byte(oa.bootstrapToken)) == 1
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

// validRegistrationURI accepts absolute URIs without a fragment, rejecting
// wildcards and dangerous schemes (RFC 6749 §3.1.2).
func validRegistrationURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Fragment != "" || strings.Contains(raw, "*") {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "javascript", "data", "vbscript", "file":
		return false
	case "http", "https":
		return u.Host != ""
	}
	return true
}
