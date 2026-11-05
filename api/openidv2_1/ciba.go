package openidv2_1

import (
	goerrors "errors"
	"net/http"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

func cibaError(c *gin.Context, status int, code, desc string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(status, gin.H{"error": code, "error_description": desc})
}

// BackchannelAuthenticationHandler implements the CIBA authentication
// endpoint (POST /oauth2/ciba, poll mode). Only confidential clients that are
// allowed the CIBA grant may use it.
func (oa *OAuth2API) BackchannelAuthenticationHandler(c *gin.Context) {
	applyBasicClientAuth(c)
	ctx := c.Request.Context()
	clientID := c.PostForm("client_id")
	if clientID == "" {
		cibaError(c, http.StatusBadRequest, domain.InvalidRequest, "client_id is required")
		return
	}
	params := map[string][]string{
		"client_secret":         {c.PostForm("client_secret")},
		"client_assertion":      {c.PostForm("client_assertion")},
		"client_assertion_type": {c.PostForm("client_assertion_type")},
	}
	cli, err := oa.authenticateClient(ctx, clientID, nil, params)
	if err != nil || cli == nil || !cli.IsConfidential {
		cibaError(c, http.StatusUnauthorized, domain.InvalidClient, "client authentication failed")
		return
	}
	if err := oa.clientService.ValidateGrantType(ctx, clientID, domain.GrantTypeCIBA); err != nil {
		cibaError(c, http.StatusBadRequest, domain.UnauthorizedClient, "client is not allowed to use CIBA")
		return
	}
	if mode := c.PostForm("client_notification_token"); mode != "" {
		cibaError(c, http.StatusBadRequest, domain.InvalidRequest, "only poll mode is supported")
		return
	}

	resp, err := oa.ciba.InitiateBackchannelAuth(ctx, cli, c.PostForm("login_hint"), c.PostForm("scope"), c.PostForm("binding_message"))
	if err != nil {
		var oerr *domain.OAuth2Error
		if goerrors.As(err, &oerr) {
			cibaError(c, http.StatusBadRequest, oerr.Code, oerr.Description)
			return
		}
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Msg("CIBA: initiation failed")
		cibaError(c, http.StatusInternalServerError, domain.ServerError, "failed to start authentication")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, resp)
}

// handleCIBAGrant polls a CIBA authentication request at the token endpoint.
func (oa *OAuth2API) handleCIBAGrant(c *gin.Context, cli *domain.Client) (*sssoapi.TokenResponse, error) {
	if oa.ciba == nil {
		return nil, domain.NewUnsupportedGrantType()
	}
	authReqID := c.PostForm("auth_req_id")
	if authReqID == "" {
		return nil, domain.NewInvalidRequest("auth_req_id is required")
	}
	tok, err := oa.ciba.IssueTokenForBackchannelAuth(c.Request.Context(), authReqID, cli.ID)
	if err == nil {
		return tok, nil
	}
	switch {
	case goerrors.Is(err, domain.ErrAuthorizationPending):
		cibaError(c, http.StatusBadRequest, "authorization_pending", "the user has not yet approved")
	case goerrors.Is(err, domain.ErrSlowDown):
		cibaError(c, http.StatusBadRequest, "slow_down", "polling too fast")
	case goerrors.Is(err, domain.ErrDeviceFlowTokenExpired):
		cibaError(c, http.StatusBadRequest, "expired_token", "auth_req_id expired")
	case goerrors.Is(err, domain.ErrDeviceFlowAccessDenied):
		cibaError(c, http.StatusBadRequest, "access_denied", "the user denied the request")
	default:
		return nil, err
	}
	return nil, nil
}
