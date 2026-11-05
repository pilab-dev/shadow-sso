package openidv2_1

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

// newRegistrationToken returns an RFC 7592 registration access token and the
// SHA-256 digest that is persisted in place of the token.
func newRegistrationToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashRegistrationToken(token), nil
}

func hashRegistrationToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func validateRegistrationMetadata(req *registerClientRequest) string {
	uris := append(append([]string{}, req.RedirectURIs...), req.PostLogoutURIs...)
	for _, uri := range uris {
		if !validRegistrationURI(uri) {
			return "invalid redirect uri: " + uri
		}
	}
	for _, uri := range []string{req.BackchannelLogoutURI, req.FrontchannelLogoutURI} {
		if uri != "" && !validRegistrationURI(uri) {
			return "invalid logout uri: " + uri
		}
	}
	return ""
}

func (oa *OAuth2API) registrationClientURI(clientID string) string {
	return strings.TrimRight(oa.config.Issuer, "/") + "/oauth2/register/" + clientID
}

// registrationResponse renders the RFC 7591/7592 client information response
// (without secrets or the registration access token).
func (oa *OAuth2API) registrationResponse(cl *domain.Client) gin.H {
	resp := gin.H{
		"client_id":                  cl.ID,
		"client_name":                cl.Name,
		"redirect_uris":              cl.RedirectURIs,
		"post_logout_redirect_uris":  cl.PostLogoutURIs,
		"grant_types":                cl.AllowedGrantTypes,
		"token_endpoint_auth_method": cl.TokenEndpointAuth,
		"registration_client_uri":    oa.registrationClientURI(cl.ID),
		"client_id_issued_at":        cl.CreatedAt.Unix(),
	}
	if cl.BackchannelLogoutURI != "" {
		resp["backchannel_logout_uri"] = cl.BackchannelLogoutURI
	}
	if cl.FrontchannelLogoutURI != "" {
		resp["frontchannel_logout_uri"] = cl.FrontchannelLogoutURI
		resp["frontchannel_logout_session_required"] = cl.FrontchannelLogoutSessionRequired
	}
	return resp
}

// authorizeRegistrationClient loads the client addressed by :client_id and
// checks the bearer registration access token. Every failure is a bare 401 so
// that client existence is not disclosed.
func (oa *OAuth2API) authorizeRegistrationClient(c *gin.Context) (*domain.Client, bool) {
	deny := func() (*domain.Client, bool) {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.Status(http.StatusUnauthorized)
		return nil, false
	}
	authz := c.GetHeader("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return deny()
	}
	cl, err := oa.clientRepo.GetClient(c.Request.Context(), c.Param("client_id"))
	if err != nil || cl == nil || cl.RegistrationTokenHash == "" {
		return deny()
	}
	got := hashRegistrationToken(strings.TrimPrefix(authz, "Bearer "))
	if subtle.ConstantTimeCompare([]byte(got), []byte(cl.RegistrationTokenHash)) != 1 {
		return deny()
	}
	return cl, true
}

// RegistrationReadHandler implements GET /oauth2/register/:client_id (RFC 7592 §2.1).
func (oa *OAuth2API) RegistrationReadHandler(c *gin.Context) {
	cl, ok := oa.authorizeRegistrationClient(c)
	if !ok {
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, oa.registrationResponse(cl))
}

// RegistrationUpdateHandler implements PUT /oauth2/register/:client_id (RFC 7592 §2.2).
// Mutable metadata is replaced; secrets and server-managed fields are untouched.
func (oa *OAuth2API) RegistrationUpdateHandler(c *gin.Context) {
	cl, ok := oa.authorizeRegistrationClient(c)
	if !ok {
		return
	}
	var req registerClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("invalid client metadata"))
		return
	}
	if req.ClientID != "" && req.ClientID != cl.ID {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("client_id does not match"))
		return
	}
	if len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("redirect_uris is required"))
		return
	}
	if msg := validateRegistrationMetadata(&req); msg != "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest(msg))
		return
	}

	cl.Name = req.ClientName
	cl.RedirectURIs = req.RedirectURIs
	cl.PostLogoutURIs = req.PostLogoutURIs
	cl.BackchannelLogoutURI = req.BackchannelLogoutURI
	cl.FrontchannelLogoutURI = req.FrontchannelLogoutURI
	cl.FrontchannelLogoutSessionRequired = req.FrontchannelLogoutSessionRequired
	cl.UpdatedAt = time.Now().UTC()

	if err := oa.clientRepo.UpdateClient(c.Request.Context(), cl); err != nil {
		log.Error().Err(err).Str("clientID", cl.ID).Msg("RegistrationUpdateHandler: update failed")
		c.JSON(http.StatusInternalServerError, domain.NewServerError("failed to update client"))
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, oa.registrationResponse(cl))
}

// RegistrationDeleteHandler implements DELETE /oauth2/register/:client_id (RFC 7592 §2.3).
func (oa *OAuth2API) RegistrationDeleteHandler(c *gin.Context) {
	cl, ok := oa.authorizeRegistrationClient(c)
	if !ok {
		return
	}
	if err := oa.clientRepo.DeleteClient(c.Request.Context(), cl.ID); err != nil {
		log.Error().Err(err).Str("clientID", cl.ID).Msg("RegistrationDeleteHandler: delete failed")
		c.JSON(http.StatusInternalServerError, domain.NewServerError("failed to delete client"))
		return
	}
	c.Status(http.StatusNoContent)
}
