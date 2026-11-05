package openidv2_1

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

const (
	parTTL     = 60 * time.Second
	parMaxBody = 64 << 10
)

// PushedAuthorizationRequestHandler implements RFC 9126 (PAR).
func (oa *OAuth2API) PushedAuthorizationRequestHandler(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, parMaxBody)
	applyBasicClientAuth(c)
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("invalid or oversized request body"))
		return
	}

	clientID := c.Request.PostForm.Get("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("client_id is required"))
		return
	}
	if c.Request.PostForm.Get("request_uri") != "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("request_uri must not be used in a pushed request"))
		return
	}

	ctx := c.Request.Context()
	cli, err := oa.clientService.GetClient(ctx, clientID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("Invalid client credentials"))
		return
	}

	form := c.Request.PostForm
	authParams := map[string][]string{
		"client_secret":         {form.Get("client_secret")},
		"client_assertion":      {form.Get("client_assertion")},
		"client_assertion_type": {form.Get("client_assertion_type")},
	}
	if cli.IsConfidential && form.Get("client_secret") == "" && form.Get("client_assertion") == "" {
		c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("Client authentication required"))
		return
	}
	if _, err := oa.authenticateClient(ctx, clientID, cli, authParams); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("PAR client authentication failed")
		c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("Invalid client credentials"))
		return
	}

	params := make(map[string]string)
	for k, v := range form {
		switch k {
		case "client_secret", "client_assertion", "client_assertion_type":
			continue
		}
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	uri := "urn:ietf:params:oauth:request_uri:" + hex.EncodeToString(buf)
	if err := oa.parStore.Put(ctx, uri, clientID, params, parTTL); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("PAR: failed to store pushed request")
		c.JSON(http.StatusServiceUnavailable, domain.NewServerError("could not store pushed request"))
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"request_uri": uri,
		"expires_in":  int(parTTL.Seconds()),
	})
}
