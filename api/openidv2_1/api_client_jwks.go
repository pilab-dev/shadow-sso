package openidv2_1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

func (oa *OAuth2API) ClientJWKSHandler(c *gin.Context) {
	clientID := c.Param("clientId")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id required"})
		return
	}

	client, err := oa.clientService.GetClient(c.Request.Context(), clientID)
	if err != nil {
		if err == domain.ErrClientNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
			return
		}
		log.Error().Err(err).Str("clientId", clientID).Msg("Failed to get client")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get client"})
		return
	}

	if client.JWKS == nil || len(client.JWKS.Keys) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "client has no JWKS"})
		return
	}

	publicKeys := make([]domain.JSONWebKey, 0, len(client.JWKS.Keys))
	for _, key := range client.JWKS.Keys {
		publicKeys = append(publicKeys, domain.JSONWebKey{
			Kid: key.Kid,
			Kty: key.Kty,
			Alg: key.Alg,
			Use: key.Use,
			N:   key.N,
			E:   key.E,
		})
	}

	c.JSON(http.StatusOK, domain.JWKS{Keys: publicKeys})
}