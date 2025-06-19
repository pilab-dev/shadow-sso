package sssogin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log" // Added for logging
)

func (oa *OAuth2API) JWKSHandler(c *gin.Context) {
	jwks, err := oa.jwksService.GetPublicJWKS(c.Request.Context())
	if err != nil {
		log.Error().Err(err).Msg("Failed to get JWKS")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve JWKS"})
		return
	}
	c.JSON(http.StatusOK, jwks)
}
