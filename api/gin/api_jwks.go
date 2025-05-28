//go:build gin

package sssogin

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (oa *OAuth2API) JWKSHandler(c *gin.Context) {
	jwks := oa.service.GetJWKS()

	c.JSON(http.StatusOK, jwks)
}
