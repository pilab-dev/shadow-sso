//go:build echo

package sssoecho

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func (oa *OAuth2API) JWKSHandler(c echo.Context) error {
	jwks := oa.service.GetJWKS()
	return c.JSON(http.StatusOK, jwks)
}
