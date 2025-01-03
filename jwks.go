package sso

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func (api *OAuth2API) JWKSHandler(c echo.Context) error {
	jwks := api.service.GetJWKS()
	return c.JSON(http.StatusOK, jwks)
}
