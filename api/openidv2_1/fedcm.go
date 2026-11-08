package openidv2_1

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/reqinfo"
	"github.com/rs/zerolog/log"
)

// FedCM (Federated Credential Management) identity provider endpoints. The
// browser mediates sign-in, so no iframe or third-party cookie is involved.

func (oa *OAuth2API) registerFedCMRoutes(e *gin.Engine) {
	e.GET("/.well-known/web-identity", oa.FedCMWebIdentityHandler)
	e.GET("/fedcm/config.json", oa.FedCMConfigHandler)
	e.GET("/fedcm/accounts", oa.FedCMAccountsHandler)
	e.GET("/fedcm/client_metadata", oa.FedCMClientMetadataHandler)
	e.POST("/fedcm/assertion", oa.FedCMAssertionHandler)
}

// FedCMWebIdentityHandler serves /.well-known/web-identity.
//
// FedCM requires this file on the registrable domain (eTLD+1) of the IdP. When
// the IdP is served from a subdomain (for example sso.example.com), the same
// JSON must also be published at https://example.com/.well-known/web-identity.
// accounts_endpoint and login_url are required when the FedCM config file
// exposes client_metadata_endpoint.
func (oa *OAuth2API) FedCMWebIdentityHandler(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=300")
	c.JSON(http.StatusOK, gin.H{
		"provider_urls":     []string{oa.config.Issuer + "/fedcm/config.json"},
		"accounts_endpoint": oa.config.Issuer + "/fedcm/accounts",
		"login_url":         oa.config.Issuer + "/login?fedcm=1",
	})
}

// FedCMConfigHandler serves the IdP configuration file.
func (oa *OAuth2API) FedCMConfigHandler(c *gin.Context) {
	base := oa.config.Issuer
	branding := gin.H{}
	if oa.brandName != "" {
		branding["name"] = oa.brandName
	}
	c.Header("Cache-Control", "public, max-age=300")
	c.JSON(http.StatusOK, gin.H{
		"accounts_endpoint":        base + "/fedcm/accounts",
		"client_metadata_endpoint": base + "/fedcm/client_metadata",
		"id_assertion_endpoint":    base + "/fedcm/assertion",
		"login_url":                base + "/login?fedcm=1",
		// Active mode can offer "use another account" in the FedCM dialog.
		// Shadow SSO supports multiple accounts and the account chooser.
		"supports_use_other_account": true,
		"branding":                   branding,
	})
}

// fedcmRequestOK enforces the browser-only Sec-Fetch-Dest header, which
// prevents regular pages from calling these credentialed endpoints.
func fedcmRequestOK(c *gin.Context) bool {
	if c.GetHeader("Sec-Fetch-Dest") != "webidentity" {
		c.AbortWithStatusJSON(http.StatusBadRequest, domain.NewInvalidRequest("FedCM requests must carry Sec-Fetch-Dest: webidentity"))
		return false
	}
	c.Header("Cache-Control", "no-store")
	return true
}

// FedCMAccountsHandler lists the account of the current OP session.
func (oa *OAuth2API) FedCMAccountsHandler(c *gin.Context) {
	if !fedcmRequestOK(c) {
		return
	}
	userID, _, ok := oa.currentOPUser(c)
	if !ok {
		// FedCM expects 401 when the user is not signed in to the IdP.
		c.JSON(http.StatusUnauthorized, gin.H{"accounts": []any{}})
		return
	}
	info := oa.silentUserInfo(c, userID)
	account := gin.H{"id": info.ID, "name": info.Name, "email": info.Email}
	if info.Name == "" {
		account["name"] = info.Email
	}
	c.JSON(http.StatusOK, gin.H{"accounts": []any{account}})
}

// FedCMClientMetadataHandler returns the RP's privacy policy and terms links.
func (oa *OAuth2API) FedCMClientMetadataHandler(c *gin.Context) {
	if !fedcmRequestOK(c) {
		return
	}
	client, err := oa.clientService.GetClient(c.Request.Context(), c.Query("client_id"))
	if err != nil || client == nil {
		c.JSON(http.StatusOK, gin.H{})
		return
	}
	meta := gin.H{}
	if client.PolicyURI != "" {
		meta["privacy_policy_url"] = client.PolicyURI
	}
	if client.TermsURI != "" {
		meta["terms_of_service_url"] = client.TermsURI
	}
	c.JSON(http.StatusOK, meta)
}

// clientAllowsOrigin reports whether origin matches a registered redirect URI.
func clientAllowsOrigin(client *domain.Client, origin string) bool {
	for _, u := range client.RedirectURIs {
		if o, ok := redirectOrigin(u); ok && o == origin {
			return true
		}
	}
	return false
}

// fedcmNonce extracts the nonce from a FedCM assertion request. Chrome 145+
// passes it inside the percent-encoded `params` JSON object; older browsers
// send a top-level `nonce` form field.
func fedcmNonce(c *gin.Context) string {
	if nonce := c.PostForm("nonce"); nonce != "" {
		return nonce
	}
	raw := c.PostForm("params")
	if raw == "" {
		raw = c.Query("params")
	}
	if raw != "" {
		var params struct {
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal([]byte(raw), &params); err == nil && params.Nonce != "" {
			return params.Nonce
		}
	}
	return c.Query("nonce")
}

// FedCMAssertionHandler issues an ID token for the signed-in account. The
// request Origin must belong to the client, and the token is bound to the
// client's nonce.
func (oa *OAuth2API) FedCMAssertionHandler(c *gin.Context) {
	if !fedcmRequestOK(c) {
		return
	}
	ctx := reqinfo.WithContext(c.Request.Context(), reqinfo.FromHTTP(c.Request))

	origin := strings.ToLower(c.GetHeader("Origin"))
	clientID := c.PostForm("client_id")
	client, err := oa.clientService.GetClient(ctx, clientID)
	if err != nil || client == nil || origin == "" || !clientAllowsOrigin(client, origin) {
		c.AbortWithStatusJSON(http.StatusForbidden, domain.NewInvalidClient("origin is not allowed for this client"))
		return
	}
	// Credentialed CORS is only granted to the verified client origin.
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Credentials", "true")
	c.Header("Vary", "Origin")

	userID, authenticatedAt, ok := oa.currentOPUser(c)
	if !ok || c.PostForm("account_id") != userID {
		c.AbortWithStatusJSON(http.StatusUnauthorized, domain.NewInvalidRequest("no matching signed-in account"))
		return
	}

	scope := "openid"
	for _, s := range []string{"email", "profile"} {
		for _, allowed := range client.AllowedScopes {
			if allowed == s {
				scope += " " + s
			}
		}
	}
	token, err := oa.tokenService.GenerateIDToken(ctx, userID, clientID, fedcmNonce(c), "", authenticatedAt, scope)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Msg("FedCM: failed to issue ID token")
		c.AbortWithStatusJSON(http.StatusInternalServerError, domain.NewServerError("failed to issue token"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}
