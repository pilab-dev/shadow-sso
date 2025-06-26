package sssogin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/internal/federation"

	ssoerrors "github.com/pilab-dev/shadow-sso/errors"
	"github.com/rs/zerolog/log"
)

// LDAPLoginRequest defines the expected JSON body for the LDAP login endpoint.
type LDAPLoginRequest struct {
	ClientID     string `json:"client_id" binding:"required"`
	Username     string `json:"username" binding:"required"`
	Password     string `json:"password" binding:"required"`
	ProviderName string `json:"provider_name" binding:"required"` // The name of the configured LDAP IdP
}

// LDAPLoginHandler handles user login via an LDAP provider.
func (oa *OAuth2API) LDAPLoginHandler(c *gin.Context) {
	var req LDAPLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warn().Err(err).Msg("LDAPLoginHandler: Invalid request payload")
		c.JSON(http.StatusBadRequest, ssoerrors.NewInvalidRequest("Invalid request payload: "+err.Error()))
		return
	}

	ctx := c.Request.Context()

	// Authenticate user via federation service
	externalUser, err := oa.federationService.AuthenticateDirect(ctx, req.ProviderName, req.Username, req.Password)
	if err != nil {
		log.Warn().Err(err).Str("provider", req.ProviderName).Str("username", req.Username).Msg("LDAP authentication failed")
		// Check for specific federation errors to return appropriate responses
		if _, ok := err.(*ssoerrors.OAuth2Error); ok { // Assuming AuthenticateDirect might return OAuth2Error for consistency
			oa.sendJSONError(c, http.StatusUnauthorized, err.(*ssoerrors.OAuth2Error))
		} else if err == federation.ErrInvalidCredentials {
			oa.sendJSONError(c, http.StatusUnauthorized, ssoerrors.NewInvalidGrant("Invalid username or password."))
		} else if err == federation.ErrUserNotFound {
			oa.sendJSONError(c, http.StatusUnauthorized, ssoerrors.NewInvalidGrant("Invalid username or password.")) // Generic message
		} else if err == federation.ErrProviderMisconfigured {
			log.Error().Err(err).Str("provider", req.ProviderName).Msg("LDAP provider misconfigured")
			oa.sendJSONError(c, http.StatusInternalServerError, ssoerrors.NewServerError("Authentication provider error."))
		} else {
			oa.sendJSONError(c, http.StatusUnauthorized, ssoerrors.NewInvalidGrant("Authentication failed."))
		}
		return
	}

	// Fetch client configuration for attribute mapping
	oauthClient, err := oa.clientService.GetClient(ctx, req.ClientID)
	if err != nil {
		log.Error().Err(err).Str("client_id", req.ClientID).Msg("LDAPLoginHandler: Failed to get client details")
		oa.sendJSONError(c, http.StatusBadRequest, ssoerrors.NewInvalidClient("Invalid client_id."))
		return
	}

	// --- Attribute Mapping ---
	// This is a critical part. We need a robust way to map attributes from
	// externalUser.RawData based on oauthClient.ClientLDAPAttribute... fields
	// and oauthClient.ClientLDAPCustomClaimsMapping.

	claims := make(map[string]interface{})

	// Standard claims based on client's LDAP attribute configuration
	if oauthClient.ClientLDAPAttributeEmail != "" && externalUser.RawData[oauthClient.ClientLDAPAttributeEmail] != nil {
		claims["email"] = externalUser.RawData[oauthClient.ClientLDAPAttributeEmail]
		if val, ok := externalUser.RawData[oauthClient.ClientLDAPAttributeEmail].(string); ok {
			claims["email_verified"] = true // Assume verified if email is present from LDAP
			log.Debug().Str("email_claim", val).Msg("Mapped email claim from LDAP")
		}
	} else if externalUser.Email != "" { // Fallback to default email from ExternalUserInfo if client specific not set/found
		claims["email"] = externalUser.Email
		claims["email_verified"] = true
		log.Debug().Str("email_claim", externalUser.Email).Msg("Mapped email claim from LDAP (default)")
	}

	if oauthClient.ClientLDAPAttributeFirstName != "" && externalUser.RawData[oauthClient.ClientLDAPAttributeFirstName] != nil {
		claims["given_name"] = externalUser.RawData[oauthClient.ClientLDAPAttributeFirstName]
	} else if externalUser.FirstName != "" {
		claims["given_name"] = externalUser.FirstName
	}

	if oauthClient.ClientLDAPAttributeLastName != "" && externalUser.RawData[oauthClient.ClientLDAPAttributeLastName] != nil {
		claims["family_name"] = externalUser.RawData[oauthClient.ClientLDAPAttributeLastName]
	} else if externalUser.LastName != "" {
		claims["family_name"] = externalUser.LastName
	}

	// Username claim (e.g., 'sub' or 'preferred_username')
	// The 'sub' claim MUST be the unique user ID from our system after user provisioning/linking.
	// For now, we'll use externalUser.ProviderUserID (LDAP DN) as a placeholder for 'sub'
	// and externalUser.Username for 'preferred_username'.
	// This needs to be integrated with user provisioning later.
	claims["sub"] = externalUser.ProviderUserID // This will be replaced by internal User.ID
	if externalUser.Username != "" {
		claims["preferred_username"] = externalUser.Username
	} else {
		claims["preferred_username"] = req.Username // Fallback to login username
	}

	// Custom claims mapping
	if oauthClient.ClientLDAPCustomClaimsMapping != nil {
		for jwtClaim, ldapAttr := range oauthClient.ClientLDAPCustomClaimsMapping {
			if val, ok := externalUser.RawData[ldapAttr]; ok {
				claims[jwtClaim] = val
				log.Debug().Str("jwt_claim", jwtClaim).Str("ldap_attr", ldapAttr).Interface("value", val).Msg("Mapped custom claim from LDAP")
			} else {
				log.Warn().Str("jwt_claim", jwtClaim).Str("ldap_attr", ldapAttr).Msg("LDAP attribute for custom claim not found in user's data")
			}
		}
	}

	// Groups/Roles mapping
	if oauthClient.ClientLDAPAttributeGroups != "" {
		if groupsVal, ok := externalUser.RawData[oauthClient.ClientLDAPAttributeGroups]; ok {
			// groupsVal could be a string or []string. Token service might expect []string for roles.
			// This might need further processing based on how roles are structured in JWT.
			claims["groups"] = groupsVal // Or "roles" depending on desired claim name
			log.Debug().Str("groups_claim", oauthClient.ClientLDAPAttributeGroups).Interface("value", groupsVal).Msg("Mapped groups claim from LDAP")
		}
	}

	// TODO: This is where user provisioning or linking would happen.
	// 1. Check if a local user corresponds to externalUser.ProviderUserID (LDAP DN).
	// 2. If not, create a new local user and link it.
	// 3. The 'sub' claim in the JWT should be the local user's stable ID.
	// For now, we are directly using LDAP attributes. This means no local user record is created/used yet.
	// This will need to be addressed for proper user management within ShadowSSO.
	// The current `oa.tokenService.GenerateTokenResponse` might expect a `domain.User` object.
	// We need to adapt this or create a path that works with `ExternalUserInfo` + claims.

	// For now, let's assume TokenService can work with these claims directly or we adapt it.
	// We need UserID for token generation. For now, using ProviderUserID (LDAP DN) as a stand-in.
	// This is NOT ideal for 'sub' claim which should be a stable local ID.
	// FIXME:
	// userIDForToken := externalUser.ProviderUserID

	// Generate token
	// The TokenService.GenerateTokenResponse currently takes (ctx, user *User, clientID string, scope string, includeRefreshToken bool, nonce string, authTime time.Time, additionalClaims map[string]interface{})
	// We don't have a domain.User here directly. We have ExternalUserInfo and derived claims.
	// This part needs careful integration.
	// Option 1: Create a temporary domain.User on the fly (not good for production).
	// Option 2: Modify TokenService to accept raw claims or ExternalUserInfo for federated users.
	// Option 3: Perform user provisioning here to get/create a domain.User. (Best long term)

	// For this PR, let's simulate a path by directly using claims.
	// This will require TokenService to be flexible or have a new method.
	// Assuming GenerateTokenResponse can be adapted or a similar method exists.
	// For now, this call will likely fail or need adjustment in TokenService.

	// Placeholder: This call will need TokenService to be adapted or a new method.
	// For now, we'll construct a minimal TokenResponse manually for structure.
	// Actual token generation will be handled by TokenService.

	// This is a simplified path for now. The TokenService will need to handle this.
	// We are missing scope and nonce which would typically come from an OAuth2 flow.
	// For a direct LDAP login not part of a standard OAuth flow, these might be defaulted or restricted.
	// FIXME:
	// scope := "" // Default or determine based on client's allowed scopes
	// nonce := "" // Not applicable for direct LDAP->token

	// The sub claim should be the actual subject identifier from your system,
	// not directly the LDAP DN after user linking/provisioning.
	// For now, using ProviderUserID (LDAP DN) as placeholder subject.
	// FIXME:
	// subject := externalUser.ProviderUserID

	// The TokenService.GenerateTokenResponse expects a fully populated domain.User.
	// We need a way to issue tokens based on ExternalUserInfo and mapped claims.
	// This might involve:
	// 1. A User Provisioning step here: find or create a local domain.User based on ExternalUserInfo.
	//    Then pass this domain.User to TokenService.
	// 2. Modifying TokenService to have a path for federated identities that don't require
	//    a full domain.User object initially, but rather the external subject and claims.

	// For now, let's assume we need to call a method that can issue tokens based on claims and client.
	// This part will be a placeholder for actual token generation logic using oa.tokenService
	// and the mapped claims.

	// This is a placeholder and will need proper integration with TokenService
	// For example, TokenService might need a new method like:
	// IssueTokenForFederatedUser(ctx context.Context, subject string, clientID string, scopes []string, claims map[string]interface{}) (*sssoapi.TokenResponse, error)

	// Simulating what TokenService might do with the claims:
	// This is highly dependent on how TokenService is structured.
	// We need to pass the `claims` map to the token service.
	// The current GenerateTokenResponse is tied to a `domain.User`.
	// We'll assume a conceptual `IssueTokenWithClaims` method on tokenService for now.

	// Placeholder for actual token generation. This will likely need TokenService enhancements.
	// For the purpose of this step, we focus on getting claims.
	// The actual token response generation will be part of TokenService integration.
	// Let's assume we have a function in tokenService like:
	// GenerateTokensFromClaims(ctx context.Context, subject, clientID string, scopes []string, inputClaims map[string]interface{}, includeRefreshToken bool) (*sssoapi.TokenResponse, error)

	// For now, we'll just log the claims that would be used.
	log.Info().Interface("claims", claims).Str("ldap_user_dn", externalUser.ProviderUserID).Msg("Claims prepared for token generation")

	// TODO: Integrate properly with TokenService.
	// This might involve fetching/creating a local user linked to this LDAP identity,
	// then calling the existing TokenService methods with that local user.
	// Or, adapting TokenService to issue tokens based on pre-resolved external claims.
	// For this iteration, returning a placeholder success to show the flow up to claims mapping.

	// --- Actual Token Generation (Conceptual - Requires TokenService modification or User Provisioning) ---
	// User provisioning step:
	//  localUser, err := oa.userProvisioningService.ProvisionUser(ctx, externalUser, req.ProviderName)
	//  if err != nil { log.Error().Err(err).Msg("User provisioning failed"); c.JSON(http.StatusInternalServerError, ...); return }
	//
	//  tokenResponse, err := oa.tokenService.GenerateTokenResponse(ctx, localUser, oauthClient.ID, strings.Split(oauthClient.AllowedScopes[0], " "), true, "", time.Now(), claims)
	//  if err != nil { log.Error().Err(err).Msg("Token generation failed"); c.JSON(http.StatusInternalServerError, ...); return }
	//  c.JSON(http.StatusOK, tokenResponse)
	// --- End Conceptual Token Generation ---

	// For now, returning the mapped claims for demonstration until TokenService integration.
	// In a real scenario, this would be a token response.
	log.Warn().Msg("LDAPLoginHandler: Token generation part is conceptual and needs full TokenService integration/user provisioning.")
	c.JSON(http.StatusOK, gin.H{
		"message":                        "Authentication successful, claims mapped.",
		"claims_to_be_included_in_token": claims,
		"ldap_dn":                        externalUser.ProviderUserID,
		"note":                           "This is not a real token response. Token generation needs to be fully integrated.",
	})
}

// RegisterLDAPRoutes adds the LDAP specific routes.
// It should be called from the main route registration if LDAP is enabled.
func (oa *OAuth2API) RegisterLDAPRoutes(router *gin.RouterGroup) {
	ldapGroup := router.Group("/ldap") // Or directly on the main router group
	{
		// The {providerName} allows for multiple LDAP configurations.
		ldapGroup.POST("/:providerName/login", oa.LDAPLoginHandler)
	}
}
