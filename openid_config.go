package sso

import (
	"fmt"
	"time"
)

// OpenIDProviderConfig represents the complete configuration for the OpenID Connect provider
type OpenIDProviderConfig struct {
	// Basic Settings
	Issuer            string        `json:"issuer"`
	AccessTokenTTL    time.Duration `json:"access_token_ttl"`
	RefreshTokenTTL   time.Duration `json:"refresh_token_ttl"`
	AuthCodeTTL       time.Duration `json:"auth_code_ttl"`
	IDTokenTTL        time.Duration `json:"id_token_ttl"`
	SessionTTL        time.Duration `json:"session_ttl"`
	KeyRotationPeriod time.Duration `json:"key_rotation_period"`
	RequireConsent    bool          `json:"require_consent"`
	ForceConsent      bool          `json:"force_consent"`

	// Endpoint Configuration
	EnabledEndpoints EndpointConfig `json:"enabled_endpoints"`

	// Flow Configuration
	EnabledFlows FlowConfig `json:"enabled_flows"`

	// Grant Types Configuration
	EnabledGrantTypes GrantTypesConfig `json:"enabled_grant_types"`

	// Security Configuration
	SecurityConfig SecurityConfig `json:"security_config"`

	// Token Configuration
	TokenConfig TokenConfig `json:"token_config"`

	// PKCE Configuration
	PKCEConfig PKCEConfig `json:"pkce_config"`

	// Claims Configuration
	ClaimsConfig ClaimsConfig `json:"claims_config"`
}

// EndpointConfig controls which endpoints are enabled
type EndpointConfig struct {
	Authorization bool `json:"authorization"`
	Token         bool `json:"token"`
	UserInfo      bool `json:"userinfo"`
	JWKS          bool `json:"jwks"`
	Registration  bool `json:"registration"`
	Revocation    bool `json:"revocation"`
	Introspection bool `json:"introspection"`
	EndSession    bool `json:"end_session"`
}

// FlowConfig controls which OAuth2/OIDC flows are enabled
type FlowConfig struct {
	AuthorizationCode bool `json:"authorization_code"`
	Implicit          bool `json:"implicit"`
	Hybrid            bool `json:"hybrid"`
}

// GrantTypesConfig controls which grant types are enabled
type GrantTypesConfig struct {
	AuthorizationCode bool `json:"authorization_code"`
	ClientCredentials bool `json:"client_credentials"`
	RefreshToken      bool `json:"refresh_token"`
	Password          bool `json:"password"`
	Implicit          bool `json:"implicit"`
	JWTBearer         bool `json:"jwt_bearer"`
	DeviceCode        bool `json:"device_code"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	RequirePKCE                   bool     `json:"require_pkce"`
	RequirePKCEForPublicClients   bool     `json:"require_pkce_for_public_clients"`
	AllowedSigningAlgs            []string `json:"allowed_signing_algs"`
	AllowedEncryptionAlgs         []string `json:"allowed_encryption_algs"`
	AllowedEncryptionEnc          []string `json:"allowed_encryption_enc"`
	RequireSignedRequestObject    bool     `json:"require_signed_request_object"`
	RequireRequestURIRegistration bool     `json:"require_request_uri_registration"`
	DefaultMaxAge                 int      `json:"default_max_age"`
	RequireAuthTime               bool     `json:"require_auth_time"`
}

// TokenConfig contains token-related settings
type TokenConfig struct {
	AccessTokenFormat          string   `json:"access_token_format"` // JWT or opaque
	IDTokenSigningAlg          string   `json:"id_token_signing_alg"`
	AccessTokenSigningAlg      string   `json:"access_token_signing_alg"`
	SupportedResponseTypes     []string `json:"supported_response_types"`
	SupportedResponseModes     []string `json:"supported_response_modes"`
	SupportedTokenEndpointAuth []string `json:"supported_token_endpoint_auth"`
}

// PKCEConfig contains PKCE-related settings
type PKCEConfig struct {
	Enabled                   bool     `json:"enabled"`
	AllowPlainChallengeMethod bool     `json:"allow_plain_challenge_method"`
	SupportedMethods          []string `json:"supported_methods"`
}

// ClaimsConfig contains claims-related settings
type ClaimsConfig struct {
	SupportedClaims       []string          `json:"supported_claims"`
	SupportedScopes       []string          `json:"supported_scopes"`
	ClaimsMappings        map[string]string `json:"claims_mappings"`
	EnableClaimsParameter bool              `json:"enable_claims_parameter"`
}

// NewDefaultConfig creates a new OpenIDProviderConfig with sensible defaults
func NewDefaultConfig(issuer string) *OpenIDProviderConfig {
	return &OpenIDProviderConfig{
		Issuer:            issuer,
		AccessTokenTTL:    time.Hour,
		RefreshTokenTTL:   time.Hour * 24 * 30, // 30 days
		AuthCodeTTL:       time.Minute * 10,
		IDTokenTTL:        time.Hour,
		SessionTTL:        time.Hour * 24,
		KeyRotationPeriod: time.Hour * 24,
		RequireConsent:    true,
		ForceConsent:      false,

		EnabledEndpoints: EndpointConfig{
			Authorization: true,
			Token:         true,
			UserInfo:      true,
			JWKS:          true,
			Registration:  false,
			Revocation:    true,
			Introspection: true,
			EndSession:    true,
		},

		EnabledFlows: FlowConfig{
			AuthorizationCode: true,
			Implicit:          true,
			Hybrid:            true,
		},

		EnabledGrantTypes: GrantTypesConfig{
			AuthorizationCode: true,
			ClientCredentials: true,
			RefreshToken:      true,
			Password:          false,
			Implicit:          true,
			JWTBearer:         false,
			DeviceCode:        false,
		},

		SecurityConfig: SecurityConfig{
			RequirePKCE:                 false,
			RequirePKCEForPublicClients: true,
			AllowedSigningAlgs:          []string{"RS256", "RS384", "RS512"},
			AllowedEncryptionAlgs:       []string{"RSA-OAEP", "RSA-OAEP-256"},
			AllowedEncryptionEnc:        []string{"A128CBC-HS256", "A256CBC-HS512"},
			RequireSignedRequestObject:  false,
			DefaultMaxAge:               3600,
			RequireAuthTime:             false,
		},

		TokenConfig: TokenConfig{
			AccessTokenFormat:      "jwt",
			IDTokenSigningAlg:      "RS256",
			AccessTokenSigningAlg:  "RS256",
			SupportedResponseTypes: []string{"code", "token", "id_token", "code token", "code id_token"},
			SupportedResponseModes: []string{"query", "fragment", "form_post"},
			SupportedTokenEndpointAuth: []string{
				"client_secret_basic",
				"client_secret_post",
				"private_key_jwt",
			},
		},

		PKCEConfig: PKCEConfig{
			Enabled:                   true,
			AllowPlainChallengeMethod: false,
			SupportedMethods:          []string{"S256"},
		},

		ClaimsConfig: ClaimsConfig{
			SupportedClaims: []string{
				"sub", "iss", "auth_time", "name",
				"given_name", "family_name", "email",
			},
			SupportedScopes: []string{
				"openid", "profile", "email", "address", "phone",
				"offline_access",
			},
			ClaimsMappings: map[string]string{
				"name":       "display_name",
				"given_name": "first_name",
				"email":      "email_address",
			},
			EnableClaimsParameter: true,
		},
	}
}

// Validate checks if the configuration is valid
func (c *OpenIDProviderConfig) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("issuer cannot be empty")
	}

	if c.AccessTokenTTL <= 0 {
		return fmt.Errorf("access token TTL must be positive")
	}

	if c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("refresh token TTL must be positive")
	}

	if c.AuthCodeTTL <= 0 {
		return fmt.Errorf("auth code TTL must be positive")
	}

	if len(c.SecurityConfig.AllowedSigningAlgs) == 0 {
		return fmt.Errorf("at least one signing algorithm must be allowed")
	}

	if c.TokenConfig.AccessTokenFormat != "jwt" && c.TokenConfig.AccessTokenFormat != "opaque" {
		return fmt.Errorf("invalid access token format: %s", c.TokenConfig.AccessTokenFormat)
	}

	return nil
}

// IsGrantTypeEnabled checks if a specific grant type is enabled
func (c *OpenIDProviderConfig) IsGrantTypeEnabled(grantType string) bool {
	switch grantType {
	case "authorization_code":
		return c.EnabledGrantTypes.AuthorizationCode
	case "client_credentials":
		return c.EnabledGrantTypes.ClientCredentials
	case "refresh_token":
		return c.EnabledGrantTypes.RefreshToken
	case "password":
		return c.EnabledGrantTypes.Password
	case "implicit":
		return c.EnabledGrantTypes.Implicit
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		return c.EnabledGrantTypes.JWTBearer
	case "urn:ietf:params:oauth:grant-type:device_code":
		return c.EnabledGrantTypes.DeviceCode
	default:
		return false
	}
}

// IsEndpointEnabled checks if a specific endpoint is enabled
func (c *OpenIDProviderConfig) IsEndpointEnabled(endpoint string) bool {
	switch endpoint {
	case "authorization":
		return c.EnabledEndpoints.Authorization
	case "token":
		return c.EnabledEndpoints.Token
	case "userinfo":
		return c.EnabledEndpoints.UserInfo
	case "jwks":
		return c.EnabledEndpoints.JWKS
	case "registration":
		return c.EnabledEndpoints.Registration
	case "revocation":
		return c.EnabledEndpoints.Revocation
	case "introspection":
		return c.EnabledEndpoints.Introspection
	case "end_session":
		return c.EnabledEndpoints.EndSession
	default:
		return false
	}
}
