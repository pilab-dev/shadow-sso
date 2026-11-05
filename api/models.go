package api

import (
	"encoding/json"
	"time"
)

const (
	TokenTypeAccessToken  = "access_token"
	TokenTypeRefreshToken = "refresh_token"
	TokenTypeIDToken      = "id_token"
)

// TokenResponse represents an OAuth 2.0 token response
type TokenResponse struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// AuthorizationDetails is the RFC 9396 authorization_details array granted to the access token.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
}

// DeviceAuthResponse is the response from the device authorization endpoint.
// See RFC 8628, Section 3.2.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`         // Lifetime in seconds of the device_code and user_code
	Interval                int    `json:"interval,omitempty"` // Minimum polling interval in seconds for the device
}

// Default discovery metadata. These describe what shadow-sso actually
// implements today; keep them in sync with the token and claims code.
var (
	// DefaultScopesSupported lists the scopes the server understands and
	// enforces. offline_access selects the longer offline refresh token lifetime.
	DefaultScopesSupported = []string{"openid", "profile", "email", "address", "phone", "offline_access"}

	// DefaultClaimsSupported lists claims that can appear in an ID token,
	// access token or UserInfo response.
	DefaultClaimsSupported = []string{
		"sub", "iss", "aud", "exp", "iat", "nbf", "jti", "auth_time", "nonce", "sid",
		"email", "email_verified", "phone_number", "phone_number_verified", "address", "name", "given_name", "family_name", "preferred_username",
		"acr", "amr", "groups", "roles", "realm_access", "resource_access", "cnf",
	}

	// DefaultTokenEndpointAuthMethods are the client authentication methods
	// implemented by the token endpoint. client_secret_basic is not parsed
	// today, so it must not be advertised.
	DefaultTokenEndpointAuthMethods = []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}

	// DefaultResourceEndpointAuthMethods are the methods implemented by the
	// introspection and revocation endpoints.
	DefaultResourceEndpointAuthMethods = []string{"client_secret_post"}

	// DPoPSigningAlgValuesSupported are the proof algorithms accepted by the
	// DPoP verifier (RSA and EC JWKs, see internal/dpop).
	DPoPSigningAlgValuesSupported = []string{
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512",
	}

	// DefaultClaimTypesSupported is the only claim type the server emits.
	DefaultClaimTypesSupported = []string{"normal"}

	// DefaultClientAssertionSigningAlgs are the RSA PKCS#1 v1.5 algorithms
	// accepted for private_key_jwt client assertions.
	DefaultClientAssertionSigningAlgs = []string{"RS256", "RS384", "RS512"}

	// DefaultPromptValuesSupported are the prompt values honoured by the
	// authorization endpoint.
	DefaultPromptValuesSupported = []string{"none", "login", "select_account"}
)

// OpenIDConfiguration represents the OpenID Connect discovery document
//
//nolint:tagliatelle
type OpenIDConfiguration struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint                *string  `json:"device_authorization_endpoint,omitempty"` // New field
	PushedAuthorizationRequestEndpoint         *string  `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests"`
	EndSessionEndpoint                         *string  `json:"end_session_endpoint,omitempty"`
	FrontchannelLogoutSupported                bool     `json:"frontchannel_logout_supported,omitempty"`
	FrontchannelLogoutSessionSupported         bool     `json:"frontchannel_logout_session_supported,omitempty"`
	BackchannelLogoutSupported                 bool     `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported          bool     `json:"backchannel_logout_session_supported,omitempty"`
	UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	RegistrationEndpoint                       *string  `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgSupported       []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	AuthorizationSigningAlgValuesSupported     []string `json:"authorization_signing_alg_values_supported,omitempty"` // JARM response signing
	ServiceDocumentation                       *string  `json:"service_documentation,omitempty"`
	UILocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
	OpPolicyURI                                *string  `json:"op_policy_uri,omitempty"`
	OpTosURI                                   *string  `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                         *string  `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpoint                      *string  `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported  []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported,omitempty"`
	ClaimsSupported                            []string `json:"claims_supported,omitempty"`
	ClaimTypesSupported                        []string `json:"claim_types_supported,omitempty"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration              bool     `json:"require_request_uri_registration"`
	PromptValuesSupported                      []string `json:"prompt_values_supported,omitempty"`
	DPoPSigningAlgValuesSupported              []string `json:"dpop_signing_alg_values_supported,omitempty"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	TLSClientCertificateBoundAccessTokens      bool     `json:"tls_client_certificate_bound_access_tokens"`
	// AuthorizationDetailsTypesSupported lists RFC 9396 types at least one client may request.
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

	// ACRValuesSupported lists the acr values asserted in ID tokens.
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`
}

type UserInfoAddress struct {
	Formatted     string `json:"formatted,omitempty"`      // (String) The full mailing address, with multiple lines if necessary.
	StreetAddress string `json:"street_address,omitempty"` // : (String) The street address component.
	Locality      string `json:"locality,omitempty"`       // (String) City or locality component.
	Region        string `json:"region,omitempty"`         // (String) State, province, prefecture, or region component.
	PostalCode    string `json:"postal_code,omitempty"`    // (String) Zip code or postal code component.
	Country       string `json:"country,omitempty"`        // (String) Country name component.
}

type UserInfo struct {
	// Core Claims (implicitly requested with openid scope):
	Sub string `json:"sub"` // Subject: A locally unique and never re-assigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client.

	// Profile Claims (requested with profile scope):
	Name              *string `json:"name,omitempty"`               // Full name of the End-User, e.g., "John Doe".
	GivenName         *string `json:"given_name,omitempty"`         // Given name of the End-User, e.g., "John".
	FamilyName        *string `json:"family_name,omitempty"`        // Family name of the End-User, e.g., "Doe".
	MiddleName        *string `json:"middle_name,omitempty"`        // Middle name of the End-User.
	Nickname          *string `json:"nickname,omitempty"`           // Casual name of the End-User that may or may not be the same as the given_name.
	PreferredUsername *string `json:"preferred_username,omitempty"` // Shorthand name for the End-User, suitable for display.
	Profile           *string `json:"profile,omitempty"`            // URL of the End-User's profile page.
	Picture           *string `json:"picture,omitempty"`            // URL of the End-User's profile picture.
	Website           *string `json:"website,omitempty"`            // Website URL of the End-User's profile.
	Gender            *string `json:"gender,omitempty"`             // The End-User's gender e.g. Male
	Birthdate         *string `json:"birthdate,omitempty"`          // The End-User's birthday, typically in ISO 8601:2004 YYYY-MM-DD format.
	ZoneInfo          *string `json:"zoneinfo,omitempty"`           // The End-User's time zone, e.g., "America/Los_Angeles" or "Europe/Budapest".
	Locale            *string `json:"locale,omitempty"`             // IETF language tag, e.g., "en-US"
	UpdatedAt         *int64  `json:"updated_at,omitempty"`         // Unix timestamp

	// Email Claims (requested with email scope):
	Email         *string `json:"email,omitempty"`          // The End-User's email address.
	EmailVerified *bool   `json:"email_verified,omitempty"` // Boolean value indicating whether the End-User's email address has been verified.

	// Address Claims (requested with address scope):
	Address *UserInfoAddress `json:"address,omitempty"` // The End-User's preferred postal address, represented as a structured object.

	// Phone Claims (requested with phone scope):
	PhoneNumber         *string `json:"phone_number,omitempty"`          // The End-User's phone number, in E.164 format.
	PhoneNumberVerified *bool   `json:"phone_number_verified,omitempty"` // Boolean value indicating whether the End-User's phone number has been verified.

	CustomClaims map[string]interface{} `json:"custom_claims,omitempty"`
}

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

	// External UI Configuration
	NextJSLoginURL string `json:"nextjs_login_url,omitempty"` // URL for the Next.js login page
}

// EndpointConfig controls which endpoints are enabled
type EndpointConfig struct {
	Authorization       bool `json:"authorization"`
	Token               bool `json:"token"`
	UserInfo            bool `json:"userinfo"`
	JWKS                bool `json:"jwks"`
	Registration        bool `json:"registration"`
	Revocation          bool `json:"revocation"`
	Introspection       bool `json:"introspection"`
	EndSession          bool `json:"end_session"`
	DeviceAuthorization bool `json:"device_authorization"`
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
	RequirePAR                    bool     `json:"require_par"` // RFC 9126: reject authorization requests not pushed first
	RequirePKCEForPublicClients   bool     `json:"require_pkce_for_public_clients"`
	AllowedSigningAlgs            []string `json:"allowed_signing_algs"`
	AllowedEncryptionAlgs         []string `json:"allowed_encryption_algs"`
	AllowedEncryptionEnc          []string `json:"allowed_encryption_enc"`
	RequireSignedRequestObject    bool     `json:"require_signed_request_object"`
	RequireRequestURIRegistration bool     `json:"require_request_uri_registration"`
	DefaultMaxAge                 int      `json:"default_max_age"`
	RequireAuthTime               bool     `json:"require_auth_time"`
	PasswordHashingCost           int      `json:"password_hashing_cost"`
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
