package services

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/domain"
)

//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_interfaces.go -package=mock_services OAuthService,TokenService,PKCEService,JWKSService,UserService,TwoFactorService,FederationService,ConfigurationService,ClientService,PhoneVerificationService,MFAService,PushMFAService,IDPManagementService,ClientManagementService,ServiceAccountService

// OAuthService defines the interface for OAuth 2.0 / OIDC operations.
type OAuthService interface {
	RegisterUser(ctx context.Context, username, password string) (*domain.User, error)
	Login(ctx context.Context, username, password, deviceInfo string) (*api.TokenResponse, error)
	GetUserSessions(ctx context.Context, userID string) ([]*domain.Session, error)
	RefreshToken(ctx context.Context, refreshTokenValue string, clientID string) (*api.TokenResponse, error)
	GetJWKS() *domain.JWKS
	ValidateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error)
	DirectGrant(ctx context.Context, clientID, clientSecret, username, password, scope string) (*api.TokenResponse, error)
	ClientCredentials(ctx context.Context, clientID, clientSecret, scope string) (*api.TokenResponse, error)
	PasswordGrant(ctx context.Context, username, password, scope string, cli *domain.Client) (*api.TokenResponse, error)
	ExchangeAuthorizationCode(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*api.TokenResponse, error)
	IntrospectToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*domain.TokenIntrospection, error)
	RevokeToken(ctx context.Context, tokenToRevoke, tokenTypeHint, clientID, clientSecret string) error
	GenerateAuthCode(ctx context.Context, clientID, userID, redirectURI, scope, codeChallenge, codeChallengeMethod, nonce string, authTime time.Time) (string, error)
	InitiateDeviceAuthorization(ctx context.Context, clientID, scope, verificationBaseURI string) (*api.DeviceAuthResponse, error)
	VerifyUserCode(ctx context.Context, userCode, userID string) (*domain.DeviceCode, error)
	IssueTokenForDeviceFlow(ctx context.Context, deviceCode, clientID string) (*api.TokenResponse, error)
	TokenExchange(ctx context.Context, subjectToken, subjectTokenType, requestedTokenType, resource, scope, clientID string) (*api.TokenResponse, error)
}

// TokenService defines the interface for token generation and validation.
type TokenService interface {
	CreateToken(ctx context.Context, opts domain.CreateTokenOptions, claims jwt.Claims) (*domain.Token, error)
	BuildToken(token *domain.Token) error
	GenerateTokenPair(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration) (*api.TokenResponse, error)
	GenerateTokenPairWithFamily(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration, family string, nonce string, authTime time.Time) (*api.TokenResponse, error)
	GenerateIDToken(ctx context.Context, userID, clientID, nonce string, authTime time.Time, scope string) (string, error)
	ValidateAccessToken(ctx context.Context, tokenValue string) (*domain.Token, error)
	RevokeToken(ctx context.Context, token string) error
	GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error)
	GetAccessTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error)
	ValidateIDToken(ctx context.Context, tokenValue string) (map[string]interface{}, error)
}

// PKCEService defines the interface for PKCE validation.
type PKCEService interface {
	ValidateCodeVerifier(ctx context.Context, code, verifier string) error
	SavePKCEChallenge(ctx context.Context, code, challenge string) error
}

// JWKSService defines the interface for JSON Web Key Set operations.
type JWKSService interface {
	GetPublicJWKS(ctx context.Context) (*JSONWebKeySet, error)
	GetJWKS() JSONWebKeySet
	GetSigningKey() (string, interface{})
}

// ClientService defines the interface for client management.
type ClientService interface {
	CreateConfidentialClient(ctx context.Context, name string, redirectURIs []string, allowedScopes []string) (*domain.Client, error)
	CreatePublicClient(ctx context.Context, name string, redirectURIs []string, allowedScopes []string) (*domain.Client, error)
	CreateClient(ctx context.Context, client *domain.Client) (*domain.Client, error)
	ValidateRedirectURI(ctx context.Context, clientID, redirectURI string) error
	ValidateScope(ctx context.Context, clientID string, requestedScopes []string) error
	ValidateGrantType(ctx context.Context, clientID, grantType string) error
	RequiresPKCE(ctx context.Context, clientID string) (bool, error)
	GetClient(ctx context.Context, clientID string) (*domain.Client, error)
	ValidateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error)
}

// UserService defines the interface for user management.
type UserService interface {
	RegisterUser(ctx context.Context, email, password, firstName, lastName string) (*domain.User, error)
	ActivateUser(ctx context.Context, userID string) error
	LockUser(ctx context.Context, userID string) error
	ListUsers(ctx context.Context, pageToken string, pageSize int) ([]*domain.User, string, error)
	GetUser(ctx context.Context, userID string) (*domain.User, error)
	ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error
	SendPhoneVerificationOtp(ctx context.Context, userID string) error
	VerifyPhoneNumber(ctx context.Context, userID, otp string) error
}

// TwoFactorService defines the interface for two-factor authentication.
type TwoFactorService interface {
	InitiateTOTPSetup(ctx context.Context, userID string) (secret, qrCodeURI string, err error)
	VerifyAndEnableTOTP(ctx context.Context, userID, totpCode string) (recoveryCodes []string, err error)
	Disable2FA(ctx context.Context, userID, passwordOr2FaCode string) error
	GenerateRecoveryCodes(ctx context.Context, userID, passwordOr2FaCode string) (recoveryCodes []string, err error)
	InitiateHOTPSetup(ctx context.Context, userID string) (secret, qrCodeURI string, initialCounter uint64, err error)
	VerifyAndEnableHOTP(ctx context.Context, userID, hotpCode string) (recoveryCodes []string, err error)
	InitiateEmailMFASetup(ctx context.Context, userID string) error
	VerifyAndEnableEmailMFA(ctx context.Context, userID, emailOtp string) (recoveryCodes []string, err error)
	SendMFAChallenge(ctx context.Context, userID string) (method string, counter uint64, challengeID string, err error)
	VerifyMFAChallenge(ctx context.Context, userID, code string, counter uint64) (bool, error)
	InitiatePushMFASetup(ctx context.Context, userID, deviceToken string) error
	VerifyAndEnablePushMFA(ctx context.Context, userID string) (recoveryCodes []string, err error)
	RegisterPushDevice(ctx context.Context, userID, deviceToken string) error
	UnregisterPushDevice(ctx context.Context, userID, deviceToken string) error
	RespondToPushChallenge(ctx context.Context, userID, challengeID, response string) (status string, err error)
	GetPushChallengeStatus(ctx context.Context, userID, challengeID string) (status string, err error)
}

// FederationService defines the interface for federated identity operations.
type FederationService interface {
	InitiateFederatedLogin(ctx context.Context, providerName string) (authURL, state string, err error)
	HandleFederatedCallback(ctx context.Context, providerName, state, sessionState, code string) (*FederationCallbackResult, error)
	ListUserFederatedIdentities(ctx context.Context, userID string) ([]*domain.UserFederatedIdentity, error)
	RemoveUserFederatedIdentity(ctx context.Context, userID, providerName, providerUserID string) error
	PromptMergeFederatedAccount(ctx context.Context, continuationToken string) (*MergePromptResult, error)
	ConfirmMergeFederatedAccount(ctx context.Context, continuationToken string) (*FederationCallbackResult, error)
	AuthenticateDirect(ctx context.Context, providerName, username, password string) (interface{}, error)
	Stop()
}

// IDPManagementService defines the interface for Identity Provider management.
type IDPManagementService interface {
	AddIdP(ctx context.Context, idp *domain.IdentityProvider) (*domain.IdentityProvider, error)
	GetIdP(ctx context.Context, id string) (*domain.IdentityProvider, error)
	ListIdPs(ctx context.Context, onlyEnabled bool) ([]*domain.IdentityProvider, error)
	UpdateIdP(ctx context.Context, idp *domain.IdentityProvider) (*domain.IdentityProvider, error)
	DeleteIdP(ctx context.Context, id string) error
}

// ClientManagementService defines the interface for OAuth client management.
type ClientManagementService interface {
	RegisterClient(ctx context.Context, client *domain.Client) (*domain.Client, string, error)
	GetClient(ctx context.Context, clientID string) (*domain.Client, error)
	ListClients(ctx context.Context, filter domain.ClientFilter) ([]*domain.Client, string, error)
	UpdateClient(ctx context.Context, client *domain.Client) (*domain.Client, error)
	DeleteClient(ctx context.Context, clientID string) error
}

// ServiceAccountService defines the interface for service account operations.
type ServiceAccountService interface {
	CreateServiceAccountKey(ctx context.Context, projectID, clientEmail, displayName string) (*domain.ServiceAccount, *domain.ServiceAccountKey, error)
	ListServiceAccountKeys(ctx context.Context, serviceAccountID string) ([]*domain.PublicKeyInfo, error)
	DeleteServiceAccountKey(ctx context.Context, serviceAccountID, keyID string) error
}

// ConfigurationService defines the interface for operational configuration.
type ConfigurationService interface {
	GetString(ctx context.Context, configType domain.ConfigurationType, key string) (string, error)
	GetStringWithDefault(ctx context.Context, configType domain.ConfigurationType, key, defaultValue string) string
	GetBool(ctx context.Context, configType domain.ConfigurationType, key string) (bool, error)
	GetBoolWithDefault(ctx context.Context, configType domain.ConfigurationType, key string, defaultValue bool) bool
	SetString(ctx context.Context, configType domain.ConfigurationType, key, value string, encrypt bool, description string, updatedBy string) error
	GetAllByType(ctx context.Context, configType domain.ConfigurationType) ([]*domain.Configuration, error)
	BootstrapDefaultConfigs(ctx context.Context) error
	RefreshCache(ctx context.Context) error
}

// PhoneVerificationService defines the interface for phone verification.
type PhoneVerificationService interface {
	SendVerificationOTP(ctx context.Context, userID string) error
	VerifyPhoneNumber(ctx context.Context, userID, otp string) error
}

// MFAService defines the interface for multi-factor authentication.
type MFAService interface {
	InitiateEmailMFASetup(ctx context.Context, userID string) error
	VerifyAndEnableEmailMFA(ctx context.Context, userID, otp string) error
	SendMFAChallenge(ctx context.Context, userID string) (method string, counter uint64, challengeID string, err error)
	VerifyMFAChallenge(ctx context.Context, userID, code string, counter uint64) (bool, error)
	VerifyMFAChallengeWithChallengeID(ctx context.Context, userID, challengeID, code string, counter uint64) (bool, error)
	DisableEmailMFA(ctx context.Context, userID string) error
}

// PushMFAService defines the interface for push-based MFA.
type PushMFAService interface {
	RegisterDeviceToken(ctx context.Context, userID, deviceToken string) error
	UnregisterDeviceToken(ctx context.Context, userID, deviceToken string) error
	CreatePushMFAChallenge(ctx context.Context, user *domain.User, ipAddress, userAgent string) (string, error)
	VerifyPushMFAChallenge(ctx context.Context, userID, challengeID string, approved bool) error
	GetPushMFAChallengeStatus(ctx context.Context, userID, challengeID string) (string, error)
	EnablePushMFA(ctx context.Context, userID string) error
	DisablePushMFA(ctx context.Context, userID string) error
}

// FederationCallbackResult holds the result of a federated callback.
type FederationCallbackResult struct {
	Status            FederationCallbackStatus
	Message           string
	AccessToken       string
	TokenType         string
	ExpiresIn         int32
	RefreshToken      string
	IDToken           string
	UserInfo          *domain.User
	ProviderUserID    string
	ProviderEmail     string
	ProviderName      string
	ContinuationToken string
}

// FederationCallbackStatus represents the status of a federated callback.
type FederationCallbackStatus string

const (
	FederationStatusLoginSuccessful    FederationCallbackStatus = "login_successful"
	FederationStatusAccountLinked      FederationCallbackStatus = "account_linked"
	FederationStatusMergeRequired      FederationCallbackStatus = "merge_required"
	FederationStatusRegistrationNeeded FederationCallbackStatus = "registration_needed"
	FederationStatusConflict           FederationCallbackStatus = "conflict"
)

// MergePromptResult holds the result of a merge prompt.
type MergePromptResult struct {
	Message                string
	ExistingLocalUserEmail string
	ProviderName           string
}

// FederationServiceInterface is an alias for the federation.Service type compatibility.
type FederationServiceInterface interface {
	GenerateAuthState() (string, error)
	GetAuthorizationURL(ctx context.Context, providerName, state string) (string, error)
	HandleCallback(ctx context.Context, providerName, queryState, sessionState, code string) (interface{}, interface{}, error)
}
