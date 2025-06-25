package services

import (
	"context"
	"crypto/rand" // Added
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex" // Added
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/dto"            // Added DTO import
	serrors "github.com/pilab-dev/shadow-sso/errors" // Import the aliased errors
	applog "github.com/pilab-dev/shadow-sso/log"     // Renamed to avoid conflict with zerolog/log
	"golang.org/x/crypto/bcrypt"
)

// Constants for Device Flow
const (
	deviceCodeLength    = 32                                // Length of the device_code in bytes
	userCodeLength      = 8                                 // Length of the user_code (e.g., "ABCD-EFGH")
	userCodeCharset     = "BCDFGHJKLMNPQRSTVWXYZ0123456789" // Base32-like, avoiding ambiguous chars
	userCodeChunkSize   = 4
	deviceCodeLifetime  = 10 * time.Minute // How long device_code and user_code are valid (e.g., 10 minutes)
	defaultPollInterval = 5                // Default polling interval in seconds
)

// generateRandomString generates a secure random string of given length in bytes, hex encoded.
func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateUserCode generates a user-friendly code.
func generateUserCode(length int, charset string, chunkSize int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// Fallback or panic, this should ideally not fail
		panic(fmt.Errorf("failed to generate random bytes for user code: %w", err))
	}

	for i := 0; i < length; i++ {
		b[i] = charset[int(b[i])%len(charset)]
	}

	if chunkSize <= 0 {
		return string(b)
	}

	var result strings.Builder
	for i, char := range b {
		if i > 0 && i%chunkSize == 0 {
			result.WriteString("-")
		}
		result.WriteByte(char)
	}
	return result.String()
}

type OAuthService struct {
	oauthRepo    OAuthRepository
	userRepo     UserService        // Changed from UserStore to UserServiceInternal
	clientRepo   client.ClientStore // Assuming this repo is fine, or it's part of OAuthRepository
	tokenService *TokenService      // Concrete TokenService, which has updated Get...Info methods
	keyID        string
	issuer       string
	logger       applog.Logger // Added application logger
}

// NewOAuthService creates a new instance of the OAuthService.
func NewOAuthService(
	oauthRepo OAuthRepository,
	userRepo UserService, // Changed
	tokenService *TokenService,
	issuer string,
	logger applog.Logger, // Added logger
) *OAuthService {
	return &OAuthService{
		oauthRepo:    oauthRepo,
		userRepo:     userRepo,
		keyID:        uuid.NewString(), // ! This must be refactored to keystore or something.
		tokenService: tokenService,
		issuer:       issuer,
		logger:       logger, // Store logger
	}
}

func (s *OAuthService) RegisterUser(ctx context.Context, username, password string) (*User, error) {
	// Hashing password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the user
	user, err := s.userRepo.CreateUser(ctx, &dto.UserCreateRequest{
		Email:     username,
		Password:  string(hashedPassword),
		FirstName: "",
		LastName:  "",
		Roles:     []string{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &User{
		ID:                      user.ID,
		Username:                user.Email,
		Password:                "",
		CreatedAt:               user.CreatedAt,
		UpdatedAt:               user.UpdatedAt,
		ExternalProviderMapping: map[string]string{},
		AdditionalUserInfo:      map[string]any{},
	}, nil
}

func (s *OAuthService) Login(ctx context.Context, username, password, deviceInfo string) (*api.TokenResponse, error) {
	// Search for the user
	user, err := s.userRepo.GetUserByEmail(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Generate token and session
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Hour)

	session := &UserSession{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		DeviceInfo:   deviceInfo,
		IsRevoked:    false,
	}

	// Save the generated session
	if err := s.userRepo.CreateSession(ctx, user.ID, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Store token in the database
	token := &Token{
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   "",
		UserID:     user.ID,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(ctx, token); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	return &api.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
	}, nil
}

// GetUserSessions retrieves all active sessions for a user.
func (s *OAuthService) GetUserSessions(ctx context.Context, userID string) ([]UserSession, error) {
	return s.userRepo.GetUserSessions(ctx, userID)
}

// TokenRefresh refreshes the access token with the refresh token.
func (s *OAuthService) RefreshToken(ctx context.Context, refreshToken string, clientID string) (*api.TokenResponse, error) {
	session, err := s.userRepo.GetSessionByToken(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	if session.IsRevoked || time.Now().After(session.ExpiresAt) {
		return nil, ErrTokenExpiredOrRevoked
	}

	if err := s.userRepo.UpdateSessionLastUsed(ctx, session.ID); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return s.tokenService.GenerateTokenPair(ctx, clientID, session.UserID, session.Scope, time.Hour)
}

// GetJWKS returns the JSON Web Key Set (JWKS) containing the public key used to sign tokens.
func (s *OAuthService) GetJWKS() JSONWebKeySet {
	keyset := JSONWebKeySet{
		Keys: make([]JSONWebKey, 0),
	}

	if false {
		// The public key of the signing key. This must be set in the constructor.
		// publicKey, _ := s.signingKey.Public().(*rsa.PublicKey)

		// Encode the public key components in base64. This is required by the JWKS spec.
		// mod := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		// exp := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

		// []JSONWebKey{
		// 	{
		// 		Kid: s.keyID, // Unique Key ID
		// 		Kty: "RSA",   // Key Type
		// 		Alg: "RS256", // Algorithm
		// 		Use: "sig",   // Usage (signature)
		// 		N:   mod,     // Modulus
		// 		E:   exp,     // Exponent
		// 	},
		// }
	}

	return keyset
}

// Additional methods for OAuthService
func (s *OAuthService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
	cli, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	// Compare client secret using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(cli.Secret), []byte(clientSecret)) != 1 {
		return nil, ErrInvalidCredentials
	}

	return cli, nil
}

// DirectGrant implements the Resource Owner Password Credentials flow
func (s *OAuthService) DirectGrant(ctx context.Context,
	clientID, clientSecret, username, password, scope string,
) (*api.TokenResponse, error) {
	// Validate cli
	cli, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// Check if password grant is allowed for this client
	if !contains(cli.AllowedGrantTypes, "password") {
		return nil, fmt.Errorf("%w: grant type not allowed for this client", ErrInvalidConfig)
	}

	// Validate user credentials
	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Validate requested scope
	if !s.validateScope(scope, cli.AllowedScopes) {
		return nil, ErrInvalidScopeRequest
	}

	// Generate tokens
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Hour)

	// Create session
	session := &UserSession{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		DeviceInfo:   "Direct Grant",
		IsRevoked:    false,
		Scope:        scope,
	}

	if err := s.userRepo.CreateSession(ctx, user.ID, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &api.TokenResponse{
		IDToken:      "",
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
	}, nil
}

// ClientCredentials implements the Client Credentials flow
func (s *OAuthService) ClientCredentials(ctx context.Context,
	clientID, clientSecret, scope string,
) (*api.TokenResponse, error) {
	// Validate cli
	cli, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// Check if client_credentials grant is allowed for this client
	if !contains(cli.AllowedGrantTypes, "client_credentials") {
		return nil, fmt.Errorf("%w: grant type not allowed for this client", ErrInvalidConfig)
	}

	// Validate requested scope
	if !s.validateScope(scope, cli.AllowedScopes) {
		return nil, ErrInvalidScopeRequest
	}

	// Generate the access token
	token, err := s.tokenService.CreateToken(ctx, CreateTokenOptions{
		TokenID:      uuid.NewString(),
		Scope:        scope,
		ClientID:     clientID,
		UserID:       "",
		TokenType:    api.TokenTypeAccessToken,
		ExpireIn:     time.Hour,
		SigningKeyID: "",
	}, nil)
	if err != nil {
		return nil, err
	}

	return &api.TokenResponse{
		IDToken:     "",
		AccessToken: token.TokenValue,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

// Helper function to validate scopes
func (s *OAuthService) validateScope(requestedScope string, allowedScopes []string) bool {
	if requestedScope == "" {
		return true
	}

	requested := strings.Split(requestedScope, " ")
	for _, req := range requested {
		found := false
		for _, allowed := range allowedScopes {
			if req == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *OAuthService) PasswordGrant(ctx context.Context,
	username, password, scope string, cli *client.Client,
) (*api.TokenResponse, error) {
	// Validate user credentials
	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// TODO: check if the user request for an id token
	// TODO: check the user if requests for a refresh token (offline_access)

	// Generate tokens
	return s.tokenService.GenerateTokenPair(ctx, cli.ID, user.ID, scope, time.Hour)
}

//nolint:funlen
func (s *OAuthService) ExchangeAuthorizationCode(ctx context.Context,
	code, clientID, clientSecret, redirectURI string,
) (*api.TokenResponse, error) {
	// Validate client
	if err := s.validateClient(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}

	// Validate authorization code
	authCode, err := s.oauthRepo.GetAuthCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code")
	}

	if authCode.Used || time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired or already used")
	}

	if authCode.ClientID != clientID || authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("invalid client or redirect URI")
	}

	// Mark code as used
	if err := s.oauthRepo.MarkAuthCodeAsUsed(ctx, code); err != nil {
		return nil, err
	}

	tokenResponse := new(api.TokenResponse)
	tokenResponse.TokenType = "Bearer"
	tokenResponse.ExpiresIn = 3600

	// Generate refresh token
	accessToken, err := s.tokenService.CreateToken(ctx, CreateTokenOptions{
		TokenID:      uuid.NewString(),
		Scope:        authCode.Scope,
		ClientID:     clientID,
		UserID:       authCode.UserID,
		TokenType:    api.TokenTypeRefreshToken,
		ExpireIn:     time.Hour, // 1 hour
		SigningKeyID: "",
	}, nil)
	if err != nil {
		return nil, err
	}

	tokenResponse.AccessToken = accessToken.TokenValue

	if contains(strings.Fields(authCode.Scope), "offline_access") {
		// Generate refresh token
		refreshToken, err := s.tokenService.CreateToken(ctx, CreateTokenOptions{
			TokenID:      uuid.NewString(),
			Scope:        authCode.Scope,
			ClientID:     clientID,
			UserID:       authCode.UserID,
			TokenType:    api.TokenTypeRefreshToken,
			ExpireIn:     time.Hour * 24 * 30, // 30 days
			SigningKeyID: "",
		}, nil)
		if err != nil {
			return nil, err
		}

		tokenResponse.RefreshToken = refreshToken.TokenValue
	}

	// Generate tokens
	return tokenResponse, nil
}

func (s *OAuthService) validateClient(ctx context.Context, clientID, clientSecret string) error {
	cli, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("invalid client: %w", err)
	}

	if cli.Secret != clientSecret {
		return ErrInvalidClientCredentials
	}

	return nil
}

// TokenIntrospection represents the response format defined in RFC 7662
//
//nolint:tagliatelle
type TokenIntrospection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

// InitiateDeviceAuthorization handles the device authorization request (RFC 8628, Section 3.1).
func (s *OAuthService) InitiateDeviceAuthorization(ctx context.Context, clientID string, scope string, verificationBaseURI string) (*api.DeviceAuthResponse, error) {
	// 1. Validate Client
	cli, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		// If client not found or other error
		return nil, serrors.NewInvalidClient("client not found or invalid")
	}

	// Check if client is allowed to use device_authorization grant type
	// A proper implementation should check `cli.AllowedGrantTypes` for "urn:ietf:params:oauth:grant-type:device_code"
	// For example:
	// if !contains(cli.AllowedGrantTypes, "urn:ietf:params:oauth:grant-type:device_code") {
	// 	return nil, serrors.NewUnsupportedGrantType("client not allowed to use device flow")
	// }
	_ = cli // Use cli to satisfy compiler until full validation is implemented

	// 2. Generate Codes
	deviceCodeVal, err := generateRandomString(deviceCodeLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate device_code: %w", err)
	}
	userCodeVal := generateUserCode(userCodeLength, userCodeCharset, userCodeChunkSize)

	// 3. Prepare DeviceCode struct
	expiresAt := time.Now().UTC().Add(deviceCodeLifetime)
	deviceAuth := &DeviceCode{ // Assuming DeviceCode is in the same package (ssso)
		ID:           uuid.NewString(),
		DeviceCode:   deviceCodeVal,
		UserCode:     userCodeVal,
		ClientID:     clientID,
		Scope:        scope,                   // TODO: Validate scope against client's allowed scopes and default scopes
		Status:       DeviceCodeStatusPending, // ssso.DeviceCodeStatusPending
		ExpiresAt:    expiresAt,
		Interval:     defaultPollInterval,
		CreatedAt:    time.Now().UTC(),
		LastPolledAt: time.Time{}, // Initialize as zero
	}

	// 4. Store DeviceCode
	// Ensure oauthRepo has SaveDeviceAuth method from the previous step.
	if err := s.oauthRepo.SaveDeviceAuth(ctx, deviceAuth); err != nil {
		return nil, fmt.Errorf("failed to save device authorization request: %w", err)
	}

	// 5. Prepare Response
	verificationURI := fmt.Sprintf("%s/device", verificationBaseURI) // e.g., "https://example.com/device"
	verificationURIComplete := fmt.Sprintf("%s?user_code=%s", verificationURI, userCodeVal)

	return &api.DeviceAuthResponse{
		DeviceCode:              deviceCodeVal,
		UserCode:                userCodeVal,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ExpiresIn:               int(deviceCodeLifetime.Seconds()),
		Interval:                defaultPollInterval,
	}, nil
}

// VerifyUserCode handles the user's attempt to authorize a device using a user_code.
// It links the user_code to the user's session/ID.
func (s *OAuthService) VerifyUserCode(ctx context.Context, userCode string, userID string) (*DeviceCode, error) {
	// 1. Retrieve DeviceCode by UserCode using the repository method
	// The repository method GetDeviceAuthByUserCode should ideally already check for expiry and pending status.
	// If not, those checks need to be here.
	deviceAuth, err := s.oauthRepo.GetDeviceAuthByUserCode(ctx, userCode)
	if err != nil {
		// This could be ErrUserCodeNotFound if the repo returns a specific error,
		// or a generic error if the lookup fails for other reasons.
		if err == serrors.ErrUserCodeNotFound { // Assuming ErrUserCodeNotFound is defined and used by the repo
			return nil, serrors.ErrUserCodeNotFound
		}
		return nil, fmt.Errorf("failed to retrieve device authorization by user code: %w", err)
	}

	// 2. Double-check status and expiry, though repository might have done some of this.
	//    This provides an additional layer of validation in the service.
	if deviceAuth.Status != DeviceCodeStatusPending {
		// If already authorized, denied, or redeemed.
		// Consider returning a specific error or message. For example, if already authorized by this user or another.
		return nil, serrors.ErrCannotApproveDeviceAuth // Or a more specific "already processed" error
	}

	if time.Now().UTC().After(deviceAuth.ExpiresAt) {
		// Though GetDeviceAuthByUserCode should ideally not return expired codes,
		// an extra check doesn't hurt, especially if there's a slight race condition.
		// Update status to expired if not already.
		_ = s.oauthRepo.UpdateDeviceAuthStatus(ctx, deviceAuth.DeviceCode, DeviceCodeStatusExpired)
		return nil, serrors.ErrUserCodeNotFound // Or ErrDeviceFlowTokenExpired
	}

	// 3. Call ApproveDeviceAuth to mark as authorized and associate userID
	// The ApproveDeviceAuth method in the repository should handle setting the status
	// to DeviceCodeStatusAuthorized and associating the userID.
	updatedDeviceAuth, err := s.oauthRepo.ApproveDeviceAuth(ctx, userCode, userID)
	if err != nil {
		// This could be ErrCannotApproveDeviceAuth if the repo returns that,
		// or a generic error.
		if err == serrors.ErrCannotApproveDeviceAuth {
			return nil, serrors.ErrCannotApproveDeviceAuth
		}
		return nil, fmt.Errorf("failed to approve device authorization: %w", err)
	}

	return updatedDeviceAuth, nil
}

// IssueTokenForDeviceFlow handles token requests for the device_code grant type (RFC 8628, Section 3.4 & 3.5).
func (s *OAuthService) IssueTokenForDeviceFlow(ctx context.Context, deviceCode string, clientID string) (*api.TokenResponse, error) {
	// 1. Retrieve DeviceCode by device_code
	deviceAuth, err := s.oauthRepo.GetDeviceAuthByDeviceCode(ctx, deviceCode)
	if err != nil {
		// It's good practice to check for specific errors from the repo if possible.
		// For example, if the repo returns serrors.ErrDeviceCodeNotFound specifically.
		// Using errors.Is here is for broader compatibility if the error is wrapped.
		if err == serrors.ErrDeviceCodeNotFound || (err != nil && strings.Contains(err.Error(), "not found")) { // Basic check
			return nil, serrors.ErrDeviceFlowTokenExpired // RFC: "expired_token" for invalid/expired device_code
		}
		return nil, fmt.Errorf("failed to retrieve device auth by device code: %w", err)
	}

	// 2. Validate ClientID
	if deviceAuth.ClientID != clientID {
		return nil, serrors.NewInvalidClient("client ID mismatch") // RFC: "invalid_client" or "invalid_grant"
	}

	// 3. Check DeviceCode Status
	switch deviceAuth.Status {
	case DeviceCodeStatusPending:
		// Update LastPolledAt. Important for rate limiting / slow_down logic.
		// We'll call this even if we return authorization_pending.
		// A real implementation of "slow_down" would check the interval *before* this update.
		if pollErr := s.oauthRepo.UpdateDeviceAuthLastPolledAt(ctx, deviceAuth.DeviceCode); pollErr != nil {
			// Log this error, but it's not fatal for returning authorization_pending.
			// Consider structured logging in a real application.
			fmt.Printf("Warning: failed to update last polled at for device code %s: %v\n", deviceAuth.DeviceCode, pollErr)
		}
		// RFC 8628: authorization_pending
		// Full "slow_down" logic would involve checking deviceAuth.LastPolledAt against deviceAuth.Interval
		// before this point and returning serrors.ErrSlowDown if necessary.
		return nil, serrors.ErrAuthorizationPending

	case DeviceCodeStatusAuthorized:
		// User has approved. Proceed to issue tokens.
		tokenResponse, tokenErr := s.tokenService.GenerateTokenPair(ctx, deviceAuth.ClientID, deviceAuth.UserID, deviceAuth.Scope, time.Hour) // Default 1 hour
		if tokenErr != nil {
			return nil, fmt.Errorf("failed to generate token pair for device flow: %w", tokenErr)
		}

		// Mark the device code as redeemed.
		if redeemErr := s.oauthRepo.UpdateDeviceAuthStatus(ctx, deviceAuth.DeviceCode, DeviceCodeStatusRedeemed); redeemErr != nil {
			// This is an internal server issue if it fails. Log it.
			// The token was issued, so we can't easily roll that back.
			// This might lead to the same device_code being used to get multiple tokens if not handled.
			// A robust system might have a retry mechanism or flag for cleanup.
			fmt.Printf("Critical Warning: failed to mark device code %s as redeemed after token issuance: %v\n", deviceAuth.DeviceCode, redeemErr)
		}
		return tokenResponse, nil

	case DeviceCodeStatusExpired:
		return nil, serrors.ErrDeviceFlowTokenExpired // RFC 8628: expired_token

	case DeviceCodeStatusDenied:
		return nil, serrors.ErrDeviceFlowAccessDenied // RFC 8628: access_denied

	case DeviceCodeStatusRedeemed:
		// This means the code was already used to issue tokens.
		// Treat as expired_token or invalid_grant as per RFC.
		return nil, serrors.ErrDeviceFlowTokenExpired

	default:
		// Unknown or unexpected status.
		return nil, serrors.NewServerError("unexpected device authorization status") // Or invalid_grant
	}
}

// IntrospectToken implements RFC 7662 Token Introspection
func (s *OAuthService) IntrospectToken(ctx context.Context,
	token, tokenTypeHint, clientID, clientSecret string,
) (*TokenIntrospection, error) { // TokenIntrospection is a local struct, not a DTO from outside.
	// Validate the requesting client
	if err := s.validateClient(ctx, clientID, clientSecret); err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	var tokenInfoDTO *dto.TokenInfoResponse // Changed to use DTO
	var err error

	// Use token_type_hint to optimize lookup
	switch tokenTypeHint {
	case "refresh_token":
		tokenInfoDTO, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
	case "access_token", "":
		tokenInfoDTO, err = s.tokenService.GetAccessTokenInfo(ctx, token)
		if err != nil && tokenTypeHint == "" {
			tokenInfoDTO, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
		}
	default:
		tokenInfoDTO, err = s.tokenService.GetAccessTokenInfo(ctx, token)
		if err != nil {
			tokenInfoDTO, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
		}
	}

	if err != nil {
		return &TokenIntrospection{Active: false}, nil
	}

	// Check if token is expired (using DTO fields)
	if time.Now().After(tokenInfoDTO.ExpiresAt) {
		return &TokenIntrospection{Active: false}, nil
	}

	var username string
	var userEmail string // Typically email is more common for "username" in OAuth contexts
	if tokenInfoDTO.UserID != "" {
		// userRepo is now UserServiceInternal, GetUserByID returns *dto.UserResponse
		userResp, userErr := s.userRepo.GetUserByID(ctx, tokenInfoDTO.UserID)
		if userErr == nil && userResp != nil {
			// Assuming UserResponse has Email or a Username field. Let's use Email.
			username = userResp.Email // Or userResp.Username if that exists
			userEmail = userResp.Email
			s.logger.Debug(ctx, "User details retrieved for introspection", map[string]interface{}{"userID": tokenInfoDTO.UserID, "email": userEmail})
		} else {
			s.logger.Warn(ctx, "IntrospectToken: Failed to get user details for active token", userErr, map[string]interface{}{"userID": tokenInfoDTO.UserID})
		}
	}

	// Populate TokenIntrospection struct (defined in this file)
	return &TokenIntrospection{
		Active:    true,
		Scope:     tokenInfoDTO.Scope,
		ClientID:  tokenInfoDTO.ClientID,
		Username:  username, // This is often the 'sub' or a preferred username. Using email here.
		TokenType: tokenInfoDTO.TokenType,
		Exp:       tokenInfoDTO.ExpiresAt.Unix(),
		Iat:       tokenInfoDTO.IssuedAt.Unix(),
		Sub:       tokenInfoDTO.UserID,
		Iss:       s.issuer,                              // Issuer from OAuthService config
		Jti:       tokenInfoDTO.ID,                       // Token ID
		Nbf:       tokenInfoDTO.IssuedAt.Unix(),          // Not Before, often same as Iat
		Aud:       tokenInfoDTO.ClientID,                 // Audience
		Email:     userEmail,                             // Example of adding other claims
		Roles:     strings.Join(tokenInfoDTO.Roles, " "), // Example: roles as space-separated string
	}, nil
}

// RevokeToken revokes a token.
// It implements RFC 7009 Token Revocation.
func (s *OAuthService) RevokeToken(ctx context.Context, tokenToRevoke, tokenTypeHint, clientID, clientSecret string) error {
	if err := s.validateClient(ctx, clientID, clientSecret); err != nil {
		return fmt.Errorf("invalid client: %w", err)
	}

	// According to RFC 7009, the server should return a 200 OK response even if the token is invalid.
	// So we ignore the error from RevokeToken and always return nil.
	// The primary purpose is to ensure the token, if valid and present, is marked as revoked.
	_ = s.tokenService.RevokeToken(ctx, tokenToRevoke) //nolint:errcheck

	return nil
}

// GenerateAuthCode generates a new authorization code for OAuth2 authorization code flow.
// It creates a secure random code and stores it with the provided client details.
func (s *OAuthService) GenerateAuthCode(ctx context.Context, clientID, redirectURI, scope string) (string, error) {
	// Generate secure random bytes for auth code
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	code := base64.StdEncoding.EncodeToString(b)

	// Create auth code record
	authCode := &AuthCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		CreatedAt:   time.Now(),
	}

	if err := s.oauthRepo.SaveAuthCode(ctx, authCode); err != nil {
		return "", fmt.Errorf("failed to save auth code: %w", err)
	}

	return code, nil
}

// GenerateTokens exchanges an authorization code for access and refresh tokens.
// It validates the code and client ID before generating new tokens.
func (s *OAuthService) GenerateTokens(ctx context.Context, code, clientID string) (*api.TokenResponse, error) {
	// Get and validate the stored auth code
	authCode, err := s.oauthRepo.GetAuthCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("invalid auth code: %w", err)
	}

	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("client ID mismatch")
	}

	if authCode.Used {
		return nil, fmt.Errorf("auth code already used")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("auth code expired")
	}

	// Generate new tokens
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Hour)

	// Create token record
	token := &Token{
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   clientID,
		Scope:      authCode.Scope,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	_ = token

	// if err := s.oauthRepo.StoreToken(ctx, token); err != nil {
	// 	return nil, fmt.Errorf("failed to store token: %w", err)
	// }

	// Mark auth code as used
	if err := s.oauthRepo.MarkAuthCodeAsUsed(ctx, code); err != nil {
		return nil, fmt.Errorf("failed to mark auth code as used: %w", err)
	}

	return &api.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
	}, nil
}

// GetUserInfo retrieves user information for a valid access token.
// It now returns api.UserInfo as expected by handlers, mapped from dto.UserResponse.
func (s *OAuthService) GetUserInfo(ctx context.Context, tokenValue string) (*api.UserInfo, error) {
	validatedToken, err := s.tokenService.ValidateAccessToken(ctx, tokenValue)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}
	if validatedToken == nil || validatedToken.UserID == "" {
		return nil, errors.New("token validation failed to yield user ID")
	}

	// userRepo is UserServiceInternal, GetUserByID returns *dto.UserResponse
	userResp, err := s.userRepo.GetUserByID(ctx, validatedToken.UserID)
	if err != nil {
		s.logger.Error(ctx, "GetUserInfo: Failed to retrieve user details", err, map[string]interface{}{"userID": validatedToken.UserID})
		return nil, fmt.Errorf("could not retrieve user information: %w", err)
	}

	if userResp == nil {
		s.logger.Error(ctx, "GetUserInfo: User not found though token was valid", errors.New("user not found post validation"), map[string]interface{}{"userID": validatedToken.UserID})
		return nil, errors.New("user not found though token was valid")
	}
	s.logger.Info(ctx, "Successfully retrieved user information for GetUserInfo", map[string]interface{}{"userID": userResp.ID, "email": userResp.Email})

	// Map dto.UserResponse to api.UserInfo
	// This is a simplified mapping. A full OIDC implementation would consider scopes
	// to determine which claims to include.
	apiUserInfo := &api.UserInfo{
		Sub:               userResp.ID,
		Name:              toPtr(userResp.FirstName + " " + userResp.LastName), // Example combination
		GivenName:         toPtr(userResp.FirstName),
		FamilyName:        toPtr(userResp.LastName),
		PreferredUsername: toPtr(userResp.Email), // Often email is used as preferred_username
		Email:             toPtr(userResp.Email),
		// EmailVerified: userResp.EmailVerified, // Assuming UserResponse has this
		// UpdatedAt: &userResp.UpdatedAt.Unix(), // api.UserInfo expects *int64 for UpdatedAt
		// Roles: userResp.Roles, // api.UserInfo doesn't have roles directly, often custom claim
	}
	updatedAtUnix := userResp.UpdatedAt.Unix()
	apiUserInfo.UpdatedAt = &updatedAtUnix

	// Example: Add custom claims if needed, based on scope or other logic
	// customClaims := map[string]interface{}{
	// 	"roles": userResp.Roles,
	// }
	// For OIDC UserInfo, standard claims are added directly. Custom claims might be namespaced.

	return apiUserInfo, nil
}

// Helper to convert string to *string, useful for optional fields in api.UserInfo
func toPtr(s string) *string {
	if s == "" { // Or based on other conditions if an empty string is valid but should be omitted
		return nil
	}
	return &s
}

// Example of adding a field to TokenIntrospection if it's not there.
// This is just to make the file compile if the diff introduces a new field.
// This struct is local to this file.
type TokenIntrospection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"` // Typically subject's username
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`   // Expiration time, seconds since epoch
	Iat       int64  `json:"iat,omitempty"`   // Issued at time, seconds since epoch
	Nbf       int64  `json:"nbf,omitempty"`   // Not before time, seconds since epoch
	Sub       string `json:"sub,omitempty"`   // Subject identifier (usually user ID)
	Aud       string `json:"aud,omitempty"`   // Audience (usually client ID)
	Iss       string `json:"iss,omitempty"`   // Issuer URL
	Jti       string `json:"jti,omitempty"`   // JWT ID (token ID)
	Email     string `json:"email,omitempty"` // Example custom claim
	Roles     string `json:"roles,omitempty"` // Example custom claim (space-separated)
}
