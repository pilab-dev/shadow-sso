package ssso

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/client"
	"golang.org/x/crypto/bcrypt"
)

type OAuthService struct {
	oauthRepo    OAuthRepository
	userRepo     UserStore
	clientRepo   client.ClientStore
	tokenService *TokenService
	keyID        string
	issuer       string
}

// NewOAuthService creates a new instance of the OAuthService.
func NewOAuthService(
	oauthRepo OAuthRepository,
	userRepo UserStore,
	tokenService *TokenService,
	issuer string,
) *OAuthService {
	return &OAuthService{
		oauthRepo:    oauthRepo,
		userRepo:     userRepo,
		keyID:        uuid.NewString(), // ! This must be refactored to keystore or something.
		tokenService: tokenService,
		issuer:       issuer,
	}
}

func (s *OAuthService) RegisterUser(ctx context.Context, username, password string) (*User, error) {
	// Hashing password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the user
	user, err := s.userRepo.CreateUser(ctx, username, string(hashedPassword))
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// func (s *OAuthService) Login(ctx context.Context, username, password, deviceInfo string) (*TokenResponse, error) {
// 	// Search for the user
// 	user, err := s.userRepo.GetUserByUsername(ctx, username)
// 	if err != nil {
// 		return nil, fmt.Errorf("user not found: %w", err)
// 	}

// 	// Check password
// 	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
// 		return nil, ErrInvalidCredentials
// 	}

// 	// Generate token and session
// 	accessToken := uuid.NewString()
// 	refreshToken := uuid.NewString()
// 	expiresAt := time.Now().Add(time.Hour)

// 	session := &UserSession{
// 		ID:           uuid.NewString(),
// 		UserID:       user.ID,
// 		AccessToken:  accessToken,
// 		RefreshToken: refreshToken,
// 		ExpiresAt:    expiresAt,
// 		CreatedAt:    time.Now(),
// 		LastUsedAt:   time.Now(),
// 		DeviceInfo:   deviceInfo,
// 		IsRevoked:    false,
// 	}

// 	// Save the generated session
// 	if err := s.userRepo.CreateSession(ctx, user.ID, session); err != nil {
// 		return nil, fmt.Errorf("failed to create session: %w", err)
// 	}

// 	// Store token in the database
// 	token := &Token{
// 		ID:         uuid.NewString(),
// 		TokenType:  "access_token",
// 		TokenValue: accessToken,
// 		ClientID:   "",
// 		UserID:     user.ID,
// 		ExpiresAt:  expiresAt,
// 		CreatedAt:  time.Now(),
// 		LastUsedAt: time.Now(),
// 	}
// 	if err := s.oauthRepo.StoreToken(ctx, token); err != nil {
// 		return nil, fmt.Errorf("failed to store token: %w", err)
// 	}

// 	return &TokenResponse{
// 		AccessToken:  accessToken,
// 		TokenType:    "Bearer",
// 		ExpiresIn:    3600,
// 		RefreshToken: refreshToken,
// 	}, nil
// }

// GetUserSessions retrieves all active sessions for a user.
func (s *OAuthService) GetUserSessions(ctx context.Context, userID string) ([]UserSession, error) {
	return s.userRepo.GetUserSessions(ctx, userID)
}

// TokenRefresh refreshes the access token with the refresh token.
func (s *OAuthService) RefreshToken(ctx context.Context, refreshToken string, clientID string) (*TokenResponse, error) {
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
) (*TokenResponse, error) {
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

	return &TokenResponse{
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
) (*TokenResponse, error) {
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
		TokenType:    TokenTypeAccessToken,
		ExpireIn:     time.Hour,
		SigningKeyID: "",
	}, nil)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
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
) (*TokenResponse, error) {
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
) (*TokenResponse, error) {
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

	tokenResponse := new(TokenResponse)
	tokenResponse.TokenType = "Bearer"
	tokenResponse.ExpiresIn = 3600

	// Generate refresh token
	accessToken, err := s.tokenService.CreateToken(ctx, CreateTokenOptions{
		TokenID:      uuid.NewString(),
		Scope:        authCode.Scope,
		ClientID:     clientID,
		UserID:       authCode.UserID,
		TokenType:    TokenTypeRefreshToken,
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
			TokenType:    TokenTypeRefreshToken,
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

// IntrospectToken implements RFC 7662 Token Introspection
func (s *OAuthService) IntrospectToken(ctx context.Context,
	token, tokenTypeHint, clientID, clientSecret string,
) (*TokenIntrospection, error) {
	// Validate the requesting client
	if err := s.validateClient(ctx, clientID, clientSecret); err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	var tokenInfo *TokenInfo
	var err error

	// Use token_type_hint to optimize lookup
	switch tokenTypeHint {
	case "refresh_token":
		tokenInfo, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
	case "access_token", "":
		tokenInfo, err = s.tokenService.GetAccessTokenInfo(ctx, token)
		if err != nil && tokenTypeHint == "" {
			// If no hint was provided, try refresh token as fallback
			tokenInfo, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
		}
	default:
		// Unknown token type hint, try both
		tokenInfo, err = s.tokenService.GetAccessTokenInfo(ctx, token)
		if err != nil {
			tokenInfo, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
		}
	}

	if err != nil {
		return &TokenIntrospection{Active: false}, nil
	}

	// Check if token is expired
	if time.Now().After(tokenInfo.ExpiresAt) {
		return &TokenIntrospection{Active: false}, nil
	}

	// If we have user info, get username
	var username string
	if tokenInfo.UserID != "" {
		user, err := s.userRepo.GetUserByID(ctx, tokenInfo.UserID)
		if err == nil {
			username = user.Username
		}
	}

	return &TokenIntrospection{
		Active:    true,
		Scope:     tokenInfo.Scope,
		ClientID:  tokenInfo.ClientID,
		Username:  username,
		TokenType: tokenInfo.TokenType,
		Exp:       tokenInfo.ExpiresAt.Unix(),
		Iat:       tokenInfo.IssuedAt.Unix(),
		Sub:       tokenInfo.UserID,
		Iss:       s.issuer,
		Jti:       tokenInfo.ID,
		Nbf:       tokenInfo.IssuedAt.Unix(),
		Aud:       tokenInfo.ClientID,
	}, nil
}
