package ssso

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/client"
	"golang.org/x/crypto/bcrypt"
)

type OAuthService struct {
	oauthRepo  OAuthRepository
	userRepo   UserRepository
	signingKey *rsa.PrivateKey
	keyID      string
	issuer     string
}

func NewOAuthService(oauthRepo OAuthRepository, userRepo UserRepository, signingKey *rsa.PrivateKey, issuer string) *OAuthService {
	return &OAuthService{
		oauthRepo:  oauthRepo,
		userRepo:   userRepo,
		signingKey: signingKey,
		keyID:      uuid.NewString(),
		issuer:     issuer,
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

func (s *OAuthService) Login(ctx context.Context, username, password, deviceInfo string) (*TokenResponse, error) {
	// Search for the user
	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password")
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

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
	}, nil
}

// Új metódus a felhasználó session-jeinek lekérdezéséhez
func (s *OAuthService) GetUserSessions(ctx context.Context, userID string) ([]UserSession, error) {
	return s.userRepo.GetUserSessions(ctx, userID)
}

// Token frissítése
func (s *OAuthService) RefreshToken(ctx context.Context, refreshToken string, clientID string) (*TokenResponse, error) {
	session, err := s.userRepo.GetSessionByToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if session.IsRevoked || time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("token expired or revoked")
	}

	// Új tokenek generálása
	newAccessToken := uuid.NewString()
	newRefreshToken := uuid.NewString()
	newExpiresAt := time.Now().Add(time.Hour)

	// Session frissítése
	session.AccessToken = newAccessToken
	session.RefreshToken = newRefreshToken
	session.ExpiresAt = newExpiresAt
	session.LastUsedAt = time.Now()

	if err := s.userRepo.UpdateSessionLastUsed(ctx, session.ID); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	// Token tárolása az OAuth rendszerben
	token := &Token{
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: newAccessToken,
		ClientID:   clientID,
		UserID:     session.UserID,
		ExpiresAt:  newExpiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(ctx, token); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  newAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: newRefreshToken,
	}, nil
}

// Session visszavonása (kijelentkezés)
func (s *OAuthService) RevokeSession(ctx context.Context, sessionID string) error {
	return s.userRepo.RevokeSession(ctx, sessionID)
}

// Lejárt session-ök törlése
func (s *OAuthService) CleanupExpiredSessions(ctx context.Context, userID string) error {
	return s.userRepo.DeleteExpiredSessions(ctx, userID)
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (s *OAuthService) GetJWKS() JWKS {
	// A privát kulcsot a service inicializálásakor kell beállítani
	publicKey, _ := s.signingKey.Public().(*rsa.PublicKey)

	// RSA kulcs komponensek Base64URL kódolása
	exp := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
	mod := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())

	return JWKS{
		Keys: []JWK{
			{
				Kid: s.keyID, // Unique Key ID
				Kty: "RSA",   // Key Type
				Alg: "RS256", // Algorithm
				Use: "sig",   // Usage (signature)
				N:   mod,     // Modulus
				E:   exp,     // Exponent
			},
		},
	}
}

// Additional methods for OAuthService
func (s *OAuthService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	cli, err := s.oauthRepo.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	// Compare client secret using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(cli.Secret), []byte(clientSecret)) != 1 {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return cli, nil
}

// DirectGrant implements the Resource Owner Password Credentials flow
func (s *OAuthService) DirectGrant(ctx context.Context,
	clientID, clientSecret, username, password, scope string,
) (*TokenResponse, error) {
	// Validate client
	client, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// Check if password grant is allowed for this client
	if !contains(client.GrantTypes, "password") {
		return nil, fmt.Errorf("grant type not allowed for this client")
	}

	// Validate user credentials
	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Validate requested scope
	if !s.validateScope(scope, client.Scopes) {
		return nil, fmt.Errorf("invalid scope requested")
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
	}

	if err := s.userRepo.CreateSession(ctx, user.ID, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

// ClientCredentials implements the Client Credentials flow
func (s *OAuthService) ClientCredentials(ctx context.Context, clientID, clientSecret, scope string) (*TokenResponse, error) {
	// Validate client
	client, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// Check if client_credentials grant is allowed for this client
	if !contains(client.GrantTypes, "client_credentials") {
		return nil, fmt.Errorf("grant type not allowed for this client")
	}

	// Validate requested scope
	if !s.validateScope(scope, client.Scopes) {
		return nil, fmt.Errorf("invalid scope requested")
	}

	// Generate access token (no refresh token for client credentials)
	accessToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Hour)

	// Store the token
	token := &Token{
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   clientID,
		UserID:     "",
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(ctx, token); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       scope,
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

func (s *OAuthService) PasswordGrant(ctx context.Context, username, password, scope string, cli *client.Client) (*TokenResponse, error) {
	// Validate user credentials
	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate tokens
	return s.generateUserTokens(ctx, user.ID, cli.ID, scope)
}

func (s *OAuthService) ClientCredentialsGrant(ctx context.Context, clientID, clientSecret, scope string) (*TokenResponse, error) {
	// Validate client
	if err := s.validateClient(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}

	// Generate client-only token (no refresh token)
	accessToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Hour)

	token := &Token{
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   clientID,
		UserID:     "",
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(ctx, token); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       scope,
	}, nil
}

func (s *OAuthService) ExchangeAuthorizationCode(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*TokenResponse, error) {
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

	// Generate tokens
	return s.generateUserTokens(ctx, "", clientID, authCode.Scope)
}

func (s *OAuthService) validateClient(ctx context.Context, clientID, clientSecret string) error {
	client, err := s.oauthRepo.GetClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("invalid client")
	}

	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
		return fmt.Errorf("invalid client credentials")
	}

	return nil
}

func (s *OAuthService) generateUserTokens(ctx context.Context, userID, clientID, scope string) (*TokenResponse, error) {
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Hour)

	token := &Token{
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   clientID,
		UserID:     userID,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(ctx, token); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

// TokenIntrospection represents the response format defined in RFC 7662
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
func (s *OAuthService) IntrospectToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*TokenIntrospection, error) {
	// Validate the requesting client
	if err := s.validateClient(ctx, clientID, clientSecret); err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	var tokenInfo *TokenInfo
	var err error

	// Use token_type_hint to optimize lookup
	switch tokenTypeHint {
	case "refresh_token":
		tokenInfo, err = s.oauthRepo.GetRefreshTokenInfo(ctx, token)
	case "access_token", "":
		tokenInfo, err = s.oauthRepo.GetAccessTokenInfo(ctx, token)
		if err != nil && tokenTypeHint == "" {
			// If no hint was provided, try refresh token as fallback
			tokenInfo, err = s.oauthRepo.GetRefreshTokenInfo(ctx, token)
		}
	default:
		// Unknown token type hint, try both
		tokenInfo, err = s.oauthRepo.GetAccessTokenInfo(ctx, token)
		if err != nil {
			tokenInfo, err = s.oauthRepo.GetRefreshTokenInfo(ctx, token)
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
	}, nil
}
