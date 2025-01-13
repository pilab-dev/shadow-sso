package ssso

import (
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
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
		keyID:      uuid.New().String(),
		issuer:     issuer,
	}
}

func (s *OAuthService) RegisterUser(username, password string) (*User, error) {
	// Jelszó hash-elése
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Felhasználó létrehozása
	user, err := s.userRepo.CreateUser(username, string(hashedPassword))
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (s *OAuthService) Login(username, password, deviceInfo string) (*TokenResponse, error) {
	// Felhasználó keresése
	user, err := s.userRepo.GetUserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Jelszó ellenőrzése
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	// Token és Session generálás
	accessToken := uuid.New().String()
	refreshToken := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour)

	session := &UserSession{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		DeviceInfo:   deviceInfo,
		IsRevoked:    false,
	}

	// Session mentése
	if err := s.userRepo.CreateSession(user.ID, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Token tárolása az OAuth rendszerben is
	token := &Token{
		ID:         uuid.New().String(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   "",
		UserID:     user.ID,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(token); err != nil {
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
func (s *OAuthService) GetUserSessions(userID string) ([]UserSession, error) {
	return s.userRepo.GetUserSessions(userID)
}

// Token frissítése
func (s *OAuthService) RefreshToken(refreshToken string, clientID string) (*TokenResponse, error) {
	session, err := s.userRepo.GetSessionByToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if session.IsRevoked || time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("token expired or revoked")
	}

	// Új tokenek generálása
	newAccessToken := uuid.New().String()
	newRefreshToken := uuid.New().String()
	newExpiresAt := time.Now().Add(time.Hour)

	// Session frissítése
	session.AccessToken = newAccessToken
	session.RefreshToken = newRefreshToken
	session.ExpiresAt = newExpiresAt
	session.LastUsedAt = time.Now()

	if err := s.userRepo.UpdateSessionLastUsed(session.ID); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	// Token tárolása az OAuth rendszerben
	token := &Token{
		ID:         uuid.New().String(),
		TokenType:  "access_token",
		TokenValue: newAccessToken,
		ClientID:   clientID,
		UserID:     session.UserID,
		ExpiresAt:  newExpiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(token); err != nil {
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
func (s *OAuthService) RevokeSession(sessionID string) error {
	return s.userRepo.RevokeSession(sessionID)
}

// Lejárt session-ök törlése
func (s *OAuthService) CleanupExpiredSessions(userID string) error {
	return s.userRepo.DeleteExpiredSessions(userID)
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
	publicKey := s.signingKey.Public().(*rsa.PublicKey)

	// RSA kulcs komponensek Base64URL kódolása
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())

	return JWKS{
		Keys: []JWK{
			{
				Kid: s.keyID, // Egyedi kulcs azonosító
				Kty: "RSA",   // Key Type
				Alg: "RS256", // Algoritmus
				Use: "sig",   // Használat (signature)
				N:   n,       // Modulus
				E:   e,       // Exponent
			},
		},
	}
}

// Additional methods for OAuthService
func (s *OAuthService) ValidateClient(clientID, clientSecret string) (*Client, error) {
	client, err := s.oauthRepo.GetClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	// Compare client secret using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

// DirectGrant implements the Resource Owner Password Credentials flow
func (s *OAuthService) DirectGrant(clientID, clientSecret, username, password, scope string) (*TokenResponse, error) {
	// Validate client
	client, err := s.ValidateClient(clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// Check if password grant is allowed for this client
	if !contains(client.GrantTypes, "password") {
		return nil, fmt.Errorf("grant type not allowed for this client")
	}

	// Validate user credentials
	user, err := s.userRepo.GetUserByUsername(username)
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
	accessToken := uuid.New().String()
	refreshToken := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour)

	// Create session
	session := &UserSession{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		DeviceInfo:   "Direct Grant",
		IsRevoked:    false,
	}

	if err := s.userRepo.CreateSession(user.ID, session); err != nil {
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
func (s *OAuthService) ClientCredentials(clientID, clientSecret, scope string) (*TokenResponse, error) {
	// Validate client
	client, err := s.ValidateClient(clientID, clientSecret)
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
	accessToken := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour)

	// Store the token
	token := &Token{
		ID:         uuid.New().String(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   clientID,
		UserID:     "",
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(token); err != nil {
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

func (s *OAuthService) PasswordGrant(username, password, clientID, clientSecret, scope string) (*TokenResponse, error) {
	// Validate client
	if err := s.validateClient(clientID, clientSecret); err != nil {
		return nil, err
	}

	// Validate user credentials
	user, err := s.userRepo.GetUserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate tokens
	return s.generateUserTokens(user.ID, clientID, scope)
}

func (s *OAuthService) ClientCredentialsGrant(clientID, clientSecret, scope string) (*TokenResponse, error) {
	// Validate client
	if err := s.validateClient(clientID, clientSecret); err != nil {
		return nil, err
	}

	// Generate client-only token (no refresh token)
	accessToken := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour)

	token := &Token{
		ID:         uuid.New().String(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   clientID,
		UserID:     "",
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(token); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       scope,
	}, nil
}

func (s *OAuthService) ExchangeAuthorizationCode(code, clientID, clientSecret, redirectURI string) (*TokenResponse, error) {
	// Validate client
	if err := s.validateClient(clientID, clientSecret); err != nil {
		return nil, err
	}

	// Validate authorization code
	authCode, err := s.oauthRepo.GetAuthCode(code)
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
	if err := s.oauthRepo.MarkAuthCodeAsUsed(code); err != nil {
		return nil, err
	}

	// Generate tokens
	return s.generateUserTokens("", clientID, authCode.Scope)
}

func (s *OAuthService) validateClient(clientID, clientSecret string) error {
	client, err := s.oauthRepo.GetClient(clientID)
	if err != nil {
		return fmt.Errorf("invalid client")
	}

	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
		return fmt.Errorf("invalid client credentials")
	}

	return nil
}

func (s *OAuthService) generateUserTokens(userID, clientID, scope string) (*TokenResponse, error) {
	accessToken := uuid.New().String()
	refreshToken := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour)

	token := &Token{
		ID:         uuid.New().String(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   clientID,
		UserID:     userID,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(token); err != nil {
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
func (s *OAuthService) IntrospectToken(token, tokenTypeHint, clientID, clientSecret string) (*TokenIntrospection, error) {
	// Validate the requesting client
	if err := s.validateClient(clientID, clientSecret); err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	var tokenInfo *TokenInfo
	var err error

	// Use token_type_hint to optimize lookup
	switch tokenTypeHint {
	case "refresh_token":
		tokenInfo, err = s.oauthRepo.GetRefreshTokenInfo(token)
	case "access_token", "":
		tokenInfo, err = s.oauthRepo.GetAccessTokenInfo(token)
		if err != nil && tokenTypeHint == "" {
			// If no hint was provided, try refresh token as fallback
			tokenInfo, err = s.oauthRepo.GetRefreshTokenInfo(token)
		}
	default:
		// Unknown token type hint, try both
		tokenInfo, err = s.oauthRepo.GetAccessTokenInfo(token)
		if err != nil {
			tokenInfo, err = s.oauthRepo.GetRefreshTokenInfo(token)
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
		user, err := s.userRepo.GetUserByID(tokenInfo.UserID)
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
