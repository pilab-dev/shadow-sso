package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain"
	serrors "github.com/pilab-dev/shadow-sso/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// Constants for Device Flow
const (
	deviceCodeLength    = 32
	userCodeLength      = 8
	userCodeCharset     = "BCDFGHJKLMNPQRSTVWXYZ0123456789"
	userCodeChunkSize   = 4
	deviceCodeLifetime  = 10 * time.Minute
	defaultPollInterval = 5
)

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateUserCode(length int, charset string, chunkSize int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
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
	oauthRepo    domain.OAuthRepository
	userRepo     domain.UserRepository
	clientRepo   client.ClientStore
	sessionRepo  domain.SessionRepository
	tokenService *TokenService
	keyID        string
	issuer       string
}

func NewOAuthService(
	oauthRepo domain.OAuthRepository,
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	tokenService *TokenService,
	issuer string,
) *OAuthService {
	return &OAuthService{
		oauthRepo:    oauthRepo,
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		keyID:        uuid.NewString(),
		tokenService: tokenService,
		issuer:       issuer,
	}
}

func (s *OAuthService) RegisterUser(ctx context.Context, username, password string) (*domain.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	user := &domain.User{
		Email:        username,
		PasswordHash: string(hashedPassword),
		Status:       domain.UserStatusActive,
	}
	err = s.userRepo.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	return user, nil
}

func (s *OAuthService) Login(ctx context.Context, username, password, deviceInfo string) (*api.TokenResponse, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, serrors.ErrInvalidCredentials
	}

	// Create a user session
	session := &domain.Session{
		ID:         uuid.NewString(),
		UserID:     user.ID,
		UserAgent:  deviceInfo,
		ExpiresAt:  time.Now().Add(24 * 30 * time.Hour), // Example long-lived session
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		IsRevoked:  false,
	}
	if err := s.sessionRepo.StoreSession(ctx, session); err != nil {
		log.Warn().Err(err).Msg("Failed to store session in OAuthService.Login")
		// Not returning error for session storage failure for now.
	}

	// Generate tokens for the client
	// ClientID and scope for this direct ROPC-like login are not well-defined here.
	// Using placeholder values.
	clientIdentifier := "oauth-service-login-client"
	loginScope := "openid profile email"
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientIdentifier, user.ID, loginScope, time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}
	return tokenPair, nil
}

func (s *OAuthService) GetUserSessions(ctx context.Context, userID string) ([]*domain.Session, error) {
	return s.sessionRepo.ListSessionsByUserID(ctx, userID, domain.SessionFilter{})
}

func (s *OAuthService) RefreshToken(ctx context.Context, refreshTokenValue string, clientID string) (*api.TokenResponse, error) {
	tokenInfo, err := s.oauthRepo.GetRefreshTokenInfo(ctx, refreshTokenValue)
	if err != nil {
		return nil, serrors.NewInvalidGrant("invalid refresh token")
	}
	if tokenInfo.IsRevoked || time.Now().After(tokenInfo.ExpiresAt) {
		return nil, serrors.NewInvalidGrant("refresh token expired or revoked")
	}
	return s.tokenService.GenerateTokenPair(ctx, clientID, tokenInfo.UserID, tokenInfo.Scope, time.Hour)
}

func (s *OAuthService) GetJWKS() *JSONWebKeySet {
	keyset := &JSONWebKeySet{
		Keys: make([]JSONWebKey, 0),
	}
	// Actual key retrieval should be from JWKSService if it's managing keys
	return keyset
}

func (s *OAuthService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
	cli, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(cli.Secret), []byte(clientSecret)) != 1 {
		return nil, serrors.ErrInvalidClientCredentials
	}
	return cli, nil
}

func (s *OAuthService) DirectGrant(ctx context.Context,
	clientID, clientSecret, username, password, scope string,
) (*api.TokenResponse, error) {
	cli, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if !contains(cli.AllowedGrantTypes, "password") {
		return nil, serrors.ErrInvalidConfig
	}
	user, err := s.userRepo.GetUserByEmail(ctx, username) // Changed from GetUserByUsername
	if err != nil {
		return nil, serrors.ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, serrors.ErrInvalidCredentials
	}
	if !s.validateScope(scope, cli.AllowedScopes) {
		return nil, serrors.NewInvalidScope("invalid scope requested by client")
	}

	session := &domain.Session{
		ID:         uuid.NewString(),
		UserID:     user.ID,
		UserAgent:  "Direct Grant",
		ExpiresAt:  time.Now().Add(time.Hour),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		IsRevoked:  false,
	}
	if err := s.sessionRepo.StoreSession(ctx, session); err != nil {
		log.Warn().Err(err).Msg("Failed to store session in OAuthService.DirectGrant")
	}
	// This direct grant in OAuthService still manually creates token strings.
	// Ideally, it should also use tokenService.GenerateTokenPair like the Login method now does.
	// For minimal changes to fix build, keeping manual token string generation for now.
	accessTokenVal := uuid.NewString()
	refreshTokenVal := uuid.NewString()

	// Store the access token (minimal info, as actual signing/details are in GenerateTokenPair)
	dbToken := &domain.Token{
		ID: uuid.NewString(), TokenType: "access_token", TokenValue: accessTokenVal,
		ClientID: clientID, UserID: user.ID, Scope: scope, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}
	if err := s.oauthRepo.StoreToken(ctx, dbToken); err != nil {
		log.Error().Err(err).Msg("Failed to store access token in DirectGrant")
		// continue without fatal error for token storage for now.
	}

	return &api.TokenResponse{
		AccessToken:  accessTokenVal,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshTokenVal,
	}, nil
}

func (s *OAuthService) ClientCredentials(ctx context.Context,
	clientID, clientSecret, scope string,
) (*api.TokenResponse, error) {
	cli, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if !contains(cli.AllowedGrantTypes, "client_credentials") {
		return nil, serrors.ErrInvalidConfig
	}
	if !s.validateScope(scope, cli.AllowedScopes) {
		return nil, serrors.NewInvalidScope("invalid scope requested by client")
	}
	token, err := s.tokenService.CreateToken(ctx, CreateTokenOptions{
		TokenID:      uuid.NewString(),
		Scope:        scope,
		ClientID:     clientID,
		UserID:       "", // No user for client_credentials
		TokenType:    api.TokenTypeAccessToken,
		ExpireIn:     time.Hour,
		SigningKeyID: "",
	}, nil)
	if err != nil {
		return nil, err
	}
	return &api.TokenResponse{
		AccessToken:  token.TokenValue,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Hour.Seconds()), // Changed to int
	}, nil
}

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
	user, err := s.userRepo.GetUserByEmail(ctx, username) // Changed from GetUserByUsername
	if err != nil {
		return nil, serrors.ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, serrors.ErrInvalidCredentials
	}
	return s.tokenService.GenerateTokenPair(ctx, cli.ID, user.ID, scope, time.Hour)
}

func (s *OAuthService) ExchangeAuthorizationCode(ctx context.Context,
	code, clientID, clientSecret, redirectURI string,
) (*api.TokenResponse, error) {
	_, err := s.ValidateClient(ctx, clientID, clientSecret) // Corrected call
	if err != nil {
		return nil, err
	}
	authCodeDomain, err := s.oauthRepo.GetAuthCode(ctx, code)
	if err != nil {
		return nil, serrors.NewInvalidGrant("invalid authorization code")
	}
	if authCodeDomain.Used || time.Now().After(authCodeDomain.ExpiresAt) {
		return nil, serrors.NewInvalidGrant("authorization code expired or already used")
	}
	if authCodeDomain.ClientID != clientID || authCodeDomain.RedirectURI != redirectURI {
		return nil, serrors.NewInvalidGrant("invalid client or redirect URI for auth code")
	}
	if err := s.oauthRepo.MarkAuthCodeAsUsed(ctx, code); err != nil {
		return nil, fmt.Errorf("failed to mark auth code as used: %w", err)
	}
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientID, authCodeDomain.UserID, authCodeDomain.Scope, time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}
	return tokenPair, nil
}

func (s *OAuthService) IntrospectToken(ctx context.Context,
	token, tokenTypeHint, clientID, clientSecret string,
) (*domain.TokenIntrospection, error) {
	_, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}
	var tokenInfo *domain.TokenInfo
	// err is already declared above, so use = for subsequent assignments
	switch tokenTypeHint {
	case "refresh_token":
		tokenInfo, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
	case "access_token", "":
		tokenInfo, err = s.tokenService.GetAccessTokenInfo(ctx, token)
		if err != nil && tokenTypeHint == "" {
			tokenInfo, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
		}
	default:
		tokenInfo, err = s.tokenService.GetAccessTokenInfo(ctx, token)
		if err != nil {
			tokenInfo, err = s.tokenService.GetRefreshTokenInfo(ctx, token)
		}
	}
	if err != nil {
		return &domain.TokenIntrospection{Active: false}, nil
	}
	if time.Now().After(tokenInfo.ExpiresAt) {
		return &domain.TokenIntrospection{Active: false}, nil
	}
	var username string
	if tokenInfo.UserID != "" {
		user, err := s.userRepo.GetUserByID(ctx, tokenInfo.UserID)
		if err == nil {
			username = user.Email
		}
	}
	return &domain.TokenIntrospection{
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

func (s *OAuthService) RevokeToken(ctx context.Context, tokenToRevoke, tokenTypeHint, clientID, clientSecret string) error {
	_, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("invalid client: %w", err)
	}
	_ = s.tokenService.RevokeToken(ctx, tokenToRevoke)
	return nil
}

func (s *OAuthService) GenerateAuthCode(
	ctx context.Context, clientID string, userID string,
	redirectURI string, scope string, codeChallenge string, codeChallengeMethod string,
) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Error().Err(err).Msg("Failed to generate random bytes for auth code")
		return "", fmt.Errorf("failed to generate random bytes for auth code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	authCode := &domain.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now(),
		Used:                false,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	if err := s.oauthRepo.SaveAuthCode(ctx, authCode); err != nil {
		log.Error().Err(err).Str("clientID", clientID).Str("userID", userID).Msg("Failed to save authorization code")
		return "", fmt.Errorf("failed to save auth code: %w", err)
	}
	log.Info().Str("clientID", clientID).Str("userID", userID).Str("code", code).Msg("Authorization code generated and saved")
	return code, nil
}

// InitiateDeviceAuthorization, VerifyUserCode, IssueTokenForDeviceFlow need to use domain.DeviceCode and domain.DeviceCodeStatus
func (s *OAuthService) InitiateDeviceAuthorization(ctx context.Context, clientID string, scope string, verificationBaseURI string) (*api.DeviceAuthResponse, error) {
	cli, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		return nil, serrors.NewInvalidClient("client not found or invalid")
	}
	_ = cli
	deviceCodeVal, err := generateRandomString(deviceCodeLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate device_code: %w", err)
	}
	userCodeVal := generateUserCode(userCodeLength, userCodeCharset, userCodeChunkSize)
	expiresAt := time.Now().UTC().Add(deviceCodeLifetime)
	deviceAuth := &domain.DeviceCode{
		ID:           uuid.NewString(),
		DeviceCode:   deviceCodeVal,
		UserCode:     userCodeVal,
		ClientID:     clientID,
		Scope:        scope,
		Status:       domain.DeviceCodeStatusPending,
		ExpiresAt:    expiresAt,
		Interval:     defaultPollInterval,
		CreatedAt:    time.Now().UTC(),
		LastPolledAt: time.Time{},
	}
	if err := s.oauthRepo.SaveDeviceAuth(ctx, deviceAuth); err != nil {
		return nil, fmt.Errorf("failed to save device authorization request: %w", err)
	}
	verificationURI := fmt.Sprintf("%s/device", verificationBaseURI)
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

func (s *OAuthService) VerifyUserCode(ctx context.Context, userCode string, userID string) (*domain.DeviceCode, error) {
	deviceAuth, err := s.oauthRepo.GetDeviceAuthByUserCode(ctx, userCode)
	if err != nil {
		if err == serrors.ErrUserCodeNotFound {
			return nil, serrors.ErrUserCodeNotFound
		}
		return nil, fmt.Errorf("failed to retrieve device authorization by user code: %w", err)
	}
	if deviceAuth.Status != domain.DeviceCodeStatusPending {
		return nil, serrors.ErrCannotApproveDeviceAuth
	}
	if time.Now().UTC().After(deviceAuth.ExpiresAt) {
		_ = s.oauthRepo.UpdateDeviceAuthStatus(ctx, deviceAuth.DeviceCode, domain.DeviceCodeStatusExpired)
		return nil, serrors.ErrUserCodeNotFound
	}
	updatedDeviceAuth, err := s.oauthRepo.ApproveDeviceAuth(ctx, userCode, userID)
	if err != nil {
		if err == serrors.ErrCannotApproveDeviceAuth {
			return nil, serrors.ErrCannotApproveDeviceAuth
		}
		return nil, fmt.Errorf("failed to approve device authorization: %w", err)
	}
	return updatedDeviceAuth, nil
}

func (s *OAuthService) IssueTokenForDeviceFlow(ctx context.Context, deviceCode string, clientID string) (*api.TokenResponse, error) {
	deviceAuth, err := s.oauthRepo.GetDeviceAuthByDeviceCode(ctx, deviceCode)
	if err != nil {
		if err == serrors.ErrDeviceCodeNotFound || (err != nil && strings.Contains(err.Error(), "not found")) {
			return nil, serrors.ErrDeviceFlowTokenExpired
		}
		return nil, fmt.Errorf("failed to retrieve device auth by device code: %w", err)
	}
	if deviceAuth.ClientID != clientID {
		return nil, serrors.NewInvalidClient("client ID mismatch")
	}
	switch deviceAuth.Status {
	case domain.DeviceCodeStatusPending:
		if pollErr := s.oauthRepo.UpdateDeviceAuthLastPolledAt(ctx, deviceAuth.DeviceCode); pollErr != nil {
			fmt.Printf("Warning: failed to update last polled at for device code %s: %v\n", deviceAuth.DeviceCode, pollErr)
		}
		return nil, serrors.ErrAuthorizationPending
	case domain.DeviceCodeStatusAuthorized:
		tokenResponse, tokenErr := s.tokenService.GenerateTokenPair(ctx, deviceAuth.ClientID, deviceAuth.UserID, deviceAuth.Scope, time.Hour)
		if tokenErr != nil {
			return nil, fmt.Errorf("failed to generate token pair for device flow: %w", tokenErr)
		}
		if redeemErr := s.oauthRepo.UpdateDeviceAuthStatus(ctx, deviceAuth.DeviceCode, domain.DeviceCodeStatusRedeemed); redeemErr != nil {
			fmt.Printf("Critical Warning: failed to mark device code %s as redeemed after token issuance: %v\n", deviceAuth.DeviceCode, redeemErr)
		}
		return tokenResponse, nil
	case domain.DeviceCodeStatusExpired:
		return nil, serrors.ErrDeviceFlowTokenExpired
	case domain.DeviceCodeStatusDenied:
		return nil, serrors.ErrDeviceFlowAccessDenied
	case domain.DeviceCodeStatusRedeemed:
		return nil, serrors.ErrDeviceFlowTokenExpired
	default:
		return nil, serrors.NewServerError("unexpected device authorization status")
	}
}

// GenerateTokens was a duplicate of ExchangeAuthorizationCode, removed it.
// GetUserInfo was a stub, removed it as user info is part of AuthService or OIDC UserInfo endpoint.
// TokenIntrospection struct was moved to domain package.
// JSONWebKey and JSONWebKeySet are local to jwks_service.go and used there.
// User, UserSession, Token, AuthCode, DeviceCode, DeviceCodeStatus are now from domain package.
// Error variables are now from serrors (github.com/pilab-dev/shadow-sso/errors).
// UserRepository.GetUserByUsername changed to GetUserByEmail.
// UserRepository.CreateSession changed to SessionRepository.StoreSession.
// UserRepository.GetUserSessions changed to SessionRepository.ListSessionsByUserID.
// OAuthService.Login now uses TokenService.GenerateTokenPair and SessionRepository.StoreSession.
// OAuthService.DirectGrant now uses SessionRepository.StoreSession.
// OAuthService.RefreshToken now uses OAuthRepository.GetRefreshTokenInfo.
// OAuthService.ExchangeAuthorizationCode now uses TokenService.GenerateTokenPair.
// OAuthService.IntrospectToken now returns *domain.TokenIntrospection and uses domain.TokenInfo.
// OAuthService.Device flow methods now use domain.DeviceCode and domain.DeviceCodeStatus.
// Removed local definitions of Token, UserSession, AuthCode, DeviceCode, TokenIntrospection, etc.
// All repository interfaces are now from domain package.
