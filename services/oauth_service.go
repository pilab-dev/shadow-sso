package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/domain"
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

type defaultOAuthService struct {
	tokenRepo      domain.TokenRepository
	authCodeRepo   domain.AuthorizationCodeRepository
	deviceAuthRepo domain.DeviceAuthorizationRepository
	clientRepo     domain.ClientRepository // Changed from client.ClientStore for consistency
	userRepo       domain.UserRepository
	sessionRepo    domain.SessionRepository
	tokenService   domain.TokenServiceInterface
	issuer         string
}

// tokenServiceAdapter wraps the services.TokenService interface to satisfy domain.TokenServiceInterface
type tokenServiceAdapter struct {
	TokenService
}

func (a *tokenServiceAdapter) GenerateTokenPairWithFamily(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration, family string, nonce string, authTime time.Time) (*api.TokenResponse, error) {
	return a.TokenService.GenerateTokenPairWithFamily(ctx, clientID, userID, scope, tokenTTL, family, nonce, authTime)
}

// newDefaultOAuthService creates a new OAuth service (internal constructor).
func newDefaultOAuthService(
	tokenRepo domain.TokenRepository,
	authCodeRepo domain.AuthorizationCodeRepository,
	deviceAuthRepo domain.DeviceAuthorizationRepository,
	clientRepo domain.ClientRepository,
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	tokenService TokenService,
	issuer string,
) OAuthService {
	return &defaultOAuthService{
		tokenRepo:      tokenRepo,
		authCodeRepo:   authCodeRepo,
		deviceAuthRepo: deviceAuthRepo,
		clientRepo:     clientRepo,
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		tokenService:   &tokenServiceAdapter{tokenService},
		issuer:         issuer,
	}
}

// NewOAuthService creates a new OAuth service (public constructor returning concrete type for backward compatibility).
func NewOAuthService(
	tokenRepo domain.TokenRepository,
	authCodeRepo domain.AuthorizationCodeRepository,
	deviceAuthRepo domain.DeviceAuthorizationRepository,
	clientRepo domain.ClientRepository,
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	tokenService domain.TokenServiceInterface,
	issuer string,
) *defaultOAuthService {
	return &defaultOAuthService{
		tokenRepo:      tokenRepo,
		authCodeRepo:   authCodeRepo,
		deviceAuthRepo: deviceAuthRepo,
		clientRepo:     clientRepo,
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		tokenService:   tokenService,
		issuer:         issuer,
	}
}

func (s *defaultOAuthService) RegisterUser(ctx context.Context, username, password string) (*domain.User, error) {
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

func (s *defaultOAuthService) Login(ctx context.Context, username, password, deviceInfo string) (*api.TokenResponse, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, domain.ErrInvalidCredentials
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

func (s *defaultOAuthService) GetUserSessions(ctx context.Context, userID string) ([]*domain.Session, error) {
	return s.sessionRepo.ListSessionsByUserID(ctx, userID, domain.SessionFilter{})
}

func (s *defaultOAuthService) RefreshToken(ctx context.Context, refreshTokenValue string, clientID string) (*api.TokenResponse, error) {
	tokenInfo, err := s.tokenRepo.GetRefreshTokenInfo(ctx, refreshTokenValue)
	if err != nil {
		return nil, domain.NewInvalidGrant("invalid refresh token")
	}
	if tokenInfo.IsRevoked || time.Now().After(tokenInfo.ExpiresAt) {
		return nil, domain.NewInvalidGrant("refresh token expired or revoked")
	}
	if err := s.tokenRepo.RevokeRefreshToken(ctx, refreshTokenValue); err != nil {
		return nil, fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	return s.tokenService.GenerateTokenPair(ctx, clientID, tokenInfo.UserID, tokenInfo.Scope, time.Hour)
}

func (s *defaultOAuthService) GetJWKS() *domain.JWKS {
	keyset := &domain.JWKS{
		Keys: make([]domain.JSONWebKey, 0),
	}
	return keyset
}

func (s *defaultOAuthService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	cli, err := s.clientRepo.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		if strings.Contains(err.Error(), domain.ErrInvalidClientCredentials.Error()) {
			return nil, domain.ErrInvalidClientCredentials
		}
		return nil, fmt.Errorf("client not found: %w", err)
	}
	return cli, nil
}

func (s *defaultOAuthService) DirectGrant(ctx context.Context,
	clientID, clientSecret, username, password, scope string,
) (*api.TokenResponse, error) {
	cli, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if !contains(cli.AllowedGrantTypes, "password") {
		return nil, domain.ErrInvalidConfig
	}
	user, err := s.userRepo.GetUserByEmail(ctx, username) // Changed from GetUserByUsername
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if !s.validateScope(scope, cli.AllowedScopes) {
		return nil, domain.NewInvalidScope("invalid scope requested by client")
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
	tokenTTL := 1 * time.Hour
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientID, user.ID, scope, tokenTTL)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate token pair in DirectGrant")
		return nil, fmt.Errorf("could not generate tokens: %w", err)
	}

	return tokenPair, nil
}

func (s *defaultOAuthService) ClientCredentials(ctx context.Context,
	clientID, clientSecret, scope string,
) (*api.TokenResponse, error) {
	cli, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if !contains(cli.AllowedGrantTypes, "client_credentials") {
		return nil, domain.ErrInvalidConfig
	}
	if !s.validateScope(scope, cli.AllowedScopes) {
		return nil, domain.NewInvalidScope("invalid scope requested by client")
	}
	token, err := s.tokenService.CreateToken(ctx, domain.CreateTokenOptions{
		TokenID:      uuid.NewString(),
		Scope:        scope,
		ClientID:     clientID,
		UserID:       "", // No user for client_credentials
		TokenType:    "access_token",
		ExpireIn:     time.Hour,
		SigningKeyID: "",
	}, nil)
	if err != nil {
		return nil, err
	}
	return &api.TokenResponse{
		AccessToken: token.TokenValue,
		TokenType:   "Bearer",
		ExpiresIn:   int(time.Hour.Seconds()), // Changed to int
	}, nil
}

func (s *defaultOAuthService) validateScope(requestedScope string, allowedScopes []string) bool {
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

func (s *defaultOAuthService) PasswordGrant(ctx context.Context,
	username, password, scope string, cli *domain.Client,
) (*api.TokenResponse, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, username) // Changed from GetUserByUsername
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	return s.tokenService.GenerateTokenPair(ctx, cli.ID, user.ID, scope, time.Hour)
}

func (s *defaultOAuthService) ExchangeAuthorizationCode(ctx context.Context,
	code, clientID, clientSecret, redirectURI string,
) (*api.TokenResponse, error) {
	_, err := s.ValidateClient(ctx, clientID, clientSecret) // Corrected call
	if err != nil {
		return nil, err
	}
	authCodeDomain, err := s.authCodeRepo.GetAuthCode(ctx, code)
	if err != nil {
		return nil, domain.NewInvalidGrant("invalid authorization code")
	}
	if authCodeDomain.Used || time.Now().After(authCodeDomain.ExpiresAt) {
		return nil, domain.NewInvalidGrant("authorization code expired or already used")
	}
	if authCodeDomain.ClientID != clientID || authCodeDomain.RedirectURI != redirectURI {
		return nil, domain.NewInvalidGrant("invalid client or redirect URI for auth code")
	}
	if err := s.authCodeRepo.MarkAuthCodeAsUsed(ctx, code); err != nil {
		return nil, fmt.Errorf("failed to mark auth code as used: %w", err)
	}
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientID, authCodeDomain.UserID, authCodeDomain.Scope, time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}
	return tokenPair, nil
}

func (s *defaultOAuthService) IntrospectToken(ctx context.Context,
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

func (s *defaultOAuthService) RevokeToken(ctx context.Context, tokenToRevoke, tokenTypeHint, clientID, clientSecret string) error {
	_, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("invalid client: %w", err)
	}
	_ = s.tokenService.RevokeToken(ctx, tokenToRevoke)
	return nil
}

func (s *defaultOAuthService) GenerateAuthCode(
	ctx context.Context, clientID string, userID string,
	redirectURI string, scope string, codeChallenge string, codeChallengeMethod string,
	nonce string, authTime time.Time,
) (string, error) {
	cli, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		return "", domain.NewInvalidClient("client not found or invalid")
	}
	if !s.validateScope(scope, cli.AllowedScopes) {
		return "", domain.NewInvalidScope("requested scope not allowed")
	}

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
	if err := s.authCodeRepo.SaveAuthCode(ctx, authCode); err != nil {
		log.Error().Err(err).Str("clientID", clientID).Str("userID", userID).Msg("Failed to save authorization code")
		return "", fmt.Errorf("failed to save auth code: %w", err)
	}
	log.Info().Str("clientID", clientID).Str("userID", userID).Msg("Authorization code generated and saved")
	return code, nil
}

// InitiateDeviceAuthorization, VerifyUserCode, IssueTokenForDeviceFlow need to use domain.DeviceCode and domain.DeviceCodeStatus
func (s *defaultOAuthService) InitiateDeviceAuthorization(ctx context.Context, clientID string, scope string, verificationBaseURI string) (*api.DeviceAuthResponse, error) {
	cli, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		return nil, domain.NewInvalidClient("client not found or invalid")
	}
	if !s.validateScope(scope, cli.AllowedScopes) {
		return nil, domain.NewInvalidScope("requested scope not allowed")
	}
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
	if err := s.deviceAuthRepo.SaveDeviceAuth(ctx, deviceAuth); err != nil {
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

func (s *defaultOAuthService) VerifyUserCode(ctx context.Context, userCode string, userID string) (*domain.DeviceCode, error) {
	deviceAuth, err := s.deviceAuthRepo.GetDeviceAuthByUserCode(ctx, userCode)
	if err != nil {
		if err == domain.ErrUserCodeNotFound { // Assuming ErrUserCodeNotFound is defined in domain
			return nil, domain.ErrUserCodeNotFound
		}
		return nil, fmt.Errorf("failed to retrieve device authorization by user code: %w", err)
	}
	if deviceAuth.Status != domain.DeviceCodeStatusPending {
		return nil, domain.ErrCannotApproveDeviceAuth // Assuming ErrCannotApproveDeviceAuth is defined
	}
	if time.Now().UTC().After(deviceAuth.ExpiresAt) {
		_ = s.deviceAuthRepo.UpdateDeviceAuthStatus(ctx, deviceAuth.DeviceCode, domain.DeviceCodeStatusExpired)
		return nil, domain.ErrUserCodeNotFound // Or ErrDeviceFlowTokenExpired
	}
	updatedDeviceAuth, err := s.deviceAuthRepo.ApproveDeviceAuth(ctx, userCode, userID)
	if err != nil {
		if err == domain.ErrCannotApproveDeviceAuth {
			return nil, domain.ErrCannotApproveDeviceAuth
		}
		return nil, fmt.Errorf("failed to approve device authorization: %w", err)
	}
	return updatedDeviceAuth, nil
}

func (s *defaultOAuthService) IssueTokenForDeviceFlow(ctx context.Context, deviceCode string, clientID string) (*api.TokenResponse, error) {
	deviceAuth, err := s.deviceAuthRepo.GetDeviceAuthByDeviceCode(ctx, deviceCode)
	if err != nil {
		// Assuming ErrDeviceCodeNotFound is defined in domain
		if err == domain.ErrDeviceCodeNotFound || (err != nil && strings.Contains(err.Error(), "not found")) {
			return nil, domain.ErrDeviceFlowTokenExpired
		}
		return nil, fmt.Errorf("failed to retrieve device auth by device code: %w", err)
	}
	if deviceAuth.ClientID != clientID {
		return nil, domain.NewInvalidClient("client ID mismatch")
	}
	switch deviceAuth.Status {
	case domain.DeviceCodeStatusPending:
		if pollErr := s.deviceAuthRepo.UpdateDeviceAuthLastPolledAt(ctx, deviceAuth.DeviceCode); pollErr != nil {
			fmt.Printf("Warning: failed to update last polled at for device code %s: %v\n", deviceAuth.DeviceCode, pollErr)
		}
		return nil, domain.ErrAuthorizationPending
	case domain.DeviceCodeStatusAuthorized:
		tokenResponse, tokenErr := s.tokenService.GenerateTokenPair(ctx, deviceAuth.ClientID, deviceAuth.UserID, deviceAuth.Scope, time.Hour)
		if tokenErr != nil {
			return nil, fmt.Errorf("failed to generate token pair for device flow: %w", tokenErr)
		}
		if redeemErr := s.deviceAuthRepo.UpdateDeviceAuthStatus(ctx, deviceAuth.DeviceCode, domain.DeviceCodeStatusRedeemed); redeemErr != nil {
			fmt.Printf("Critical Warning: failed to mark device code %s as redeemed after token issuance: %v\n", deviceAuth.DeviceCode, redeemErr)
		}
		return tokenResponse, nil
	case domain.DeviceCodeStatusExpired:
		return nil, domain.ErrDeviceFlowTokenExpired
	case domain.DeviceCodeStatusDenied:
		return nil, domain.ErrDeviceFlowAccessDenied
	case domain.DeviceCodeStatusRedeemed:
		return nil, domain.ErrDeviceFlowTokenExpired
	default:
		return nil, domain.NewServerError("unexpected device authorization status")
	}
}

// GenerateTokens was a duplicate of ExchangeAuthorizationCode, removed it.
// GetUserInfo was a stub, removed it as user info is part of AuthService or OIDC UserInfo endpoint.
// TokenIntrospection struct was moved to domain package.
// JSONWebKey and JSONWebKeySet are local to jwks_service.go and used there.
// User, UserSession, Token, AuthCode, DeviceCode, DeviceCodeStatus are now from domain package.
// Error variables are now from domain (github.com/pilab-dev/shadow-sso/errors).
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

// intersectScopes returns the space-delimited intersection of requested and
// granted scopes. If requested is empty it returns granted verbatim (no
// restriction). When the intersection is empty the exchange is denied.
func intersectScopes(requested, granted string) (string, error) {
	if requested == "" {
		return granted, nil
	}

	grantedSet := make(map[string]struct{}, len(strings.Split(granted, " ")))
	for _, s := range strings.Split(granted, " ") {
		if s != "" {
			grantedSet[s] = struct{}{}
		}
	}

	var intersected []string
	for _, s := range strings.Split(requested, " ") {
		if s == "" {
			continue
		}
		if _, ok := grantedSet[s]; ok {
			intersected = append(intersected, s)
		}
	}

	if len(intersected) == 0 {
		return "", domain.NewInvalidScope("requested scope exceeds granted scope")
	}

	return strings.Join(intersected, " "), nil
}

func (s *defaultOAuthService) TokenExchange(ctx context.Context, subjectToken, subjectTokenType, requestedTokenType, resource, scope, clientID string) (*api.TokenResponse, error) {
	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" && subjectTokenType != "urn:ietf:params:oauth:token-type:jwt" {
		return nil, domain.NewInvalidRequest("unsupported subject_token_type")
	}

	tokenInfo, err := s.tokenService.ValidateAccessToken(ctx, subjectToken)
	if err != nil {
		if errors.Is(err, domain.ErrTokenExpiredOrRevoked) {
			return nil, domain.NewInvalidGrant("invalid subject token: expired or revoked")
		}
		return nil, domain.NewInvalidGrant("invalid subject token")
	}

	if clientID != "" {
		client, err := s.clientRepo.GetClient(ctx, clientID)
		if err != nil {
			return nil, domain.NewInvalidClient("client not found")
		}
		if tokenInfo.ClientID != "" && tokenInfo.ClientID != clientID {
			return nil, domain.NewInvalidClient("client ID mismatch")
		}
		_ = client
	}

	// RFC 8693 §2: the exchanged token's scope is the intersection of the
	// requested scope and the original token's scope. Never grant broader
	// scopes than the subject token carried.
	effectiveScope, err := intersectScopes(scope, tokenInfo.Scope)
	if err != nil {
		return nil, err
	}

	return s.tokenService.GenerateTokenPair(ctx, clientID, tokenInfo.UserID, effectiveScope, time.Hour)
}
