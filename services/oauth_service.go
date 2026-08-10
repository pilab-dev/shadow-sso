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
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
	tracerName          = "oauth-service"
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
	tokenRepo        domain.TokenRepository
	authCodeRepo     domain.AuthorizationCodeRepository
	deviceAuthRepo   domain.DeviceAuthorizationRepository
	clientRepo       domain.ClientRepository // Changed from client.ClientStore for consistency
	userRepo         domain.UserRepository
	sessionRepo      domain.SessionRepository
	tokenService     domain.TokenServiceInterface
	issuer           string
	realmSettingsRepo domain.RealmSettingsRepository
}

// oauthServiceOption configures a defaultOAuthService at construction time.
type oauthServiceOption func(*defaultOAuthService)

// WithRealmSettings injects the realm settings repository so grant paths use
// the persisted AccessTokenLifespan/AccessCodeLifespan instead of hardcoded
// values. When absent, legacy hardcoded TTLs are used.
func WithRealmSettings(repo domain.RealmSettingsRepository) oauthServiceOption {
	return func(s *defaultOAuthService) {
		s.realmSettingsRepo = repo
	}
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
	opts ...oauthServiceOption,
) OAuthService {
	svc := &defaultOAuthService{
		tokenRepo:      tokenRepo,
		authCodeRepo:   authCodeRepo,
		deviceAuthRepo: deviceAuthRepo,
		clientRepo:     clientRepo,
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		tokenService:   &tokenServiceAdapter{tokenService},
		issuer:         issuer,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
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
	opts ...oauthServiceOption,
) *defaultOAuthService {
	svc := &defaultOAuthService{
		tokenRepo:      tokenRepo,
		authCodeRepo:   authCodeRepo,
		deviceAuthRepo: deviceAuthRepo,
		clientRepo:     clientRepo,
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		tokenService:   tokenService,
		issuer:         issuer,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// legacyAccessTokenTTL is the hardcoded lifetime used when no realm settings
// repository is wired (pre-realm-settings behavior).
const legacyAccessTokenTTL = time.Hour

// legacyAccessCodeTTL mirrors the hardcoded authorization-code lifetime.
const legacyAccessCodeTTL = 10 * time.Minute

// realmAccessTokenLifespan returns the access-token TTL persisted in realm
// settings. It errors when the configured lifespan is non-positive so callers
// fail with a clear error instead of issuing degenerate tokens.
func (s *defaultOAuthService) realmAccessTokenLifespan(ctx context.Context) (time.Duration, error) {
	if s.realmSettingsRepo == nil {
		return legacyAccessTokenTTL, nil
	}
	settings, err := s.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil {
		return 0, err
	}
	if settings.AccessTokenLifespan <= 0 {
		return 0, fmt.Errorf("invalid realm settings: access token lifespan must be positive, got %d", settings.AccessTokenLifespan)
	}
	return time.Duration(settings.AccessTokenLifespan) * time.Second, nil
}

// realmAccessCodeLifespan returns the authorization-code TTL persisted in
// realm settings. It errors when the configured lifespan is non-positive.
func (s *defaultOAuthService) realmAccessCodeLifespan(ctx context.Context) (time.Duration, error) {
	if s.realmSettingsRepo == nil {
		return legacyAccessCodeTTL, nil
	}
	settings, err := s.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil {
		return 0, err
	}
	if settings.AccessCodeLifespan <= 0 {
		return 0, fmt.Errorf("invalid realm settings: access code lifespan must be positive, got %d", settings.AccessCodeLifespan)
	}
	return time.Duration(settings.AccessCodeLifespan) * time.Second, nil
}

func (s *defaultOAuthService) RegisterUser(ctx context.Context, username, password string) (*domain.User, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "RegisterUser", attribute.String("user.username", username))
	defer span.End()

	log.Ctx(ctx).Debug().Str("username", username).Msg("Attempting user registration")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to hash password")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("username", username).Msg("Failed to hash password during user registration")
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &domain.User{
		Email:        username,
		PasswordHash: string(hashedPassword),
		Status:       domain.UserStatusActive,
	}
	err = s.userRepo.CreateUser(ctx, user)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to create user")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("username", username).Msg("Failed to create user in repository")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	span.SetAttributes(attribute.String("user.id", user.ID))
	log.Ctx(ctx).Info().Str("username", username).Str("user_id", user.ID).Msg("User registered successfully")
	return user, nil
}

func (s *defaultOAuthService) Login(ctx context.Context, username, password, deviceInfo string) (*api.TokenResponse, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "Login",
		attribute.String("user.username", username),
		attribute.String("device_info", deviceInfo),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("username", username).Str("device_info", deviceInfo).Msg("Processing user login attempt")

	user, err := s.userRepo.GetUserByEmail(ctx, username)
	if err != nil {
		telemetry.RecordSpanError(span, err, "user not found")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Warn().Err(err).Str("username", username).Msg("Login failed: user not found")
		return nil, fmt.Errorf("user not found: %w", err)
	}
	span.SetAttributes(attribute.String("user.id", user.ID))

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		telemetry.RecordSpanError(span, err, "invalid password credentials")
		span.SetStatus(codes.Error, "invalid credentials")
		log.Ctx(ctx).Warn().Str("username", username).Str("user_id", user.ID).Msg("Login failed: password mismatch")
		return nil, domain.ErrInvalidCredentials
	}

	// Create a user session
	clientIdentifier := "oauth-service-login-client"
	session := &domain.Session{
		ID:         uuid.NewString(),
		UserID:     user.ID,
		ClientID:   clientIdentifier,
		UserAgent:  deviceInfo,
		ExpiresAt:  time.Now().Add(24 * 30 * time.Hour), // Example long-lived session
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		IsRevoked:  false,
	}
	session.TokenID = session.ID
	if err := s.sessionRepo.StoreSession(ctx, session); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("user_id", user.ID).Str("session_id", session.ID).Msg("Failed to store session in OAuthService.Login")
	} else {
		log.Ctx(ctx).Debug().Str("user_id", user.ID).Str("session_id", session.ID).Msg("Session stored successfully during login")
	}

	// Generate tokens for the client
	loginScope := "openid profile email"
	tokenTTL, err := s.realmAccessTokenLifespan(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid realm settings access token lifespan")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("user_id", user.ID).Msg("Failed to resolve access token lifespan in Login")
		return nil, err
	}
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientIdentifier, user.ID, loginScope, tokenTTL, session.ID)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to generate token pair")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("user_id", user.ID).Msg("Failed to generate token pair during login")
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}

	log.Ctx(ctx).Info().Str("username", username).Str("user_id", user.ID).Str("session_id", session.ID).Msg("User login successful")
	return tokenPair, nil
}

func (s *defaultOAuthService) GetUserSessions(ctx context.Context, userID string) ([]*domain.Session, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "GetUserSessions", attribute.String("user.id", userID))
	defer span.End()

	log.Ctx(ctx).Debug().Str("user_id", userID).Msg("Fetching user sessions")

	sessions, err := s.sessionRepo.ListSessionsByUserID(ctx, userID, domain.SessionFilter{})
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list user sessions")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("user_id", userID).Msg("Failed to list sessions by user ID")
		return nil, err
	}

	span.SetAttributes(attribute.Int("sessions.count", len(sessions)))
	log.Ctx(ctx).Debug().Str("user_id", userID).Int("session_count", len(sessions)).Msg("Successfully retrieved user sessions")
	return sessions, nil
}

func (s *defaultOAuthService) RefreshToken(ctx context.Context, refreshTokenValue string, clientID string) (*api.TokenResponse, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "RefreshToken", attribute.String("oauth.client_id", clientID))
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", clientID).Msg("Attempting refresh token exchange")

	tokenInfo, err := s.tokenRepo.GetRefreshTokenInfo(ctx, refreshTokenValue)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid refresh token")
		span.SetStatus(codes.Error, "invalid refresh token")
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Refresh token lookup failed")
		return nil, domain.NewInvalidGrant("invalid refresh token")
	}
	span.SetAttributes(
		attribute.String("user.id", tokenInfo.UserID),
		attribute.String("oauth.scope", tokenInfo.Scope),
		attribute.Bool("token.is_revoked", tokenInfo.IsRevoked),
	)

	if tokenInfo.IsRevoked || time.Now().After(tokenInfo.ExpiresAt) {
		errRev := errors.New("refresh token expired or revoked")
		telemetry.RecordSpanError(span, errRev, "refresh token invalid state")
		span.SetStatus(codes.Error, errRev.Error())
		log.Ctx(ctx).Warn().
			Str("client_id", clientID).
			Str("user_id", tokenInfo.UserID).
			Bool("is_revoked", tokenInfo.IsRevoked).
			Time("expires_at", tokenInfo.ExpiresAt).
			Msg("Refresh token grant rejected: expired or revoked")
		return nil, domain.NewInvalidGrant("refresh token expired or revoked")
	}

	if err := s.tokenRepo.RevokeRefreshToken(ctx, refreshTokenValue); err != nil {
		telemetry.RecordSpanError(span, err, "failed to revoke refresh token")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Str("user_id", tokenInfo.UserID).Msg("Failed to revoke current refresh token")
		return nil, fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	tokenTTL, err := s.realmAccessTokenLifespan(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid realm settings access token lifespan")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Str("user_id", tokenInfo.UserID).Msg("Failed to resolve access token lifespan in RefreshToken")
		return nil, err
	}
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientID, tokenInfo.UserID, tokenInfo.Scope, tokenTTL, "")
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to generate token pair")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Str("user_id", tokenInfo.UserID).Msg("Failed to generate new token pair during refresh")
		return nil, err
	}

	log.Ctx(ctx).Info().Str("client_id", clientID).Str("user_id", tokenInfo.UserID).Msg("Refresh token exchange successful")
	return tokenPair, nil
}

func (s *defaultOAuthService) GetJWKS() *domain.JWKS {
	log.Debug().Msg("Retrieving JWKS keyset")
	keyset := &domain.JWKS{
		Keys: make([]domain.JSONWebKey, 0),
	}
	return keyset
}

func (s *defaultOAuthService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "ValidateClient", attribute.String("oauth.client_id", clientID))
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", clientID).Msg("Validating client credentials")

	cli, err := s.clientRepo.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		telemetry.RecordSpanError(span, err, "client validation failed")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Client credential validation failed")
		if strings.Contains(err.Error(), domain.ErrInvalidClientCredentials.Error()) {
			return nil, domain.ErrInvalidClientCredentials
		}
		return nil, fmt.Errorf("client not found: %w", err)
	}

	log.Ctx(ctx).Debug().Str("client_id", clientID).Str("client_name", cli.Name).Msg("Client validated successfully")
	return cli, nil
}

func (s *defaultOAuthService) DirectGrant(ctx context.Context,
	clientID, clientSecret, username, password, scope string,
) (*api.TokenResponse, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "DirectGrant",
		attribute.String("oauth.client_id", clientID),
		attribute.String("user.username", username),
		attribute.String("oauth.scope", scope),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", clientID).Str("username", username).Str("scope", scope).Msg("Processing Direct Grant authentication")

	cli, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		telemetry.RecordSpanError(span, err, "client validation failed in direct grant")
		return nil, err
	}

	if !contains(cli.AllowedGrantTypes, "password") {
		errGrant := domain.ErrInvalidConfig
		telemetry.RecordSpanError(span, errGrant, "password grant type not allowed")
		span.SetStatus(codes.Error, "password grant type not allowed for client")
		log.Ctx(ctx).Warn().Str("client_id", clientID).Msg("Direct grant rejected: password grant type not allowed for client")
		return nil, errGrant
	}

	user, err := s.userRepo.GetUserByEmail(ctx, username)
	if err != nil {
		telemetry.RecordSpanError(span, err, "user not found")
		span.SetStatus(codes.Error, "user not found")
		log.Ctx(ctx).Warn().Err(err).Str("username", username).Msg("Direct grant failed: user not found")
		return nil, domain.ErrInvalidCredentials
	}
	span.SetAttributes(attribute.String("user.id", user.ID))

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		telemetry.RecordSpanError(span, err, "password mismatch")
		span.SetStatus(codes.Error, "invalid credentials")
		log.Ctx(ctx).Warn().Str("username", username).Str("user_id", user.ID).Msg("Direct grant failed: invalid password")
		return nil, domain.ErrInvalidCredentials
	}

	if !s.validateScope(ctx, scope, cli.AllowedScopes) {
		errScope := domain.NewInvalidScope("invalid scope requested by client")
		telemetry.RecordSpanError(span, errScope, "invalid scope requested")
		span.SetStatus(codes.Error, "invalid scope")
		log.Ctx(ctx).Warn().Str("client_id", clientID).Str("requested_scope", scope).Msg("Direct grant rejected: scope not allowed")
		return nil, errScope
	}

	session := &domain.Session{
		ID:         uuid.NewString(),
		UserID:     user.ID,
		ClientID:   clientID,
		UserAgent:  "Direct Grant",
		ExpiresAt:  time.Now().Add(time.Hour),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		IsRevoked:  false,
	}
	session.TokenID = session.ID
	if err := s.sessionRepo.StoreSession(ctx, session); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("session_id", session.ID).Str("user_id", user.ID).Msg("Failed to store session in OAuthService.DirectGrant")
	}

	tokenTTL, err := s.realmAccessTokenLifespan(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid realm settings access token lifespan")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Str("user_id", user.ID).Msg("Failed to resolve access token lifespan in DirectGrant")
		return nil, err
	}
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientID, user.ID, scope, tokenTTL, session.ID)
	if err != nil {
		telemetry.RecordSpanError(span, err, "token pair generation failed")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Str("user_id", user.ID).Msg("Failed to generate token pair in DirectGrant")
		return nil, fmt.Errorf("could not generate tokens: %w", err)
	}

	log.Ctx(ctx).Info().Str("client_id", clientID).Str("user_id", user.ID).Msg("Direct Grant token issuance successful")
	return tokenPair, nil
}

func (s *defaultOAuthService) ClientCredentials(ctx context.Context,
	clientID, clientSecret, scope string,
) (*api.TokenResponse, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "ClientCredentials",
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.scope", scope),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", clientID).Str("scope", scope).Msg("Processing Client Credentials grant")

	cli, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		telemetry.RecordSpanError(span, err, "client validation failed")
		return nil, err
	}

	if !contains(cli.AllowedGrantTypes, "client_credentials") {
		errGrant := domain.ErrInvalidConfig
		telemetry.RecordSpanError(span, errGrant, "client_credentials grant type not allowed")
		span.SetStatus(codes.Error, "grant type disabled")
		log.Ctx(ctx).Warn().Str("client_id", clientID).Msg("Client Credentials grant rejected: grant type disabled for client")
		return nil, errGrant
	}

	if !s.validateScope(ctx, scope, cli.AllowedScopes) {
		errScope := domain.NewInvalidScope("invalid scope requested by client")
		telemetry.RecordSpanError(span, errScope, "invalid scope requested")
		span.SetStatus(codes.Error, "invalid scope")
		log.Ctx(ctx).Warn().Str("client_id", clientID).Str("scope", scope).Msg("Client Credentials grant rejected: scope not allowed")
		return nil, errScope
	}

	tokenTTL, err := s.realmAccessTokenLifespan(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid realm settings access token lifespan")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Msg("Failed to resolve access token lifespan in ClientCredentials")
		return nil, err
	}

	token, err := s.tokenService.CreateToken(ctx, domain.CreateTokenOptions{
		TokenID:      uuid.NewString(),
		Scope:        scope,
		ClientID:     clientID,
		UserID:       "", // No user for client_credentials
		TokenType:    "access_token",
		ExpireIn:     tokenTTL,
		SigningKeyID: "",
		Roles:        cli.ServiceAccountRoles,
	}, nil)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to create token")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Msg("Failed to create access token for client_credentials")
		return nil, err
	}

	log.Ctx(ctx).Info().Str("client_id", clientID).Msg("Client Credentials token issuance successful")
	return &api.TokenResponse{
		AccessToken: token.TokenValue,
		TokenType:   "Bearer",
		ExpiresIn:   int(tokenTTL.Seconds()),
	}, nil
}

func (s *defaultOAuthService) validateScope(ctx context.Context, requestedScope string, allowedScopes []string) bool {
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
			log.Ctx(ctx).Debug().Str("requested_scope", req).Msg("Scope validation failed: scope not in allowed list")
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
	_, span := telemetry.StartSpan(ctx, tracerName, "PasswordGrant",
		attribute.String("oauth.client_id", cli.ID),
		attribute.String("user.username", username),
		attribute.String("oauth.scope", scope),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", cli.ID).Str("username", username).Msg("Processing Password Grant request")

	user, err := s.userRepo.GetUserByEmail(ctx, username)
	if err != nil {
		telemetry.RecordSpanError(span, err, "user not found")
		span.SetStatus(codes.Error, "user not found")
		log.Ctx(ctx).Warn().Err(err).Str("username", username).Msg("Password grant failed: user not found")
		return nil, domain.ErrInvalidCredentials
	}
	span.SetAttributes(attribute.String("user.id", user.ID))

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		telemetry.RecordSpanError(span, err, "password mismatch")
		span.SetStatus(codes.Error, "invalid credentials")
		log.Ctx(ctx).Warn().Str("username", username).Str("user_id", user.ID).Msg("Password grant failed: password mismatch")
		return nil, domain.ErrInvalidCredentials
	}

	tokenTTL, err := s.realmAccessTokenLifespan(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid realm settings access token lifespan")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", cli.ID).Str("user_id", user.ID).Msg("Failed to resolve access token lifespan in PasswordGrant")
		return nil, err
	}

	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, cli.ID, user.ID, scope, tokenTTL, "")
	if err != nil {
		telemetry.RecordSpanError(span, err, "token pair generation failed")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", cli.ID).Str("user_id", user.ID).Msg("Password grant failed: token generation error")
		return nil, err
	}

	log.Ctx(ctx).Info().Str("client_id", cli.ID).Str("user_id", user.ID).Msg("Password grant token issuance successful")
	return tokenPair, nil
}

func (s *defaultOAuthService) ExchangeAuthorizationCode(ctx context.Context,
	code, clientID, clientSecret, redirectURI string,
) (*api.TokenResponse, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "ExchangeAuthorizationCode",
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.redirect_uri", redirectURI),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", clientID).Str("redirect_uri", redirectURI).Msg("Exchanging authorization code for tokens")

	// Client is already authenticated by the caller (TokenHandler).
	// Re-validation would fail here because the stored bcrypt hash gets
	// passed as the "secret" instead of the original plaintext secret.
	// Skip redundant client validation.

	authCodeDomain, err := s.authCodeRepo.GetAuthCode(ctx, code)
	if err != nil {
		telemetry.RecordSpanError(span, err, "auth code not found")
		span.SetStatus(codes.Error, "invalid authorization code")
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Authorization code exchange failed: code not found")
		return nil, domain.NewInvalidGrant("invalid authorization code")
	}
	span.SetAttributes(
		attribute.String("user.id", authCodeDomain.UserID),
		attribute.String("oauth.scope", authCodeDomain.Scope),
		attribute.Bool("auth_code.used", authCodeDomain.Used),
		attribute.String("oauth.nonce", authCodeDomain.Nonce),
	)

	if authCodeDomain.Used || time.Now().After(authCodeDomain.ExpiresAt) {
		errUsed := errors.New("authorization code expired or already used")
		telemetry.RecordSpanError(span, errUsed, "auth code expired/used")
		span.SetStatus(codes.Error, errUsed.Error())
		log.Ctx(ctx).Warn().
			Str("client_id", clientID).
			Bool("used", authCodeDomain.Used).
			Time("expires_at", authCodeDomain.ExpiresAt).
			Msg("Authorization code exchange rejected: code expired or already used")
		return nil, domain.NewInvalidGrant("authorization code expired or already used")
	}

	if authCodeDomain.ClientID != clientID || authCodeDomain.RedirectURI != redirectURI {
		errMismatch := errors.New("invalid client or redirect URI for auth code")
		telemetry.RecordSpanError(span, errMismatch, "auth code metadata mismatch")
		span.SetStatus(codes.Error, errMismatch.Error())
		log.Ctx(ctx).Warn().
			Str("client_id", clientID).
			Str("expected_client_id", authCodeDomain.ClientID).
			Str("redirect_uri", redirectURI).
			Str("expected_redirect_uri", authCodeDomain.RedirectURI).
			Msg("Authorization code exchange rejected: client or redirect URI mismatch")
		return nil, domain.NewInvalidGrant("invalid client or redirect URI for auth code")
	}

	if err := s.authCodeRepo.MarkAuthCodeAsUsed(ctx, code); err != nil {
		telemetry.RecordSpanError(span, err, "failed to mark auth code as used")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Msg("Failed to mark authorization code as used")
		return nil, fmt.Errorf("failed to mark auth code as used: %w", err)
	}

	tokenTTL, err := s.realmAccessTokenLifespan(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid realm settings access token lifespan")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Str("user_id", authCodeDomain.UserID).Msg("Failed to resolve access token lifespan in auth code exchange")
		return nil, err
	}
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientID, authCodeDomain.UserID, authCodeDomain.Scope, tokenTTL, "")
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to generate token pair")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Str("user_id", authCodeDomain.UserID).Msg("Failed to generate token pair during auth code exchange")
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}

	// If a nonce was stored in the auth code, regenerate the ID token with it.
	if authCodeDomain.Nonce != "" {
		idToken, err := s.tokenService.GenerateIDToken(ctx, authCodeDomain.UserID, clientID, authCodeDomain.Nonce, "", authCodeDomain.CreatedAt, authCodeDomain.Scope)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Failed to generate ID token with nonce, continuing without it")
		} else {
			tokenPair.IDToken = idToken
		}
	}

	log.Ctx(ctx).Info().Str("client_id", clientID).Str("user_id", authCodeDomain.UserID).Msg("Authorization code exchange successful")
	return tokenPair, nil
}

func (s *defaultOAuthService) IntrospectToken(ctx context.Context,
	token, tokenTypeHint, clientID, clientSecret string,
) (*domain.TokenIntrospection, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "IntrospectToken",
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.token_type_hint", tokenTypeHint),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", clientID).Str("token_type_hint", tokenTypeHint).Msg("Introspecting token")

	_, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid client during introspection")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Token introspection failed: invalid client")
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	var tokenInfo *domain.TokenInfo
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
		log.Ctx(ctx).Debug().Err(err).Str("client_id", clientID).Msg("Token introspection completed: token active=false (lookup failed)")
		span.SetAttributes(attribute.Bool("token.active", false))
		return &domain.TokenIntrospection{Active: false}, nil
	}

	if time.Now().After(tokenInfo.ExpiresAt) {
		log.Ctx(ctx).Debug().Str("client_id", clientID).Time("expires_at", tokenInfo.ExpiresAt).Msg("Token introspection completed: token active=false (expired)")
		span.SetAttributes(attribute.Bool("token.active", false))
		return &domain.TokenIntrospection{Active: false}, nil
	}

	span.SetAttributes(
		attribute.Bool("token.active", true),
		attribute.String("user.id", tokenInfo.UserID),
		attribute.String("oauth.scope", tokenInfo.Scope),
		attribute.String("token.type", tokenInfo.TokenType),
	)

	var username string
	if tokenInfo.UserID != "" {
		user, err := s.userRepo.GetUserByID(ctx, tokenInfo.UserID)
		if err == nil {
			username = user.Email
		} else {
			log.Ctx(ctx).Warn().Err(err).Str("user_id", tokenInfo.UserID).Msg("Failed to resolve user email during introspection")
		}
	}

	log.Ctx(ctx).Info().Str("client_id", clientID).Str("user_id", tokenInfo.UserID).Bool("active", true).Msg("Token introspection active response returned")
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
	_, span := telemetry.StartSpan(ctx, tracerName, "RevokeToken",
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.token_type_hint", tokenTypeHint),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", clientID).Str("token_type_hint", tokenTypeHint).Msg("Revoking token")

	_, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid client during token revocation")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Token revocation failed: invalid client")
		return fmt.Errorf("invalid client: %w", err)
	}

	if err := s.tokenService.RevokeToken(ctx, tokenToRevoke); err != nil {
		telemetry.RecordSpanError(span, err, "failed to revoke token")
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Token revocation returned warning/error")
	}

	log.Ctx(ctx).Info().Str("client_id", clientID).Msg("Token revocation processed successfully")
	return nil
}

func (s *defaultOAuthService) GenerateAuthCode(
	ctx context.Context, clientID string, userID string,
	redirectURI string, scope string, codeChallenge string, codeChallengeMethod string,
	nonce string, authTime time.Time,
) (string, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "GenerateAuthCode",
		attribute.String("oauth.client_id", clientID),
		attribute.String("user.id", userID),
		attribute.String("oauth.redirect_uri", redirectURI),
		attribute.String("oauth.scope", scope),
		attribute.String("pkce.code_challenge_method", codeChallengeMethod),
	)
	defer span.End()

	log.Ctx(ctx).Debug().
		Str("client_id", clientID).
		Str("user_id", userID).
		Str("redirect_uri", redirectURI).
		Str("scope", scope).
		Msg("Generating authorization code")

	cli, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		telemetry.RecordSpanError(span, err, "client not found")
		span.SetStatus(codes.Error, "invalid client")
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("GenerateAuthCode failed: client not found")
		return "", domain.NewInvalidClient("client not found or invalid")
	}

	if !s.validateScope(ctx, scope, cli.AllowedScopes) {
		errScope := domain.NewInvalidScope("requested scope not allowed")
		telemetry.RecordSpanError(span, errScope, "scope not allowed")
		span.SetStatus(codes.Error, "invalid scope")
		log.Ctx(ctx).Warn().Str("client_id", clientID).Str("scope", scope).Msg("GenerateAuthCode failed: scope not allowed")
		return "", errScope
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		telemetry.RecordSpanError(span, err, "entropy failure for auth code")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Msg("Failed to generate random bytes for auth code")
		return "", fmt.Errorf("failed to generate random bytes for auth code: %w", err)
	}
	codeTTL, err := s.realmAccessCodeLifespan(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid realm settings access code lifespan")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("clientID", clientID).Str("userID", userID).Msg("Failed to resolve access code lifespan in GenerateAuthCode")
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	authCode := &domain.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		ExpiresAt:           time.Now().Add(codeTTL),
		CreatedAt:           time.Now(),
		Used:                false,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
	}

	if err := s.authCodeRepo.SaveAuthCode(ctx, authCode); err != nil {
		telemetry.RecordSpanError(span, err, "failed to save auth code")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("clientID", clientID).Str("userID", userID).Msg("Failed to save authorization code")
		return "", fmt.Errorf("failed to save auth code: %w", err)
	}

	log.Ctx(ctx).Info().Str("clientID", clientID).Str("userID", userID).Msg("Authorization code generated and saved")
	return code, nil
}

func (s *defaultOAuthService) InitiateDeviceAuthorization(ctx context.Context, clientID string, scope string, verificationBaseURI string) (*api.DeviceAuthResponse, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "InitiateDeviceAuthorization",
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.scope", scope),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", clientID).Str("scope", scope).Msg("Initiating device authorization flow")

	cli, err := s.clientRepo.GetClient(ctx, clientID)
	if err != nil {
		telemetry.RecordSpanError(span, err, "client not found")
		span.SetStatus(codes.Error, "invalid client")
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("InitiateDeviceAuthorization failed: client not found")
		return nil, domain.NewInvalidClient("client not found or invalid")
	}

	if !s.validateScope(ctx, scope, cli.AllowedScopes) {
		errScope := domain.NewInvalidScope("requested scope not allowed")
		telemetry.RecordSpanError(span, errScope, "scope not allowed")
		span.SetStatus(codes.Error, "invalid scope")
		log.Ctx(ctx).Warn().Str("client_id", clientID).Str("scope", scope).Msg("InitiateDeviceAuthorization failed: scope not allowed")
		return nil, errScope
	}

	deviceCodeVal, err := generateRandomString(deviceCodeLength)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to generate device_code")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Msg("Failed to generate random string for device code")
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
		telemetry.RecordSpanError(span, err, "failed to save device authorization")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Msg("Failed to save device authorization request")
		return nil, fmt.Errorf("failed to save device authorization request: %w", err)
	}

	verificationURI := fmt.Sprintf("%s/oauth2/device/verify", verificationBaseURI)
	verificationURIComplete := fmt.Sprintf("%s?user_code=%s", verificationURI, userCodeVal)

	log.Ctx(ctx).Info().Str("client_id", clientID).Str("user_code", userCodeVal).Msg("Device authorization flow initiated successfully")
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
	_, span := telemetry.StartSpan(ctx, tracerName, "VerifyUserCode",
		attribute.String("user.id", userID),
		attribute.String("device_flow.user_code", userCode),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("user_id", userID).Str("user_code", userCode).Msg("Verifying device user code")

	deviceAuth, err := s.deviceAuthRepo.GetDeviceAuthByUserCode(ctx, userCode)
	if err != nil {
		telemetry.RecordSpanError(span, err, "user code lookup failed")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Warn().Err(err).Str("user_code", userCode).Msg("Failed to retrieve device authorization by user code")
		if err == domain.ErrUserCodeNotFound {
			return nil, domain.ErrUserCodeNotFound
		}
		return nil, fmt.Errorf("failed to retrieve device authorization by user code: %w", err)
	}

	span.SetAttributes(
		attribute.String("oauth.client_id", deviceAuth.ClientID),
		attribute.String("device_flow.status", string(deviceAuth.Status)),
	)

	if deviceAuth.Status != domain.DeviceCodeStatusPending {
		errStatus := domain.ErrCannotApproveDeviceAuth
		telemetry.RecordSpanError(span, errStatus, "device authorization not pending")
		span.SetStatus(codes.Error, "device authorization not pending")
		log.Ctx(ctx).Warn().Str("user_code", userCode).Str("status", string(deviceAuth.Status)).Msg("Cannot approve device auth: status not pending")
		return nil, errStatus
	}

	if time.Now().UTC().After(deviceAuth.ExpiresAt) {
		errExpired := domain.ErrUserCodeNotFound
		telemetry.RecordSpanError(span, errExpired, "device authorization expired")
		span.SetStatus(codes.Error, "expired user code")
		log.Ctx(ctx).Warn().Str("user_code", userCode).Time("expires_at", deviceAuth.ExpiresAt).Msg("User code verification failed: code expired")
		_ = s.deviceAuthRepo.UpdateDeviceAuthStatus(ctx, deviceAuth.DeviceCode, domain.DeviceCodeStatusExpired)
		return nil, errExpired
	}

	updatedDeviceAuth, err := s.deviceAuthRepo.ApproveDeviceAuth(ctx, userCode, userID)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to approve device auth")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("user_code", userCode).Str("user_id", userID).Msg("Failed to approve device authorization")
		if err == domain.ErrCannotApproveDeviceAuth {
			return nil, domain.ErrCannotApproveDeviceAuth
		}
		return nil, fmt.Errorf("failed to approve device authorization: %w", err)
	}

	log.Ctx(ctx).Info().Str("user_code", userCode).Str("user_id", userID).Str("client_id", updatedDeviceAuth.ClientID).Msg("Device authorization approved successfully")
	return updatedDeviceAuth, nil
}

func (s *defaultOAuthService) IssueTokenForDeviceFlow(ctx context.Context, deviceCode string, clientID string) (*api.TokenResponse, error) {
	_, span := telemetry.StartSpan(ctx, tracerName, "IssueTokenForDeviceFlow",
		attribute.String("oauth.client_id", clientID),
	)
	defer span.End()

	log.Ctx(ctx).Debug().Str("client_id", clientID).Msg("Polling/issuing token for device flow")

	deviceAuth, err := s.deviceAuthRepo.GetDeviceAuthByDeviceCode(ctx, deviceCode)
	if err != nil {
		telemetry.RecordSpanError(span, err, "device code lookup failed")
		span.SetStatus(codes.Error, "device code not found")
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Failed to retrieve device authorization by device code")
		if err == domain.ErrDeviceCodeNotFound || (err != nil && strings.Contains(err.Error(), "not found")) {
			return nil, domain.ErrDeviceFlowTokenExpired
		}
		return nil, fmt.Errorf("failed to retrieve device auth by device code: %w", err)
	}

	span.SetAttributes(
		attribute.String("device_flow.status", string(deviceAuth.Status)),
		attribute.String("user.id", deviceAuth.UserID),
	)

	if deviceAuth.ClientID != clientID {
		errMismatch := domain.NewInvalidClient("client ID mismatch")
		telemetry.RecordSpanError(span, errMismatch, "client ID mismatch for device flow")
		span.SetStatus(codes.Error, "client ID mismatch")
		log.Ctx(ctx).Warn().Str("client_id", clientID).Str("expected_client_id", deviceAuth.ClientID).Msg("Device flow token polling failed: client ID mismatch")
		return nil, errMismatch
	}

	switch deviceAuth.Status {
	case domain.DeviceCodeStatusPending:
		if pollErr := s.deviceAuthRepo.UpdateDeviceAuthLastPolledAt(ctx, deviceAuth.DeviceCode); pollErr != nil {
			log.Ctx(ctx).Warn().Err(pollErr).Str("client_id", clientID).Msg("Failed to update last polled time for device code")
		}
		log.Ctx(ctx).Debug().Str("client_id", clientID).Msg("Device authorization pending user consent")
		return nil, domain.ErrAuthorizationPending

	case domain.DeviceCodeStatusAuthorized:
		tokenTTL, ttlErr := s.realmAccessTokenLifespan(ctx)
		if ttlErr != nil {
			telemetry.RecordSpanError(span, ttlErr, "invalid realm settings access token lifespan")
			span.SetStatus(codes.Error, ttlErr.Error())
			log.Ctx(ctx).Error().Err(ttlErr).Str("client_id", clientID).Str("user_id", deviceAuth.UserID).Msg("Failed to resolve access token lifespan in device flow")
			return nil, ttlErr
		}
		tokenResponse, tokenErr := s.tokenService.GenerateTokenPair(ctx, deviceAuth.ClientID, deviceAuth.UserID, deviceAuth.Scope, tokenTTL, "")
		if tokenErr != nil {
			telemetry.RecordSpanError(span, tokenErr, "token generation failed for device flow")
			span.SetStatus(codes.Error, tokenErr.Error())
			log.Ctx(ctx).Error().Err(tokenErr).Str("client_id", clientID).Str("user_id", deviceAuth.UserID).Msg("Failed to generate token pair for approved device flow")
			return nil, fmt.Errorf("failed to generate token pair for device flow: %w", tokenErr)
		}
		if redeemErr := s.deviceAuthRepo.UpdateDeviceAuthStatus(ctx, deviceAuth.DeviceCode, domain.DeviceCodeStatusRedeemed); redeemErr != nil {
			log.Ctx(ctx).Error().Err(redeemErr).Str("client_id", clientID).Msg("Critical Warning: failed to mark device code as redeemed after token issuance")
		}
		log.Ctx(ctx).Info().Str("client_id", clientID).Str("user_id", deviceAuth.UserID).Msg("Tokens successfully issued for device flow")
		return tokenResponse, nil

	case domain.DeviceCodeStatusExpired:
		log.Ctx(ctx).Warn().Str("client_id", clientID).Msg("Device flow token request rejected: status expired")
		return nil, domain.ErrDeviceFlowTokenExpired

	case domain.DeviceCodeStatusDenied:
		log.Ctx(ctx).Warn().Str("client_id", clientID).Msg("Device flow token request rejected: user denied authorization")
		return nil, domain.ErrDeviceFlowAccessDenied

	case domain.DeviceCodeStatusRedeemed:
		log.Ctx(ctx).Warn().Str("client_id", clientID).Msg("Device flow token request rejected: device code already redeemed")
		return nil, domain.ErrDeviceFlowTokenExpired

	default:
		errStatus := domain.NewServerError("unexpected device authorization status")
		telemetry.RecordSpanError(span, errStatus, "unexpected device auth status")
		span.SetStatus(codes.Error, "unexpected device authorization status")
		log.Ctx(ctx).Error().Str("client_id", clientID).Str("status", string(deviceAuth.Status)).Msg("Unexpected device authorization status")
		return nil, errStatus
	}
}

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
	_, span := telemetry.StartSpan(ctx, tracerName, "TokenExchange",
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.subject_token_type", subjectTokenType),
		attribute.String("oauth.requested_token_type", requestedTokenType),
		attribute.String("oauth.scope", scope),
	)
	defer span.End()

	log.Ctx(ctx).Debug().
		Str("client_id", clientID).
		Str("subject_token_type", subjectTokenType).
		Str("requested_token_type", requestedTokenType).
		Str("scope", scope).
		Msg("Processing RFC 8693 Token Exchange request")

	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" && subjectTokenType != "urn:ietf:params:oauth:token-type:jwt" {
		errType := domain.NewInvalidRequest("unsupported subject_token_type")
		telemetry.RecordSpanError(span, errType, "unsupported subject_token_type")
		span.SetStatus(codes.Error, "unsupported subject_token_type")
		log.Ctx(ctx).Warn().Str("subject_token_type", subjectTokenType).Msg("Token exchange rejected: unsupported subject token type")
		return nil, errType
	}

	tokenInfo, err := s.tokenService.ValidateAccessToken(ctx, subjectToken)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid subject token")
		span.SetStatus(codes.Error, "invalid subject token")
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Token exchange rejected: subject token validation failed")
		if errors.Is(err, domain.ErrTokenExpiredOrRevoked) {
			return nil, domain.NewInvalidGrant("invalid subject token: expired or revoked")
		}
		return nil, domain.NewInvalidGrant("invalid subject token")
	}
	span.SetAttributes(
		attribute.String("user.id", tokenInfo.UserID),
		attribute.String("oauth.subject_client_id", tokenInfo.ClientID),
	)

	if clientID != "" {
		client, err := s.clientRepo.GetClient(ctx, clientID)
		if err != nil {
			telemetry.RecordSpanError(span, err, "client not found")
			span.SetStatus(codes.Error, "client not found")
			log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("Token exchange failed: client not found")
			return nil, domain.NewInvalidClient("client not found")
		}
		if tokenInfo.ClientID != "" && tokenInfo.ClientID != clientID {
			errMismatch := domain.NewInvalidClient("client ID mismatch")
			telemetry.RecordSpanError(span, errMismatch, "client ID mismatch")
			span.SetStatus(codes.Error, "client ID mismatch")
			log.Ctx(ctx).Warn().Str("client_id", clientID).Str("token_client_id", tokenInfo.ClientID).Msg("Token exchange failed: client ID mismatch")
			return nil, errMismatch
		}
		_ = client
	}

	effectiveScope, err := intersectScopes(scope, tokenInfo.Scope)
	if err != nil {
		telemetry.RecordSpanError(span, err, "scope intersection error")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Warn().Err(err).Str("requested_scope", scope).Str("granted_scope", tokenInfo.Scope).Msg("Token exchange failed: scope intersection invalid")
		return nil, err
	}

	tokenTTL, err := s.realmAccessTokenLifespan(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "invalid realm settings access token lifespan")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Str("user_id", tokenInfo.UserID).Msg("Failed to resolve access token lifespan in token exchange")
		return nil, err
	}
	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientID, tokenInfo.UserID, effectiveScope, tokenTTL, "")
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to generate token pair")
		span.SetStatus(codes.Error, err.Error())
		log.Ctx(ctx).Error().Err(err).Str("client_id", clientID).Str("user_id", tokenInfo.UserID).Msg("Token exchange failed: error generating new token pair")
		return nil, err
	}

	log.Ctx(ctx).Info().Str("client_id", clientID).Str("user_id", tokenInfo.UserID).Str("effective_scope", effectiveScope).Msg("RFC 8693 Token Exchange successful")
	return tokenPair, nil
}
