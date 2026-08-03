package services

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/metrics"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var errMissingKidSAValidation = errors.New("missing kid header, not a service account token, try other validation")

const tokenTracerName = "token-service"

// TokenService handles token generation and validation
type defaultTokenService struct {
	repo   domain.TokenRepository // Changed to domain.TokenRepository
	cache  cache.TokenStore
	issuer string

	signer *TokenSigner

	// Added for SA token validation
	pubKeyRepo domain.PublicKeyRepository
	saRepo     domain.ServiceAccountRepository
	userRepo  domain.UserRepository // New dependency

	// For user attribute mappers (optional - nil checks when not configured)
	userAttrMapperRepo domain.UserAttributeMapperRepository
	userAttrRepo       domain.UserAttributeRepository

	// For Keycloak-style protocol mappers (optional - nil checks when not configured)
	protocolMapperRepo domain.ProtocolMapperRepository

	// For Keycloak-style role & group claims (optional - nil checks when not configured)
	groupRepo domain.GroupRepository
	roleRepo  domain.RoleRepository
}

// newDefaultTokenService creates a new TokenService instance (internal constructor).
func newDefaultTokenService(
	repo domain.TokenRepository,
	tokenCache cache.TokenStore,
	issuer string,
	signer *TokenSigner,
	pubKeyRepo domain.PublicKeyRepository,
	saRepo domain.ServiceAccountRepository,
	userRepo domain.UserRepository,
	userAttrMapperRepo domain.UserAttributeMapperRepository,
	userAttrRepo domain.UserAttributeRepository,
	protocolMapperRepo domain.ProtocolMapperRepository,
	groupRepo domain.GroupRepository,
	roleRepo domain.RoleRepository,
) *defaultTokenService {
	return &defaultTokenService{
		repo:               repo,
		cache:              tokenCache,
		issuer:             issuer,
		signer:             signer,
		pubKeyRepo:         pubKeyRepo,
		saRepo:             saRepo,
		userRepo:           userRepo,
		userAttrMapperRepo: userAttrMapperRepo,
		userAttrRepo:       userAttrRepo,
		protocolMapperRepo: protocolMapperRepo,
		groupRepo:          groupRepo,
		roleRepo:           roleRepo,
	}
}

// NewTokenService creates a new TokenService instance (public constructor).
func NewTokenService(
	repo domain.TokenRepository,
	tokenCache cache.TokenStore,
	issuer string,
	signer *TokenSigner,
	pubKeyRepo domain.PublicKeyRepository,
	saRepo domain.ServiceAccountRepository,
	userRepo domain.UserRepository,
	userAttrMapperRepo domain.UserAttributeMapperRepository,
	userAttrRepo domain.UserAttributeRepository,
	groupRepo domain.GroupRepository,
	roleRepo domain.RoleRepository,
) *defaultTokenService {
	return &defaultTokenService{
		repo:       repo,
		cache:      tokenCache,
		issuer:     issuer,
		signer:     signer,
		pubKeyRepo: pubKeyRepo,
		saRepo:     saRepo,
		userRepo:  userRepo,
		userAttrMapperRepo: userAttrMapperRepo,
		userAttrRepo: userAttrRepo,
		groupRepo:  groupRepo,
		roleRepo:   roleRepo,
	}
}

// Removed local Token struct definition, will use domain.Token

// ToEntry converts a domain.Token to a cache.TokenEntry.
func toCacheEntry(t *domain.Token) *cache.TokenEntry { // Ensure cache pkg is imported
	return &cache.TokenEntry{
		ID: t.ID, UserID: t.UserID, ClientID: t.ClientID,
		Scope: t.Scope, ExpiresAt: t.ExpiresAt, IsRevoked: t.IsRevoked,
		Roles: t.Roles, // Add Roles
		// Issuer and other fields not in TokenEntry are omitted
		SessionID: t.SessionID,
	}
}

// fromCacheEntry populates a domain.Token from a cache.TokenEntry.
func fromCacheEntry(entry *cache.TokenEntry, tokenValue string) *domain.Token { // Ensure cache pkg is imported
	// TokenValue, CreatedAt, LastUsedAt, Issuer are not in TokenEntry.
	// These will be missing if token is only populated from cache.
	// This function might need to return a partially populated token or fetch more details.
	// For now, it populates what's available.
	return &domain.Token{
		ID:         entry.ID,
		UserID:     entry.UserID,
		ClientID:   entry.ClientID,
		Scope:      entry.Scope,
		ExpiresAt:  entry.ExpiresAt,
		IsRevoked:  entry.IsRevoked,
		Roles:      entry.Roles,
		SessionID:  entry.SessionID,
		TokenValue: tokenValue, // Pass tokenValue if needed for context
		// TokenType, CreatedAt, LastUsedAt, Issuer would need to be set if required by caller
	}
}

type CreateTokenOptions struct {
	// TokenID is the unique ID for the token (UUID)
	TokenID string
	// Scope is the scope for the token (if its an access token)
	Scope string
	// ClientID is the client ID for the token
	ClientID string
	// UserID is the user ID for the token
	UserID string
	// TokenType is either "access_token", "refresh_token", "id_token"
	TokenType string
	// ExpireIn is the expiration time for the token, in duration (e.g. 24h)
	ExpireIn time.Duration
	// SigningKeyID is the ID of the signing key in the TokenSigner. When empty, the default key will be used.
	SigningKeyID string
}

// CreateToken creates a new token with the given options and claims.
func (s *defaultTokenService) CreateToken(ctx context.Context, opts domain.CreateTokenOptions, claims jwt.Claims) (*domain.Token, error) {
	ctx, span := telemetry.StartSpan(ctx, tokenTracerName, "CreateToken",
		attribute.String("user.id", opts.UserID),
		attribute.String("token.type", opts.TokenType),
		attribute.String("oauth.client_id", opts.ClientID),
	)
	defer span.End()

	expiresAt := time.Now().Add(opts.ExpireIn)

	// ? This is a default claim object, it can be used for both access and refresh tokens.
	// ? Later it should be changed to a specific one for access_token, and id_token
	// Access token claims
	tokenClaimsMap := jwt.MapClaims{
		"iss": s.issuer,
		"sub": opts.UserID,
		"aud": jwt.ClaimStrings{opts.ClientID},
		"exp": jwt.NewNumericDate(expiresAt).Unix(),
		"iat": jwt.NewNumericDate(time.Now()).Unix(),
		"nbf": jwt.NewNumericDate(time.Now()).Unix(),
		"jti": opts.TokenID,
	}

	var userRoles []string
	if len(opts.Roles) > 0 {
		userRoles = opts.Roles
		tokenClaimsMap["roles"] = userRoles
	} else if opts.UserID != "" {
		user, errUser := s.userRepo.GetUserByID(ctx, opts.UserID)
		if errUser != nil {
			log.Ctx(ctx).Warn().Err(errUser).Str("userID", opts.UserID).Msg("CreateToken: failed to get user for roles, proceeding without roles claim.")
		} else if user != nil {
			userRoles = user.Roles
			if len(userRoles) > 0 {
				tokenClaimsMap["roles"] = userRoles
			}
			if opts.TokenType == api.TokenTypeAccessToken {
				s.applyRoleAndGroupClaims(ctx, tokenClaimsMap, opts, user)
			}
		}
	}

	if opts.SessionID != "" {
		tokenClaimsMap["sid"] = opts.SessionID
	}

	// Apply token attribute mappers for access tokens
	if opts.TokenType == api.TokenTypeAccessToken {
		if err := s.ApplyTokenMappers(ctx, tokenClaimsMap, opts.ClientID, opts.UserID, api.TokenTypeAccessToken); err != nil {
			log.Ctx(ctx).Warn().Err(err).Str("client_id", opts.ClientID).Str("user_id", opts.UserID).Msg("CreateToken: failed to apply token mappers for access token")
			telemetry.RecordSpanError(span, err, "failed to apply token mappers")
		}
	}

	signedToken, err := s.signer.Sign(tokenClaimsMap, s.resolveSigningKeyID(opts.SigningKeyID, opts.ClientID))
	if err != nil {
			telemetry.RecordSpanError(span, err, "failed to sign token")
			span.SetStatus(codes.Error, "failed to sign token")
			return nil, err
		}

	// Store token in repository
	token := &domain.Token{ // Changed to domain.Token
		ID:         opts.TokenID,
		TokenType:  opts.TokenType,
		TokenValue: signedToken,
		ClientID:   opts.ClientID,
		UserID:     opts.UserID,
		Scope:      opts.Scope,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		Roles:      userRoles, // Store roles in the token struct
		SessionID:  opts.SessionID,
	}
		if err := s.repo.StoreToken(ctx, token); err != nil {
			telemetry.RecordSpanError(span, err, "failed to store token")
			span.SetStatus(codes.Error, "failed to store token")
			return nil, err
		}

	if opts.TokenType == api.TokenTypeAccessToken {
		// Store token in cache
		if err := s.cache.Set(ctx, toCacheEntry(token)); err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("failed to cache token")
		}
	}
	if metrics.TokensCreatedTotal != nil {
		metrics.TokensCreatedTotal.Inc()
	}
	return token, nil
}

// applyRoleAndGroupClaims adds Keycloak-style role claims to an access token:
// realm_access.roles (user roles + group-derived realm roles) and
// resource_access.<clientID>.roles (user client roles + group-derived client
// roles). Group role references are role IDs and are resolved to names via the
// role repository. Both repositories are optional; when either is nil the
// claims are skipped (backward compatible).
func (s *defaultTokenService) applyRoleAndGroupClaims(ctx context.Context, tokenClaimsMap jwt.MapClaims, opts domain.CreateTokenOptions, user *domain.User) {
	if s.groupRepo == nil || s.roleRepo == nil {
		return
	}

	realmRoles := make(map[string]bool)
	for _, name := range user.Roles {
		if name != "" {
			realmRoles[name] = true
		}
	}

	clientRoles := make(map[string]map[string]bool)
	for clientID, names := range user.ClientRoles {
		for _, name := range names {
			if name == "" {
				continue
			}
			if clientRoles[clientID] == nil {
				clientRoles[clientID] = make(map[string]bool)
			}
			clientRoles[clientID][name] = true
		}
	}

	groups, err := s.groupRepo.GetGroupsByUserID(ctx, opts.UserID)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("userID", opts.UserID).Msg("CreateToken: failed to get groups for role claims, proceeding without group-derived roles.")
	}

	for _, group := range groups {
		for _, roleID := range group.RealmRoles {
			role, errRole := s.roleRepo.GetRoleByID(ctx, roleID)
			if errRole != nil || role == nil {
				continue
			}
			realmRoles[role.Name] = true
		}
		for clientID, roleIDs := range group.ClientRoles {
			for _, roleID := range roleIDs {
				role, errRole := s.roleRepo.GetRoleByID(ctx, roleID)
				if errRole != nil || role == nil {
					continue
				}
				if clientRoles[clientID] == nil {
					clientRoles[clientID] = make(map[string]bool)
				}
				clientRoles[clientID][role.Name] = true
			}
		}
	}

	if len(realmRoles) > 0 {
		tokenClaimsMap["realm_access"] = map[string]any{
			"roles": sortedKeys(realmRoles),
		}
	}
	if len(clientRoles) > 0 {
		resourceAccess := make(map[string]any)
		for clientID, roles := range clientRoles {
			resourceAccess[clientID] = map[string]any{
				"roles": sortedKeys(roles),
			}
		}
		tokenClaimsMap["resource_access"] = resourceAccess
	}
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// resolveSigningKeyID picks the client's dedicated key with realm-default fallback unless explicit is set.
func (s *defaultTokenService) resolveSigningKeyID(explicit, clientID string) string {
	if explicit != "" {
		return explicit
	}
	keyID, _ := s.signer.ResolveSigningKeyID(clientID)
	return keyID
}

// BuildToken builds the token value for an existing token struct.
func (s *defaultTokenService) BuildToken(token *domain.Token) error { // Changed to domain.Token
	// ? This is a default claim object, it can be used for both access and refresh tokens.
	// ? Later it should be changed to a specific one for access_token, and id_token
	// Access token claims
	tokenMapClaims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": token.UserID,
		"aud": jwt.ClaimStrings{token.ClientID},
		"exp": jwt.NewNumericDate(token.ExpiresAt).Unix(),
		"iat": jwt.NewNumericDate(token.CreatedAt).Unix(),
		"nbf": jwt.NewNumericDate(token.CreatedAt).Unix(),
		"jti": token.ID,
	}

	// Fetch and add roles if UserID is present (context needed for repo call)
	// BuildToken might need to accept context if it's to fetch roles.
	// For now, let's assume if token.Roles is already populated, it uses that.
	// If not, and UserID is present, it would ideally fetch. This implies BuildToken needs context.
	// Let's simplify: if token.Roles is already populated (e.g. by caller), use it.
	// This is a limitation if BuildToken is called with a Token struct that hasn't had Roles populated yet.
	// A better BuildToken would take context and fetch roles if needed.
	// For this subtask, we will assume token.Roles might be pre-populated by the caller if roles are desired.
	// Or, more realistically, BuildToken is primarily for re-signing an existing ssso.Token, which should have roles.
	if len(token.Roles) > 0 {
		tokenMapClaims["roles"] = token.Roles
	}
	// If UserID is present and token.Roles is empty, one might fetch roles here if context was available.
	// else if token.UserID != "" && s.userRepo != nil { /* fetch roles - needs context */ }

	signedToken, err := s.signer.Sign(tokenMapClaims, s.resolveSigningKeyID("", token.ClientID))
	if err != nil {
		return fmt.Errorf("cannot sign token: %w", err)
	}

	token.TokenValue = signedToken

	return nil
}

// func (s *defaultTokenService) generateUserTokens(ctx context.Context, userID, clientID, scope string) (*TokenResponse, error) {
// 	tokenID := uuid.NewString()

// 	// Generate access token
// 	signedToken, err := s.CreateToken(CreateTokenOptions{
// 		TokenID:      tokenID,
// 		ClientID:     clientID,
// 		UserID:       userID,
// 		Scope:        scope,
// 		ExpireIn:     time.Hour,
// 		TokenType:    api.TokenTypeAccessToken,
// 		SigningKeyID: "", // Use the default
// 	}, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	token := &Token{
// 		ID:         tokenID,
// 		TokenType:  "access_token",
// 		TokenValue: signedToken,
// 		ClientID:   clientID,
// 		UserID:     userID,
// 		ExpiresAt:  time.Now().Add(time.Hour),
// 		CreatedAt:  time.Now(),
// 		LastUsedAt: time.Now(),
// 		Scope:      scope,
// 		IsRevoked:  false,
// 	}
// 	if err := s.repo.StoreToken(ctx, token); err != nil {
// 		return nil, err
// 	}

// 	// Generate refresh token
// 	refreshTokenClaims := jwt.RegisteredClaims{
// 		Issuer:  s.issuer,
// 		Subject: userID,
// 		Audience: jwt.ClaimStrings{
// 			clientID,
// 		},
// 		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
// 		IssuedAt:  jwt.NewNumericDate(time.Now()),
// 		NotBefore: jwt.NewNumericDate(time.Now()),
// 		ID:        refreshTokenID,
// 	}

// 	signedRefreshToken, err := s.signer(refreshTokenClaims)
// 	if err != nil {
// 		return nil, err
// 	}

// 	token = &Token{
// 		ID:         refreshTokenID,
// 		TokenType:  "refresh_token",
// 		TokenValue: signedRefreshToken,
// 		ClientID:   clientID,
// 		UserID:     userID,
// 		ExpiresAt:  refreshTokenClaims.ExpiresAt.Time,
// 		CreatedAt:  time.Now(),
// 		LastUsedAt: time.Now(),
// 	}
// 	if err := s.repo.StoreToken(ctx, token); err != nil {
// 		return nil, err
// 	}

// 	return &TokenResponse{
// 		AccessToken:  signedAccessToken,
// 		TokenType:    "Bearer",
// 		ExpiresIn:    3600,
// 		RefreshToken: signedRefreshToken,
// 		Scope:        scope,
// 	}, nil
// }

// GenerateTokenPair creates a new access and refresh token pair. sessionID, when
// non-empty, is emitted as the `sid` claim on the access, refresh, and ID
// tokens so RP-initiated and back-channel logout can correlate the session
// (see internal/oidclogout and api/openidv2_1/logout_register.go).
func (s *defaultTokenService) GenerateTokenPair(ctx context.Context,
	clientID, userID, scope string, tokenTTL time.Duration, sessionID string,
) (*api.TokenResponse, error) {
	ctx, span := telemetry.StartSpan(ctx, tokenTracerName, "GenerateTokenPair",
		attribute.String("user.id", userID),
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.scope", scope),
	)
	defer span.End()

	// Generate access token
	accessTokenID := uuid.NewString()
	accessToken, err := s.CreateToken(ctx, domain.CreateTokenOptions{
		TokenID:      accessTokenID,
		Scope:        scope,
		ClientID:     clientID,
		UserID:       userID,
		TokenType:    api.TokenTypeAccessToken,
		ExpireIn:     tokenTTL,
		SigningKeyID: "", // Use default key
		SessionID:    sessionID,
	}, nil) // claims can be nil, CreateToken will make its own MapClaims
	if err != nil {
			telemetry.RecordSpanError(span, err, "failed to create access token")
			span.SetStatus(codes.Error, "failed to create access token")
			return nil, fmt.Errorf("failed to create access token: %w", err)
		}

		// Generate refresh token
	refreshTokenID := uuid.NewString()
	refreshTokenTTL := tokenTTL * 24 // Example: Refresh token lives 24x longer
	refreshToken, err := s.CreateToken(ctx, domain.CreateTokenOptions{
		TokenID:      refreshTokenID,
		Scope:        scope,
		ClientID:     clientID,
		UserID:       userID,
		TokenType:    api.TokenTypeRefreshToken,
		ExpireIn:     refreshTokenTTL,
		SigningKeyID: "", // Use default key
		SessionID:    sessionID,
	}, nil)
	if err != nil {
			telemetry.RecordSpanError(span, err, "failed to create refresh token")
			span.SetStatus(codes.Error, "failed to create refresh token")
			return nil, fmt.Errorf("failed to create refresh token: %w", err)
		}

	// CreateToken already handles storing in repo and caching for access tokens.
	// The metrics.TokensCreatedTotal.Inc() is also called within CreateToken.

	var idToken string
	if strings.Contains(scope, "openid") {
		idToken, err = s.GenerateIDToken(ctx, userID, clientID, "", sessionID, time.Now(), scope)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("failed to generate ID token, continuing without it")
			idToken = ""
		}
	}

	return &api.TokenResponse{
		IDToken:      idToken,
		AccessToken:  accessToken.TokenValue,
		TokenType:    "Bearer", // Standard token type for responses
		ExpiresIn:    int(tokenTTL.Seconds()),
		RefreshToken: refreshToken.TokenValue,
	}, nil
}

func (s *defaultTokenService) ValidateAccessToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	_, span := telemetry.StartSpan(ctx, tokenTracerName, "ValidateAccessToken")
	defer span.End()

	parsedSAJWT, err := jwt.ParseWithClaims(tokenValue, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errMissingKidSAValidation
		}
		publicKeyInfo, errDb := s.pubKeyRepo.GetPublicKey(ctx, kid)
		if errDb != nil {
			// If the kid simply isn't in the SA key store (key not found), signal
			// errMissingKidSAValidation so the outer fallback tries user-token validation.
			// This is the normal case for user JWTs whose kid belongs to a realm signing key.
			if strings.Contains(errDb.Error(), "not found") {
				return nil, errMissingKidSAValidation
			}
			log.Ctx(ctx).Warn().Err(errDb).Str("kid", kid).Msg("Failed to get public key for SA JWT")
			return nil, fmt.Errorf("SA key retrieval failed for kid %s: %w", kid, errDb)
		}
		if publicKeyInfo.Status != "ACTIVE" {
			return nil, fmt.Errorf("public key %s is not active", kid)
		}
		block, _ := pem.Decode([]byte(publicKeyInfo.PublicKey))
		if block == nil {
			return nil, errors.New("failed to decode PEM block for SA public key")
		}
		pub, errParse := x509.ParsePKIXPublicKey(block.Bytes)
		if errParse != nil {
			return nil, fmt.Errorf("failed to parse SA public key: %w", errParse)
		}
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, errors.New("public key is not RSA type")
	})

	if err == nil {
		if parsedSAJWT.Valid {
			claims, ok := parsedSAJWT.Claims.(*jwt.MapClaims)
			if !ok {
				telemetry.RecordSpanError(span, errors.New("invalid claims type in SA JWT"), "invalid claims type")
				span.SetStatus(codes.Error, "invalid claims type in SA JWT")
				return nil, errors.New("invalid claims type in SA JWT")
			}
			issuerClaim, _ := (*claims)["iss"].(string)
			if issuerClaim == "" {
				telemetry.RecordSpanError(span, errors.New("SA JWT missing 'iss' claim"), "missing iss claim")
				span.SetStatus(codes.Error, "SA JWT missing 'iss' claim")
				return nil, errors.New("SA JWT missing 'iss' claim")
			}
			var expiresAt time.Time
			if exp, okClaim := (*claims)["exp"].(float64); okClaim {
				expiresAt = time.Unix(int64(exp), 0)
			} else {
				telemetry.RecordSpanError(span, errors.New("SA JWT missing 'exp' claim"), "missing exp claim")
				span.SetStatus(codes.Error, "SA JWT missing 'exp' claim")
				return nil, errors.New("SA JWT missing 'exp' claim")
			}
			if time.Now().After(expiresAt) {
				telemetry.RecordSpanError(span, domain.ErrTokenExpiredOrRevoked, "SA JWT expired")
				span.SetStatus(codes.Error, "SA JWT expired")
				return nil, domain.ErrTokenExpiredOrRevoked
			}
			var issuedAt time.Time
			if iat, okClaim := (*claims)["iat"].(float64); okClaim {
				issuedAt = time.Unix(int64(iat), 0)
			} else {
				telemetry.RecordSpanError(span, errors.New("SA JWT missing 'iat' claim"), "missing iat claim")
				span.SetStatus(codes.Error, "SA JWT missing 'iat' claim")
				return nil, errors.New("SA JWT missing 'iat' claim")
			}
			var tokenScope string
			if scope, okClaim := (*claims)["scope"].(string); okClaim {
				tokenScope = scope
			}
			jtiClaim, _ := (*claims)["jti"].(string)
			return &domain.Token{
				ID:         jtiClaim,
				TokenType:  "service_account_jwt",
				TokenValue: tokenValue,
				UserID:     issuerClaim,
				Scope:      tokenScope,
				ExpiresAt:  expiresAt,
				CreatedAt:  issuedAt,
				IsRevoked:  false,
				Issuer:     issuerClaim,
				Roles:      []string{},
			}, nil
		} else {
			errInvalid := fmt.Errorf("SA JWT parsed (err is nil) but token.Valid is false, unexpected state")
			telemetry.RecordSpanError(span, errInvalid, "SA JWT invalid state")
			span.SetStatus(codes.Error, "SA JWT invalid state")
			return nil, errInvalid
		}
	}

	if errors.Is(err, errMissingKidSAValidation) || (err != nil && strings.Contains(err.Error(), "malformed")) {
		log.Ctx(ctx).Debug().Msg("Attempting user token validation (SA token 'kid' missing or error explicitly requesting fallback).")
		return s.validateUserToken(ctx, tokenValue)
	}

	errFinal := fmt.Errorf("SA JWT processing error: %w", err)
	telemetry.RecordSpanError(span, errFinal, "SA JWT processing error")
	span.SetStatus(codes.Error, "SA JWT processing error")
	return nil, errFinal
}

func (s *defaultTokenService) validateUserToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	if s.signer.HasRSASigner() {
		if token, err := s.validateRS256Token(tokenValue); err == nil {
			return token, nil
		}
	}

	if entry, cacheErr := s.cache.Get(ctx, tokenValue); cacheErr == nil && entry != nil {
		if !entry.IsRevoked && time.Now().Before(entry.ExpiresAt) {
			userToken := fromCacheEntry(entry, tokenValue)
			userToken.Issuer = s.issuer
			return userToken, nil
		}
		_ = s.cache.Delete(ctx, tokenValue)
		return nil, domain.ErrTokenExpiredOrRevoked
	}

	userTokenDB, repoErr := s.repo.GetAccessToken(ctx, tokenValue)
	if repoErr != nil {
		return nil, fmt.Errorf("token not found or invalid: %w", repoErr)
	}
	if userTokenDB.IsRevoked || time.Now().After(userTokenDB.ExpiresAt) {
		return nil, domain.ErrTokenExpiredOrRevoked
	}
	if userTokenDB.Issuer == "" {
		userTokenDB.Issuer = s.issuer
	}

		if cacheSetErr := s.cache.Set(ctx, toCacheEntry(userTokenDB)); cacheSetErr != nil {
			log.Ctx(ctx).Warn().Err(cacheSetErr).Msg("failed to cache user token")
		}
	return userTokenDB, nil
}

func (s *defaultTokenService) validateRS256Token(tokenValue string) (*domain.Token, error) {
	pubKey := s.signer.GetRSAPublicKey()
	if pubKey == nil {
		return nil, errors.New("no RSA public key available for validation")
	}

	token, err := jwt.ParseWithClaims(tokenValue, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("RS256 token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("RS256 token is invalid")
	}

	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type in RS256 token")
	}

	userID, _ := (*claims)["sub"].(string)
	if userID == "" {
		return nil, errors.New("RS256 token missing 'sub' claim")
	}

	var expiresAt time.Time
	if exp, ok := (*claims)["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	} else {
		return nil, errors.New("RS256 token missing 'exp' claim")
	}

	if time.Now().After(expiresAt) {
		return nil, domain.ErrTokenExpiredOrRevoked
	}

	var issuedAt time.Time
	if iat, ok := (*claims)["iat"].(float64); ok {
		issuedAt = time.Unix(int64(iat), 0)
	}

	jtiClaim, _ := (*claims)["jti"].(string)
	issuerClaim, _ := (*claims)["iss"].(string)
	var tokenScope string
	if scope, ok := (*claims)["scope"].(string); ok {
		tokenScope = scope
	}

	var roles []string
	if rolesRaw, ok := (*claims)["roles"].([]interface{}); ok {
		for _, r := range rolesRaw {
			if roleStr, ok := r.(string); ok {
				roles = append(roles, roleStr)
			}
		}
	}

	if issuerClaim == "" {
		issuerClaim = s.issuer
	}

	return &domain.Token{
		ID:         jtiClaim,
		TokenType:  "access_token",
		TokenValue: tokenValue,
		UserID:     userID,
		Scope:      tokenScope,
		ExpiresAt:  expiresAt,
		CreatedAt:  issuedAt,
		IsRevoked:  false,
		Issuer:     issuerClaim,
		Roles:      roles,
	}, nil
}

func (s *defaultTokenService) RevokeToken(ctx context.Context, token string) error {
	_, span := telemetry.StartSpan(ctx, tokenTracerName, "RevokeToken")
	defer span.End()

	if err := s.cache.Delete(ctx, token); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("failed to delete token from cache")
	}

	if err := s.repo.RevokeToken(ctx, token); err != nil {
		telemetry.RecordSpanError(span, err, "failed to revoke token")
		span.SetStatus(codes.Error, "failed to revoke token")
		return err
	}
	return nil
}

// GetRefreshTokenInfo retrieves metadata about a refresh token. Returns the token info if found,
// or an error if not found or database error.
func (s *defaultTokenService) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) { // Changed to domain.TokenInfo
	return s.repo.GetRefreshTokenInfo(ctx, tokenValue)
}

// GetAccessTokenInfo retrieves metadata about an access token. Returns the token info if found,
// or an error if not found or database error.
func (s *defaultTokenService) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) { // Changed to domain.TokenInfo
	return s.repo.GetAccessTokenInfo(ctx, tokenValue)
}

// GenerateIDToken generates an ID token for a user.
func (s *defaultTokenService) GenerateIDToken(ctx context.Context, userID, clientID, nonce, sessionID string, authTime time.Time, scope string) (string, error) {
	_, span := telemetry.StartSpan(ctx, tokenTracerName, "GenerateIDToken",
		attribute.String("user.id", userID),
	)
	defer span.End()

	if userID == "" {
		err := errors.New("userID required for ID token")
		telemetry.RecordSpanError(span, err, "missing userID")
		span.SetStatus(codes.Error, "missing userID")
		return "", err
	}

	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get user for ID token")
		span.SetStatus(codes.Error, "failed to get user for ID token")
		return "", fmt.Errorf("failed to get user for ID token: %w", err)
	}
	if user == nil {
		err := errors.New("user not found for ID token")
		telemetry.RecordSpanError(span, err, "user not found")
		span.SetStatus(codes.Error, "user not found for ID token")
		return "", err
	}

	claims := jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       userID,
		"aud":       clientID,
		"exp":       jwt.NewNumericDate(authTime.Add(time.Hour)),
		"iat":       jwt.NewNumericDate(authTime),
		"auth_time": jwt.NewNumericDate(authTime),
		"email":     user.Email,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	if sessionID != "" {
		claims["sid"] = sessionID
	}

	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		if s == "profile" {
			claims["name"] = strings.TrimSpace(user.FirstName + " " + user.LastName)
			claims["preferred_username"] = user.Email
		} else if s == "email" {
			claims["email"] = user.Email
			claims["email_verified"] = true
		}
	}

	if err := s.ApplyTokenMappers(ctx, claims, clientID, userID, api.TokenTypeIDToken); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Str("user_id", userID).Msg("GenerateIDToken: failed to apply token mappers")
	}

	return s.signer.Sign(claims, s.resolveSigningKeyID("", clientID))
}

// ValidateIDToken validates an ID token.
func (s *defaultTokenService) ValidateIDToken(ctx context.Context, tokenValue string) (map[string]interface{}, error) {
	return nil, errors.New("not implemented: ValidateIDToken requires JWKS setup, see skipped tests")
}

// setNestedClaim sets a claim value in the map, supporting dot-notation
// for nested keys (e.g. "realm_access.roles" creates {"realm_access": {"roles": value}}).
// This allows token mappers to produce Grafana-compatible nested claim structures
// like realm_access.roles and resource_access.<client_id>.roles dynamically.
func setNestedClaim(claims map[string]interface{}, key string, value interface{}) {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) == 1 {
		mergeClaimValue(claims, key, value)
		return
	}
	prefix := parts[0]
	suffix := parts[1]
	nested, ok := claims[prefix].(map[string]interface{})
	if !ok {
		nested = make(map[string]interface{})
		claims[prefix] = nested
	}
	setNestedClaim(nested, suffix, value)
}

// mergeClaimValue stores value under key, merging with an existing value:
// maps are merged key-by-key, string slices are appended de-duplicated with
// order preserved, and any other existing value is replaced.
func mergeClaimValue(claims map[string]interface{}, key string, value interface{}) {
	existing, ok := claims[key]
	if !ok {
		claims[key] = value
		return
	}
	switch newVal := value.(type) {
	case map[string]interface{}:
		if oldMap, ok := existing.(map[string]interface{}); ok {
			for k, v := range newVal {
				oldMap[k] = v
			}
			return
		}
	case []string:
		if oldSlice, ok := existing.([]string); ok {
			merged := append([]string{}, oldSlice...)
			seen := make(map[string]struct{}, len(merged))
			for _, s := range merged {
				seen[s] = struct{}{}
			}
			for _, s := range newVal {
				if _, dup := seen[s]; !dup {
					merged = append(merged, s)
					seen[s] = struct{}{}
				}
			}
			claims[key] = merged
			return
		}
	}
	claims[key] = value
}

// ApplyTokenMappers applies user attribute and Keycloak-style protocol mappers
// to the provided claims map. Each mapper category is optional and nil-safe:
// categories whose repositories are not configured are skipped entirely and
// never touch the claims. All steps are logged at debug level for traceability;
// applied mappings are logged at info level so operators can verify claims in
// production logs.
func (s *defaultTokenService) ApplyTokenMappers(ctx context.Context, claims map[string]interface{}, clientID, userID, tokenType string) error {
	ctx, span := telemetry.StartSpan(ctx, tokenTracerName, "ApplyTokenMappers",
		attribute.String("client_id", clientID),
		attribute.String("user_id", userID),
		attribute.String("token_type", tokenType),
	)
	defer span.End()

	logger := log.Ctx(ctx)

	totalApplied := 0
	totalSkipped := 0
	categoriesRun := 0

	if s.userAttrMapperRepo != nil && s.userAttrRepo != nil {
		categoriesRun++
		applied, skipped, err := s.applyUserAttributeMappers(ctx, claims, clientID, userID, tokenType)
		if err != nil {
			logger.Warn().Err(err).
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Msg("ApplyTokenMappers: user attribute mapper category failed")
			telemetry.RecordSpanError(span, err, "failed to apply user attribute mappers")
			span.SetStatus(codes.Error, "failed to apply user attribute mappers")
			return err
		}
		totalApplied += applied
		totalSkipped += skipped
	}

	if s.protocolMapperRepo != nil {
		categoriesRun++
		applied, skipped, err := s.applyProtocolMappers(ctx, claims, clientID, userID, tokenType)
		if err != nil {
			logger.Warn().Err(err).
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Msg("ApplyTokenMappers: protocol mapper category failed")
			telemetry.RecordSpanError(span, err, "failed to apply protocol mappers")
			span.SetStatus(codes.Error, "failed to apply protocol mappers")
			return err
		}
		totalApplied += applied
		totalSkipped += skipped
	}

	if categoriesRun == 0 {
		logger.Debug().
			Str("client_id", clientID).
			Str("user_id", userID).
			Str("token_type", tokenType).
			Msg("ApplyTokenMappers: no mapper repositories configured, nothing to apply")
		return nil
	}

	logger.Info().
		Str("client_id", clientID).
		Str("user_id", userID).
		Str("token_type", tokenType).
		Int("applied_count", totalApplied).
		Int("skipped_count", totalSkipped).
		Int("mapper_categories", categoriesRun).
		Msg("ApplyTokenMappers: completed")

	return nil
}

// applyUserAttributeMappers applies the existing user-attribute mapper category.
// It returns the number of mappers applied and skipped. Individual mappers whose
// user attribute is missing are skipped; repository failures are returned as
// errors so token issuance can surface them.
func (s *defaultTokenService) applyUserAttributeMappers(ctx context.Context, claims map[string]interface{}, clientID, userID, tokenType string) (int, int, error) {
	logger := log.Ctx(ctx)

	logger.Debug().
		Str("client_id", clientID).
		Str("user_id", userID).
		Str("token_type", tokenType).
		Msg("ApplyTokenMappers: fetching user attribute mappers for client")

	mappers, err := s.userAttrMapperRepo.GetMappersForClient(ctx, clientID, tokenType)
	if err != nil {
		logger.Warn().Err(err).
			Str("client_id", clientID).
			Str("user_id", userID).
			Str("token_type", tokenType).
			Msg("ApplyTokenMappers: failed to fetch user attribute mappers")
		return 0, 0, fmt.Errorf("failed to fetch token mappers: %w", err)
	}

	if len(mappers) == 0 {
		logger.Debug().
			Str("client_id", clientID).
			Str("user_id", userID).
			Str("token_type", tokenType).
			Msg("ApplyTokenMappers: no user attribute mappers configured for this client and token type")
		return 0, 0, nil
	}

	logger.Info().
		Str("client_id", clientID).
		Str("user_id", userID).
		Str("token_type", tokenType).
		Int("mapper_count", len(mappers)).
		Msg("ApplyTokenMappers: found configured user attribute mappers")

	userAttrs, err := s.userAttrRepo.GetAttributesByUserID(ctx, userID)
	if err != nil {
		logger.Warn().Err(err).
			Str("client_id", clientID).
			Str("user_id", userID).
			Str("token_type", tokenType).
			Msg("ApplyTokenMappers: failed to fetch user attributes")
		return 0, 0, fmt.Errorf("failed to fetch user attributes for token mappers: %w", err)
	}

	attrMap := make(map[string]string, len(userAttrs))
	for _, attr := range userAttrs {
		attrMap[attr.Name] = attr.Value
	}

	logger.Debug().
		Str("client_id", clientID).
		Str("user_id", userID).
		Str("token_type", tokenType).
		Int("attribute_count", len(userAttrs)).
		Strs("attribute_names", func() []string {
			names := make([]string, 0, len(userAttrs))
			for _, a := range userAttrs {
				names = append(names, a.Name)
			}
			return names
		}()).
		Msg("ApplyTokenMappers: fetched user attributes")

	appliedCount := 0
	skippedCount := 0

	for _, mapper := range mappers {
		attrValue, exists := attrMap[mapper.UserAttribute]
		if !exists {
			logger.Debug().
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Str("mapper_name", mapper.Name).
				Str("mapper_id", mapper.ID).
				Str("user_attribute", mapper.UserAttribute).
				Str("token_claim", mapper.TokenClaimName).
				Bool("multi_valued", mapper.MultiValued).
				Msg("ApplyTokenMappers: user attribute not found, skipping mapper")
			skippedCount++
			continue
		}

		if mapper.MultiValued {
			values := splitCSV(attrValue)
			setNestedClaim(claims, mapper.TokenClaimName, values)
			logger.Info().
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Str("mapper_name", mapper.Name).
				Str("mapper_id", mapper.ID).
				Str("user_attribute", mapper.UserAttribute).
				Str("token_claim", mapper.TokenClaimName).
				Strs("values", values).
				Int("value_count", len(values)).
				Msg("ApplyTokenMappers: applied multi-valued mapper")
		} else {
			setNestedClaim(claims, mapper.TokenClaimName, attrValue)
			logger.Info().
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Str("mapper_name", mapper.Name).
				Str("mapper_id", mapper.ID).
				Str("user_attribute", mapper.UserAttribute).
				Str("token_claim", mapper.TokenClaimName).
				Str("value", attrValue).
				Msg("ApplyTokenMappers: applied mapper")
		}
		appliedCount++
	}

	logger.Debug().
		Str("client_id", clientID).
		Str("user_id", userID).
		Str("token_type", tokenType).
		Int("applied_count", appliedCount).
		Int("skipped_count", skippedCount).
		Msg("ApplyTokenMappers: user attribute mappers done")

	return appliedCount, skippedCount, nil
}

// applyProtocolMappers evaluates Keycloak-style protocol mappers for the client.
// Only "openid-connect" protocol mappers are honored; other protocols (e.g.
// SAML) are skipped. The claim target comes from Config["claim.name"]
// (dot-notation supported) and the value from Config["claim.value"] or is
// derived per mapper type (realm/client roles, group membership, user
// attribute). Config["multivalued"] yields an array claim. Unknown mapper types
// and mappers without data are skipped, never failing token issuance.
func (s *defaultTokenService) applyProtocolMappers(ctx context.Context, claims map[string]interface{}, clientID, userID, tokenType string) (int, int, error) {
	logger := log.Ctx(ctx)

	logger.Debug().
		Str("client_id", clientID).
		Str("user_id", userID).
		Str("token_type", tokenType).
		Msg("ApplyTokenMappers: fetching protocol mappers for client")

	mappers, err := s.protocolMapperRepo.ListClientProtocolMappers(ctx, clientID)
	if err != nil {
		logger.Warn().Err(err).
			Str("client_id", clientID).
			Str("user_id", userID).
			Str("token_type", tokenType).
			Msg("ApplyTokenMappers: failed to fetch protocol mappers")
		return 0, 0, fmt.Errorf("failed to fetch protocol mappers: %w", err)
	}

	if len(mappers) == 0 {
		logger.Debug().
			Str("client_id", clientID).
			Str("user_id", userID).
			Str("token_type", tokenType).
			Msg("ApplyTokenMappers: no protocol mappers configured for this client")
		return 0, 0, nil
	}

	oidcMappers := make([]*domain.ProtocolMapper, 0, len(mappers))
	for _, mapper := range mappers {
		if mapper == nil {
			continue
		}
		if mapper.Protocol != "" && mapper.Protocol != "openid-connect" {
			logger.Debug().
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Str("mapper_name", mapper.Name).
				Str("mapper_id", mapper.ID).
				Str("protocol", mapper.Protocol).
				Msg("ApplyTokenMappers: skipping non-openid-connect protocol mapper")
			continue
		}
		oidcMappers = append(oidcMappers, mapper)
	}
	if len(oidcMappers) == 0 {
		return 0, 0, nil
	}

	needsUser, needsGroups, needsAttrs := mapperDataNeeds(oidcMappers)

	var user *domain.User
	if needsUser && s.userRepo != nil {
		user, err = s.userRepo.GetUserByID(ctx, userID)
		if err != nil {
			logger.Debug().Err(err).
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Msg("ApplyTokenMappers: failed to load user for protocol mappers, role mappers will be skipped")
		}
	}

	var groups []*domain.Group
	if needsGroups && s.groupRepo != nil {
		groups, err = s.groupRepo.GetGroupsByUserID(ctx, userID)
		if err != nil {
			logger.Debug().Err(err).
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Msg("ApplyTokenMappers: failed to load groups for protocol mappers, group mappers will be skipped")
		}
	}

	attrMap := make(map[string]string)
	if needsAttrs && s.userAttrRepo != nil {
		userAttrs, attrErr := s.userAttrRepo.GetAttributesByUserID(ctx, userID)
		if attrErr != nil {
			logger.Debug().Err(attrErr).
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Msg("ApplyTokenMappers: failed to load user attributes for protocol mappers, attribute mappers will be skipped")
		} else {
			for _, attr := range userAttrs {
				attrMap[attr.Name] = attr.Value
			}
		}
	}

	appliedCount := 0
	skippedCount := 0
	for _, mapper := range oidcMappers {
		claimName := configString(mapper.Config, "claim.name")
		if claimName == "" {
			logger.Debug().
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Str("mapper_name", mapper.Name).
				Str("mapper_id", mapper.ID).
				Msg("ApplyTokenMappers: protocol mapper has no claim.name, skipping")
			skippedCount++
			continue
		}

		value, ok := s.protocolMapperValue(mapper, user, groups, attrMap)
		if !ok {
			logger.Debug().
				Str("client_id", clientID).
				Str("user_id", userID).
				Str("token_type", tokenType).
				Str("mapper_name", mapper.Name).
				Str("mapper_id", mapper.ID).
				Str("mapper_type", mapper.ProtocolMapper).
				Str("token_claim", claimName).
				Msg("ApplyTokenMappers: no value available for protocol mapper, skipping")
			skippedCount++
			continue
		}

		if configBool(mapper.Config, "multivalued") {
			if str, isStr := value.(string); isStr {
				value = splitCSV(str)
			}
		} else if names, isSlice := value.([]string); isSlice {
			value = strings.Join(names, ",")
		}

		setNestedClaim(claims, claimName, value)
		appliedCount++
		logger.Info().
			Str("client_id", clientID).
			Str("user_id", userID).
			Str("token_type", tokenType).
			Str("mapper_name", mapper.Name).
			Str("mapper_id", mapper.ID).
			Str("mapper_type", mapper.ProtocolMapper).
			Str("token_claim", claimName).
			Msg("ApplyTokenMappers: applied protocol mapper")
	}

	logger.Debug().
		Str("client_id", clientID).
		Str("user_id", userID).
		Str("token_type", tokenType).
		Int("applied_count", appliedCount).
		Int("skipped_count", skippedCount).
		Msg("ApplyTokenMappers: protocol mappers done")

	return appliedCount, skippedCount, nil
}

// mapperDataNeeds reports which data sources the given protocol mappers require:
// the user record (role mappers), the user's groups (group mappers) and the
// user's attributes (attribute mappers), so each source is fetched at most once.
func mapperDataNeeds(mappers []*domain.ProtocolMapper) (needsUser, needsGroups, needsAttrs bool) {
	for _, m := range mappers {
		switch {
		case isRoleMapper(m):
			needsUser = true
		case isGroupMembershipMapper(m):
			needsGroups = true
		case isAttributeMapper(m):
			needsAttrs = true
		}
	}
	return needsUser, needsGroups, needsAttrs
}

// protocolMapperValue derives the claim value for a protocol mapper. Hardcoded
// claim mappers read Config["claim.value"]; group membership mappers use the
// user's group names; role mappers use the user's realm and client roles;
// user-attribute mappers read the attribute named by Config["user.attribute"].
// ok is false when the mapper type is unknown or its data is unavailable — the
// mapper is then skipped without failing token issuance.
func (s *defaultTokenService) protocolMapperValue(m *domain.ProtocolMapper, user *domain.User, groups []*domain.Group, attrMap map[string]string) (interface{}, bool) {
	switch {
	case isHardcodedClaimMapper(m):
		v := configString(m.Config, "claim.value")
		if v == "" {
			return nil, false
		}
		return v, true
	case isGroupMembershipMapper(m):
		names := make([]string, 0, len(groups))
		for _, g := range groups {
			if g == nil {
				continue
			}
			name := g.Name
			if name == "" {
				name = g.Path
			}
			if name != "" {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			return nil, false
		}
		return names, true
	case isRoleMapper(m):
		if user == nil {
			return nil, false
		}
		roles := make([]string, 0, len(user.Roles)+len(user.ClientRoles))
		roles = append(roles, user.Roles...)
		for _, clientRoleNames := range user.ClientRoles {
			roles = append(roles, clientRoleNames...)
		}
		if len(roles) == 0 {
			return nil, false
		}
		return roles, true
	case isAttributeMapper(m):
		attrName := configString(m.Config, "user.attribute")
		if attrName == "" {
			attrName = configString(m.Config, "user_attribute")
		}
		if attrName == "" {
			return nil, false
		}
		v, ok := attrMap[attrName]
		if !ok || v == "" {
			return nil, false
		}
		return v, true
	}
	return nil, false
}

func isHardcodedClaimMapper(m *domain.ProtocolMapper) bool {
	return strings.Contains(m.ProtocolMapper, "hardcoded")
}

func isGroupMembershipMapper(m *domain.ProtocolMapper) bool {
	return strings.Contains(m.ProtocolMapper, "group-membership") || strings.Contains(m.ProtocolMapper, "group_membership")
}

func isRoleMapper(m *domain.ProtocolMapper) bool {
	return strings.Contains(m.ProtocolMapper, "realm-role") || strings.Contains(m.ProtocolMapper, "realm_role") ||
		strings.Contains(m.ProtocolMapper, "client-role") || strings.Contains(m.ProtocolMapper, "client_role")
}

func isAttributeMapper(m *domain.ProtocolMapper) bool {
	return strings.Contains(m.ProtocolMapper, "attribute")
}

func configString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

func configBool(cfg map[string]any, key string) bool {
	if cfg == nil {
		return false
	}
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		return err == nil && b
	}
	return false
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func (s *defaultTokenService) GenerateTokenPairWithFamily(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration, family string, nonce string, authTime time.Time) (*api.TokenResponse, error) {
	return nil, errors.New("not implemented: GenerateTokenPairWithFamily requires JWKS setup, see skipped tests")
}
