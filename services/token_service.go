package services

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/metrics"
	"github.com/rs/zerolog/log"
)

var _ = jwt.SigningMethodRS256 // ensure jwt import is used

// TokenService handles token generation and validation
type TokenService struct {
	repo   domain.TokenRepository
	cache  cache.TokenStore
	issuer string

	signer *TokenSigner
	jwks   *JWKSService

	pubKeyRepo domain.PublicKeyRepository
	saRepo     domain.ServiceAccountRepository
	userRepo   domain.UserRepository
}

// NewTokenService creates a new TokenService instance
func NewTokenService(
	repo domain.TokenRepository,
	tokenCache cache.TokenStore,
	issuer string,
	signer *TokenSigner,
	jwks *JWKSService,
	pubKeyRepo domain.PublicKeyRepository,
	saRepo domain.ServiceAccountRepository,
	userRepo domain.UserRepository,
) *TokenService {
	return &TokenService{
		repo:       repo,
		cache:      tokenCache,
		issuer:     issuer,
		signer:     signer,
		jwks:       jwks,
		pubKeyRepo: pubKeyRepo,
		saRepo:     saRepo,
		userRepo:   userRepo,
	}
}

// ToEntry converts a domain.Token to a cache.TokenEntry.
func toCacheEntry(t *domain.Token) *cache.TokenEntry { // Ensure cache pkg is imported
	return &cache.TokenEntry{
		ID: t.ID, UserID: t.UserID, ClientID: t.ClientID,
		Scope: t.Scope, ExpiresAt: t.ExpiresAt, IsRevoked: t.IsRevoked,
		Roles: t.Roles, // Add Roles
		// Issuer and other fields not in TokenEntry are omitted
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
		TokenValue: tokenValue, // Pass tokenValue if needed for context
		// TokenType, CreatedAt, LastUsedAt, Issuer would need to be set if required by caller
	}
}

type CreateTokenOptions struct {
	TokenID            string
	Scope              string
	ClientID           string
	UserID             string
	TokenType          string
	ExpireIn           time.Duration
	SigningKeyID       string
	RefreshTokenFamily string
}

// CreateToken creates a new token with the given options and claims.
func (s *TokenService) CreateToken(ctx context.Context, opts CreateTokenOptions, claims jwt.Claims) (*domain.Token, error) { // Changed return type
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
	if opts.UserID != "" {
		user, errUser := s.userRepo.GetUserByID(ctx, opts.UserID)
		if errUser != nil {
			log.Warn().Err(errUser).Str("userID", opts.UserID).Msg("CreateToken: failed to get user for roles, proceeding without roles claim.")
		} else if user != nil {
			userRoles = user.Roles
			if len(userRoles) > 0 {
				tokenClaimsMap["roles"] = userRoles
			}
		}
	}

	// Generate access token with the signer
	signingKeyID := opts.SigningKeyID
	if signingKeyID == "" && s.jwks != nil {
		signingKeyID, _ = s.jwks.GetSigningKey()
	}
	signedToken, err := s.signer.Sign(tokenClaimsMap, signingKeyID)
	if err != nil {
		return nil, err
	}

	// Store token in repository
	token := &domain.Token{
		ID:                 opts.TokenID,
		TokenType:          opts.TokenType,
		TokenValue:         signedToken,
		ClientID:           opts.ClientID,
		UserID:             opts.UserID,
		Scope:              opts.Scope,
		ExpiresAt:          expiresAt,
		CreatedAt:          time.Now(),
		LastUsedAt:         time.Now(),
		Roles:              userRoles,
		RefreshTokenFamily: opts.RefreshTokenFamily,
	}
	if err := s.repo.StoreToken(ctx, token); err != nil {
		return nil, err
	}

	if opts.TokenType == api.TokenTypeAccessToken {
		// Store token in cache
		if err := s.cache.Set(ctx, toCacheEntry(token)); err != nil { // Use toCacheEntry
			// return nil, fmt.Errorf("failed to cache token: %w", err)
			log.Warn().Err(err).Msg("failed to cache token")
		}
	}
	metrics.TokensCreatedTotal.Inc()
	return token, nil
}

// BuildToken builds the token value for an existing token struct.
func (s *TokenService) BuildToken(token *domain.Token) error { // Changed to domain.Token
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

	// Generate access token with the signer
	// Assuming s.signer.Sign takes jwt.Claims (jwt.MapClaims implements this)
	signedToken, err := s.signer.Sign(tokenMapClaims, "") // Pass empty keyID for default signer key
	if err != nil {
		return fmt.Errorf("cannot sign token: %w", err)
	}

	token.TokenValue = signedToken

	return nil
}

// func (s *TokenService) generateUserTokens(ctx context.Context, userID, clientID, scope string) (*TokenResponse, error) {
// 	tokenID := uuid.NewString()

// 	// Generate access token
// 	signedToken, err := s.CreateToken(CreateTokenOptions{
// 		TokenID:      tokenID,
// 		ClientID:     clientID,
// 		UserID:       userID,
// 		Scope:        scope,
// 		ExpireIn:     time.Hour,
// 		TokenType:    "access_token",
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

// GenerateTokenPair creates a new access and refresh token pair
func (s *TokenService) GenerateTokenPair(ctx context.Context,
	clientID, userID, scope string, tokenTTL time.Duration,
) (*api.TokenResponse, error) {
	return s.GenerateTokenPairWithFamily(ctx, clientID, userID, scope, tokenTTL, "", "", time.Time{})
}

// GenerateTokenPairWithFamily creates a new access and refresh token pair with an optional refresh token family.
func (s *TokenService) GenerateTokenPairWithFamily(ctx context.Context,
	clientID, userID, scope string, tokenTTL time.Duration, family string, nonce string, authTime time.Time,
) (*api.TokenResponse, error) {
	// Generate access token
	accessTokenID := uuid.NewString()
	accessToken, err := s.CreateToken(ctx, CreateTokenOptions{
		TokenID:      accessTokenID,
		Scope:        scope,
		ClientID:     clientID,
		UserID:       userID,
		TokenType:    api.TokenTypeAccessToken,
		ExpireIn:     tokenTTL,
		SigningKeyID: "",
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	// Generate refresh token
	refreshTokenID := uuid.NewString()
	refreshTokenTTL := tokenTTL * 24
	if family == "" {
		family = uuid.NewString()
	}
	refreshToken, err := s.CreateToken(ctx, CreateTokenOptions{
		TokenID:            refreshTokenID,
		Scope:              scope,
		ClientID:           clientID,
		UserID:             userID,
		TokenType:          api.TokenTypeRefreshToken,
		ExpireIn:           refreshTokenTTL,
		SigningKeyID:       "",
		RefreshTokenFamily: family,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	// Generate ID token if openid scope is requested
	idToken := ""
	if s.containsScope(scope, "openid") {
		user, userErr := s.userRepo.GetUserByID(ctx, userID)
		if userErr != nil {
			log.Warn().Err(userErr).Str("userID", userID).Msg("GenerateTokenPairWithFamily: failed to fetch user for ID token claims")
		}
		idToken, err = s.GenerateIDToken(ctx, userID, clientID, nonce, authTime, user)
		if err != nil {
			return nil, fmt.Errorf("failed to create ID token: %w", err)
		}
	}

	return &api.TokenResponse{
		IDToken:      idToken,
		AccessToken:  accessToken.TokenValue,
		TokenType:    "Bearer",
		ExpiresIn:    int(tokenTTL.Seconds()),
		RefreshToken: refreshToken.TokenValue,
	}, nil
}

func (s *TokenService) containsScope(scope, target string) bool {
	return strings.Contains(" "+scope+" ", " "+target+" ")
}

// GenerateIDToken creates a signed JWT ID token per OIDC Core spec.
func (s *TokenService) GenerateIDToken(ctx context.Context, userID, clientID, nonce string, authTime time.Time, user *domain.User) (string, error) {
	keyID, _ := s.jwks.GetSigningKey()
	if keyID == "" {
		return "", fmt.Errorf("no signing key available for ID token")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       userID,
		"aud":       clientID,
		"exp":       jwt.NewNumericDate(now.Add(time.Hour)).Unix(),
		"iat":       jwt.NewNumericDate(now).Unix(),
		"auth_time": authTime.Unix(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	if user != nil {
		claims["name"] = user.FirstName + " " + user.LastName
		if user.Email != "" {
			claims["email"] = user.Email
		}
		if len(user.Roles) > 0 {
			claims["roles"] = user.Roles
		}
	}

	signingKeyID, _ := s.jwks.GetSigningKey()
	signedToken, err := s.signer.Sign(claims, signingKeyID)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return signedToken, nil
}

// ValidateAccessToken validates an access token and returns its information.
// It inspects the JWT header to determine token type before routing to the appropriate validator.
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		return s.validateUserToken(ctx, tokenValue)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return s.validateUserToken(ctx, tokenValue)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return s.validateUserToken(ctx, tokenValue)
	}

	kid, hasKid := header["kid"].(string)
	alg, _ := header["alg"].(string)

	isSARSA := hasKid && kid != "" && (alg == "RS256" || alg == "RS384" || alg == "RS512")

	if isSARSA {
		if _, err := s.pubKeyRepo.GetPublicKey(ctx, kid); err == nil {
			return s.validateSAJWT(ctx, tokenValue, kid)
		}
		log.Debug().Str("kid", kid).Msg("kid not found in pubKeyRepo, falling back to validateUserToken")
	}

	return s.validateUserToken(ctx, tokenValue)
}

func (s *TokenService) validateSAJWT(ctx context.Context, tokenValue, kid string) (*domain.Token, error) {
	parsedSAJWT, err := jwt.ParseWithClaims(tokenValue, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		publicKeyInfo, errDb := s.pubKeyRepo.GetPublicKey(ctx, kid)
		if errDb != nil {
			log.Warn().Err(errDb).Str("kid", kid).Msg("Failed to get public key for SA JWT")
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

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, domain.ErrTokenExpiredOrRevoked
		}
		return nil, fmt.Errorf("SA JWT validation failed: %w", err)
	}

	if !parsedSAJWT.Valid {
		return nil, errors.New("SA JWT parsed but is not valid")
	}

	claims, ok := parsedSAJWT.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type in SA JWT")
	}
	issuerClaim, _ := (*claims)["iss"].(string)
	if issuerClaim == "" {
		return nil, errors.New("SA JWT missing 'iss' claim")
	}
	var expiresAt time.Time
	if exp, okClaim := (*claims)["exp"].(float64); okClaim {
		expiresAt = time.Unix(int64(exp), 0)
	} else {
		return nil, errors.New("SA JWT missing 'exp' claim")
	}
	if time.Now().After(expiresAt) {
		return nil, domain.ErrTokenExpiredOrRevoked
	}
	var issuedAt time.Time
	if iat, okClaim := (*claims)["iat"].(float64); okClaim {
		issuedAt = time.Unix(int64(iat), 0)
	} else {
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
}

func (s *TokenService) validateUserToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	if entry, cacheErr := s.cache.Get(ctx, tokenValue); cacheErr == nil {
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
		log.Warn().Err(cacheSetErr).Msg("failed to cache user token")
	}
	return userTokenDB, nil
}

// RevokeToken revokes an access token. This will invalidate the token and remove it from cache
// This is a no-op if the token is already revoked. This is useful for logging out, for example.
func (s *TokenService) RevokeToken(ctx context.Context, token string) error {
	if err := s.cache.Delete(ctx, token); err != nil {
		log.Warn().Err(err).Msg("failed to delete token from cache")
	}

	return s.repo.RevokeToken(ctx, token)
}

// GetRefreshTokenInfo retrieves metadata about a refresh token. Returns the token info if found,
// or an error if not found or database error.
func (s *TokenService) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) { // Changed to domain.TokenInfo
	return s.repo.GetRefreshTokenInfo(ctx, tokenValue)
}

// GetAccessTokenInfo retrieves metadata about an access token. Returns the token info if found,
// or an error if not found or database error.
func (s *TokenService) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) { // Changed to domain.TokenInfo
	return s.repo.GetAccessTokenInfo(ctx, tokenValue)
}
