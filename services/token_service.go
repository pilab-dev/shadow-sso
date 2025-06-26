package services

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	serrors "github.com/pilab-dev/shadow-sso/errors" // Added for serrors
	"github.com/pilab-dev/shadow-sso/internal/metrics"
	"github.com/rs/zerolog/log"
)

var errMissingKidSAValidation = errors.New("missing kid header, not a service account token, try other validation")

// TokenService handles token generation and validation
type TokenService struct {
	repo   domain.TokenRepository // Changed to domain.TokenRepository
	cache  cache.TokenStore
	issuer string

	signer *TokenSigner

	// Added for SA token validation
	pubKeyRepo domain.PublicKeyRepository
	saRepo     domain.ServiceAccountRepository
	userRepo   domain.UserRepository // New dependency
}

// NewTokenService creates a new TokenService instance
func NewTokenService(
	repo domain.TokenRepository, // Changed to domain.TokenRepository
	tokenCache cache.TokenStore,
	issuer string, // Issuer for user tokens
	signer *TokenSigner,
	pubKeyRepo domain.PublicKeyRepository,
	saRepo domain.ServiceAccountRepository,
	userRepo domain.UserRepository, // New
) *TokenService {
	return &TokenService{
		repo:       repo,
		cache:      tokenCache,
		issuer:     issuer,
		signer:     signer,
		pubKeyRepo: pubKeyRepo,
		saRepo:     saRepo,
		userRepo:   userRepo, // New
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
	// s.signer.Sign now accepts jwt.Claims (which jwt.MapClaims implements)
	signedToken, err := s.signer.Sign(tokenClaimsMap, opts.SigningKeyID)
	if err != nil {
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
	// Generate access token
	accessToken := &domain.Token{ // Changed to domain.Token
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: "",
		ClientID:   clientID,
		UserID:     userID,
		Scope:      scope,
		ExpiresAt:  time.Now().Add(tokenTTL),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	if err := s.BuildToken(accessToken); err != nil {
		return nil, fmt.Errorf("failed to build access token: %w", err)
	}

	// Generate refresh token
	refreshToken := &domain.Token{ // Changed to domain.Token
		ID:         uuid.NewString(),
		TokenType:  "refresh_token",
		TokenValue: uuid.NewString(),
		ClientID:   clientID,
		UserID:     userID,
		Scope:      scope,
		ExpiresAt:  time.Now().Add(tokenTTL * 24), // Refresh tokens live longer
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	if err := s.BuildToken(refreshToken); err != nil {
		return nil, fmt.Errorf("failed to build refresh token: %w", err)
	}

	// Store tokens
	if err := s.repo.StoreToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}
	metrics.TokensCreatedTotal.Inc() // Access token

	if err := s.repo.StoreToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}
	metrics.TokensCreatedTotal.Inc() // Refresh token

	// Cache access token for faster validation
	if err := s.cache.Set(ctx, toCacheEntry(accessToken)); err != nil { // Use toCacheEntry
		log.Warn().Err(err).Msg("failed to cache access token")
	}

	return &api.TokenResponse{
		IDToken:      "",
		AccessToken:  accessToken.TokenValue,
		TokenType:    "Bearer",
		ExpiresIn:    int(tokenTTL.Seconds()),
		RefreshToken: refreshToken.TokenValue,
	}, nil
}

// ValidateToken validates an access token and returns its information. If the token is revoked or expired,
// it returns ErrTokenExpiredOrRevoked.
// This version handles both Service Account JWTs and regular user tokens.
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenValue string) (*domain.Token, error) { // Changed return type
	// This line needs to be at the package level of token_service.go, or passed in.
	// var errMissingKidSAValidation = errors.New("missing kid header, not a service account token, try other validation")

	parsedSAJWT, err := jwt.ParseWithClaims(tokenValue, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errMissingKidSAValidation // Use the package-level var
		}
		publicKeyInfo, errDb := s.pubKeyRepo.GetPublicKey(ctx, kid)
		if errDb != nil {
			log.Warn().Err(errDb).Str("kid", kid).Msg("Failed to get public key for SA JWT")
			return nil, fmt.Errorf("SA key retrieval failed for kid %s: %w", kid, errDb)
		}
		if publicKeyInfo.Status != "ACTIVE" { // Assuming "ACTIVE" is status string
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

	if err == nil { // Implies parsedSAJWT is not nil
		if parsedSAJWT.Valid {
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
				return nil, serrors.ErrTokenExpiredOrRevoked // Use serrors
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
			jtiClaim, _ := (*claims)["jti"].(string) // JTI is optional for some SA JWTs, use if present for ID
			return &domain.Token{                    // Changed to domain.Token
				ID:         jtiClaim,
				TokenType:  "service_account_jwt",
				TokenValue: tokenValue,
				UserID:     issuerClaim,
				Scope:      tokenScope,
				ExpiresAt:  expiresAt,
				CreatedAt:  issuedAt,
				IsRevoked:  false,
				Issuer:     issuerClaim,
				Roles:      []string{}, // Service Accounts do not have user roles in this model
			}, nil
		} else {
			// This case should ideally not be reached if jwt-go behaves as expected:
			// if err is nil, token should be valid.
			return nil, fmt.Errorf("SA JWT parsed (err is nil) but token.Valid is false, unexpected state")
		}
	} // end if err == nil

	// At this point, err != nil. Check if it's the signal to fallback.
	if errors.Is(err, errMissingKidSAValidation) {
		log.Debug().Msg("Attempting user token validation (SA token 'kid' missing or error explicitly requesting fallback).")
		// Fallback to user token validation (original logic from existing ValidateAccessToken)
		// Ensure s.repo, s.cache, ErrTokenExpiredOrRevoked are accessible and correctly used
		if entry, cacheErr := s.cache.Get(ctx, tokenValue); cacheErr == nil {
			if !entry.IsRevoked && time.Now().Before(entry.ExpiresAt) {
				userToken := fromCacheEntry(entry, tokenValue) // Use fromCacheEntry
				// Populate missing fields for user token from repo if necessary, or ensure FromEntry is sufficient
				// For user tokens, Issuer might be s.issuer if it's consistent
				userToken.Issuer = s.issuer // Default issuer for user tokens
				return userToken, nil
			}
			_ = s.cache.Delete(ctx, tokenValue)          // Delete expired/revoked from cache
			return nil, serrors.ErrTokenExpiredOrRevoked // Use serrors
		}
		// Check repository (for user tokens)
		userTokenDB, repoErr := s.repo.GetAccessToken(ctx, tokenValue) // Assumes s.repo is TokenRepository, returns *domain.Token
		if repoErr != nil {
			// If user token not found, and it wasn't an SA token, then it's truly not found or invalid.
			return nil, fmt.Errorf("token not found or invalid: %w", repoErr)
		}
		if userTokenDB.IsRevoked || time.Now().After(userTokenDB.ExpiresAt) {
			return nil, serrors.ErrTokenExpiredOrRevoked // Use serrors
		}
		// Ensure Issuer is set for user tokens from repo
		if userTokenDB.Issuer == "" { // If not already set by repo (e.g. older tokens)
			userTokenDB.Issuer = s.issuer
		}

		// Cache valid user token
		if cacheSetErr := s.cache.Set(ctx, toCacheEntry(userTokenDB)); cacheSetErr != nil { // Use toCacheEntry
			log.Warn().Err(cacheSetErr).Msg("failed to cache user token")
		}
		return userTokenDB, nil
	} // end if errors.Is(err, errMissingKidSAValidation)

	// If error is not errMissingKidSAValidation, it's a genuine SA JWT processing/validation error
	// or other jwt.ValidationError that occurred during ParseWithClaims.

	// FIXME: fix this error check case
	// var validationError *jwt.ValidationError
	// if errors.As(err, &validationError) { // Check if it's a standard JWT validation error
	// 	if validationError.Is(jwt.ErrTokenExpired) {
	// 		return nil, ErrTokenExpiredOrRevoked // Map to our existing error
	// 	}
	// 	// Could map other validationError types like ErrTokenNotValidYet, ErrTokenSignatureInvalid
	// 	return nil, fmt.Errorf("SA JWT validation failed: %w", err) // General SA JWT error
	// }
	// Other errors (e.g. from Keyfunc like DB error, PEM error, non-JWT error from ParseWithClaims)
	return nil, fmt.Errorf("SA JWT processing error: %w", err)
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
