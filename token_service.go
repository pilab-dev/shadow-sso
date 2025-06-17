package ssso

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
	"github.com/rs/zerolog/log"
)

var errMissingKidSAValidation = errors.New("missing kid header, not a service account token, try other validation")

// TokenInfo is a simplified struct for token introspection results.
type TokenInfo struct {
	ID         string
	TokenType  string
	ClientID   string
	UserID     string
	Scope      string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	IsRevoked  bool
	// Add Issuer string if needed from introspection
}

// TokenRepository defines the interface for storing and retrieving user OAuth tokens.
type TokenRepository interface {
	StoreToken(ctx context.Context, token *Token) error
	GetAccessToken(ctx context.Context, tokenValue string) (*Token, error) // Used by TokenService fallback
	RevokeToken(ctx context.Context, tokenValue string) error             // Used by TokenService.RevokeToken
	GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error) // Used by TokenService
	GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)  // Used by TokenService
	// Potentially GetRefreshToken(ctx, tokenValue) (*Token, error) if refresh grant is fully supported
}

// TokenService handles token generation and validation
type TokenService struct {
	repo   TokenRepository
	cache  cache.TokenStore
	issuer string

	signer *TokenSigner

	// Added for SA token validation
	pubKeyRepo domain.PublicKeyRepository
	saRepo     domain.ServiceAccountRepository
}

// NewTokenService creates a new TokenService instance
func NewTokenService(
	repo TokenRepository,
	tokenCache cache.TokenStore,
	issuer string, // Issuer for user tokens
	signer *TokenSigner,
	pubKeyRepo domain.PublicKeyRepository, // New
	saRepo domain.ServiceAccountRepository, // New
) *TokenService {
	return &TokenService{
		repo:       repo,
		cache:      tokenCache,
		issuer:     issuer,
		signer:     signer,
		pubKeyRepo: pubKeyRepo,
		saRepo:     saRepo,
	}
}

// Token represents an OAuth token, also used for synthetic service account tokens.
// This struct was moved here conceptually from the original plan of modifying oauth.go
type Token struct {
	ID         string    `bson:"_id,omitempty" json:"id"`
	TokenType  string    `bson:"token_type" json:"token_type"`
	TokenValue string    `bson:"token_value" json:"token_value"`
	ClientID   string    `bson:"client_id" json:"client_id"`
	UserID     string    `bson:"user_id" json:"user_id"` // For SA JWT, this will be the 'iss' (client_email)
	Scope      string    `bson:"scope,omitempty" json:"scope,omitempty"`
	ExpiresAt  time.Time `bson:"expires_at" json:"expires_at"`
	CreatedAt  time.Time `bson:"created_at" json:"created_at"`
	LastUsedAt time.Time `bson:"last_used_at" json:"last_used_at"`
	IsRevoked  bool      `bson:"is_revoked,omitempty" json:"is_revoked,omitempty"`
	Issuer     string    `bson:"issuer,omitempty" json:"issuer,omitempty"` // Added
}

// ToEntry converts a Token to a cache.TokenEntry.
func (t *Token) ToEntry() *cache.TokenEntry {
	return &cache.TokenEntry{
		ID:        t.ID,
		UserID:    t.UserID,
		ClientID:  t.ClientID,
		Scope:     t.Scope,
		ExpiresAt: t.ExpiresAt,
		IsRevoked: t.IsRevoked,
		// Issuer is not part of TokenEntry
	}
}

// FromEntry populates a Token from a cache.TokenEntry.
// Fields like TokenValue, CreatedAt, LastUsedAt, Issuer are not typically in a cache entry
// and will need to be populated from the main repository if needed beyond basic validation.
func (t *Token) FromEntry(entry *cache.TokenEntry) {
	t.ID = entry.ID
	t.UserID = entry.UserID
	t.ClientID = entry.ClientID
	t.Scope = entry.Scope
	t.ExpiresAt = entry.ExpiresAt
	t.IsRevoked = entry.IsRevoked
	// TokenValue, CreatedAt, LastUsedAt, Issuer are not in cache.TokenEntry
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

func (s *TokenService) CreateToken(ctx context.Context, opts CreateTokenOptions, claims jwt.Claims) (*Token, error) {
	expiresAt := time.Now().Add(opts.ExpireIn)

	// ? This is a default claim object, it can be used for both access and refresh tokens.
	// ? Later it should be changed to a specific one for access_token, and id_token
	// Access token claims
	tokenClaims := jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   opts.UserID,
		Audience:  jwt.ClaimStrings{opts.ClientID},
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ID:        opts.TokenID,
	}

	// Generate access token with the signer
	signedToken, err := s.signer.Sign(tokenClaims, opts.SigningKeyID)
	if err != nil {
		return nil, err
	}

	// Store token in repository
	token := &Token{
		ID:         opts.TokenID,
		TokenType:  opts.TokenType,
		TokenValue: signedToken,
		ClientID:   opts.ClientID,
		UserID:     opts.UserID,
		Scope:      opts.Scope,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.repo.StoreToken(ctx, token); err != nil {
		return nil, err
	}

	if opts.TokenType == api.TokenTypeAccessToken {
		// Store token in cache
		if err := s.cache.Set(ctx, token.ToEntry()); err != nil {
			// return nil, fmt.Errorf("failed to cache token: %w", err)
			log.Warn().Err(err).Msg("failed to cache token")
		}
	}

	return token, nil
}

func (s *TokenService) BuildToken(token *Token) error {
	// ? This is a default claim object, it can be used for both access and refresh tokens.
	// ? Later it should be changed to a specific one for access_token, and id_token
	// Access token claims
	tokenClaims := jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   token.UserID,
		Audience:  jwt.ClaimStrings{token.ClientID},
		ExpiresAt: jwt.NewNumericDate(token.ExpiresAt),
		IssuedAt:  jwt.NewNumericDate(token.CreatedAt),
		NotBefore: jwt.NewNumericDate(token.CreatedAt),
		ID:        token.ID,
	}

	// Generate access token with the signer
	signedToken, err := s.signer.Sign(tokenClaims, "")
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
	accessToken := &Token{
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
	refreshToken := &Token{
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

	if err := s.repo.StoreToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Cache access token for faster validation
	if err := s.cache.Set(ctx, accessToken.ToEntry()); err != nil {
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
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenValue string) (*Token, error) {
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
				return nil, ErrTokenExpiredOrRevoked
			} // Assumes ErrTokenExpiredOrRevoked is defined
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
			return &Token{ // Assumes Token struct has an Issuer field
				ID:         jtiClaim, // Use JTI as ID if available, otherwise could be hash of tokenValue or empty
				TokenType:  "service_account_jwt",
				TokenValue: tokenValue,
				UserID:     issuerClaim, // For SA JWTs, UserID is the issuer (e.g. service account client_email)
				Scope:      tokenScope,
				ExpiresAt:  expiresAt,
				CreatedAt:  issuedAt,
				IsRevoked:  false,       // SA JWTs are typically not statefully revoked like this in this system
				Issuer:     issuerClaim, // Store the issuer from the JWT
				// ClientID might be derivable from 'aud' claim if needed, or from the SA itself if fetched
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
				var userToken Token // Assuming Token is in the same package ssso
				userToken.FromEntry(entry)
				// Populate missing fields for user token from repo if necessary, or ensure FromEntry is sufficient
				// For user tokens, Issuer might be s.issuer if it's consistent
				userToken.Issuer = s.issuer // Default issuer for user tokens
				return &userToken, nil
			}
			_ = s.cache.Delete(ctx, tokenValue) // Delete expired/revoked from cache
			return nil, ErrTokenExpiredOrRevoked // Assumes ErrTokenExpiredOrRevoked is defined
		}
		// Check repository (for user tokens)
		userToken, repoErr := s.repo.GetAccessToken(ctx, tokenValue) // Assumes s.repo is TokenRepository
		if repoErr != nil {
			// If user token not found, and it wasn't an SA token, then it's truly not found or invalid.
			return nil, fmt.Errorf("token not found or invalid: %w", repoErr)
		}
		if userToken.IsRevoked || time.Now().After(userToken.ExpiresAt) {
			return nil, ErrTokenExpiredOrRevoked
		}
		// Ensure Issuer is set for user tokens from repo
		if userToken.Issuer == "" { // If not already set by repo (e.g. older tokens)
			userToken.Issuer = s.issuer
		}

		// Cache valid user token
		if cacheSetErr := s.cache.Set(ctx, userToken.ToEntry()); cacheSetErr != nil {
			log.Warn().Err(cacheSetErr).Msg("failed to cache user token")
		}
		return userToken, nil
	} // end if errors.Is(err, errMissingKidSAValidation)

	// If error is not errMissingKidSAValidation, it's a genuine SA JWT processing/validation error
	// or other jwt.ValidationError that occurred during ParseWithClaims.
	var validationError *jwt.ValidationError
	if errors.As(err, &validationError) { // Check if it's a standard JWT validation error
		if validationError.Is(jwt.ErrTokenExpired) {
			return nil, ErrTokenExpiredOrRevoked // Map to our existing error
		}
		// Could map other validationError types like ErrTokenNotValidYet, ErrTokenSignatureInvalid
		return nil, fmt.Errorf("SA JWT validation failed: %w", err) // General SA JWT error
	}
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
func (s *TokenService) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error) {
	return s.repo.GetRefreshTokenInfo(ctx, tokenValue)
}

// GetAccessTokenInfo retrieves metadata about an access token. Returns the token info if found,
// or an error if not found or database error.
func (s *TokenService) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error) {
	return s.repo.GetAccessTokenInfo(ctx, tokenValue)
}
