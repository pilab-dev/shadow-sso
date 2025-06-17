package middleware

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	// "github.com/pilab-dev/shadow-sso/domain" // Not used directly here yet
	"github.com/pilab-dev/shadow-sso/ssso" // For TokenService and Token model
)

// internalTokenClaimKey is the key used to store the *ssso.Token object within authn.Claims.
const internalTokenClaimKey = "_internal_auth_token"

// Authenticator validates JWT tokens using TokenService.
type Authenticator struct {
	tokenService *ssso.TokenService
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(ts *ssso.TokenService) *Authenticator {
	return &Authenticator{
		tokenService: ts,
	}
}

// Authenticate implements authn.Authenticator.
// It validates the JWT from the Authorization header and, if successful,
// returns claims containing the original *ssso.Token object and standard claims like 'sub'.
func (a *Authenticator) Authenticate(ctx context.Context, req authn.Request) (authn.Claims, error) {
	authHeader := req.Header().Get("Authorization")
	if authHeader == "" {
		return nil, authn.ErrNoCredentials // No Authorization header results in authn.ErrNoCredentials
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		// Invalid format leads to Unauthenticated error
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid authorization header format: expected Bearer token"))
	}
	tokenValue := parts[1]

	// Validate the token using TokenService
	validatedToken, err := a.tokenService.ValidateAccessToken(ctx, tokenValue)
	if err != nil {
		// Ensure ssso.ErrTokenExpiredOrRevoked is a well-defined error in the ssso package
		if errors.Is(err, ssso.ErrTokenExpiredOrRevoked) {
			return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("token expired or revoked"))
		}
		// For other validation errors (e.g., malformed, signature invalid)
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token: %w", err))
	}

	if validatedToken == nil { // Should ideally not happen if err is nil
	    return nil, connect.NewError(connect.CodeInternal, errors.New("token validation successful but token object is nil"))
	}

	// Store the entire token object within the claims map, plus standard claims.
	claimsData := authn.Claims{
		internalTokenClaimKey: validatedToken,
		"sub":                 validatedToken.UserID, // Standard subject claim
		// "iss": validatedToken.Issuer, // If Issuer is part of ssso.Token
	}
    if validatedToken.Scope != "" {
        claimsData["scope"] = validatedToken.Scope
    }
    if validatedToken.Issuer != "" { // Assuming Issuer field exists in ssso.Token
        claimsData["iss"] = validatedToken.Issuer
    }


	return claimsData, nil
}

// NewAuthInterceptor creates a Connect interceptor for JWT Bearer authentication.
func NewAuthInterceptor(ts *ssso.TokenService) connect.Interceptor {
	customAuthenticator := NewAuthenticator(ts)
	opts := []authn.InterceptorOption{
		authn.WithAuthenticator(customAuthenticator),
	}
	return authn.NewInterceptor(opts...)
}

// GetAuthenticatedTokenFromContext retrieves the validated *ssso.Token from the authn.Claims in the context.
// Service methods should use this helper to get the full, typed token object.
func GetAuthenticatedTokenFromContext(ctx context.Context) (*ssso.Token, bool) {
	claims := authn.ClaimsFromContext(ctx)
	if claims == nil {
		return nil, false // No claims found in context
	}

	tokenVal, ok := claims.Get(internalTokenClaimKey)
	if !ok {
		return nil, false // Our specific token claim is not present
	}

	token, typeAssertionOk := tokenVal.(*ssso.Token)
	if !typeAssertionOk {
		// This would indicate a programming error, wrong type stored/retrieved.
		// Log this situation if possible.
		return nil, false
	}
	return token, true
}

// Ensure Authenticator implements the interface
var _ authn.Authenticator = (*Authenticator)(nil)
