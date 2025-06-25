package domain

import "context"

// TokenContextKey is the key used to store TokenInfo in context.
const TokenContextKey = "auth_token"

// GetAuthenticatedTokenFromContext retrieves TokenInfo from context.
func GetAuthenticatedTokenFromContext(ctx context.Context) (*TokenInfo, bool) {
	val := ctx.Value(TokenContextKey)
	if tokenInfo, ok := val.(*TokenInfo); ok {
		return tokenInfo, true
	}
	return nil, false
}
