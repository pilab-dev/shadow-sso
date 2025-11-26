package domain

import (
	"context"
	"errors"
)

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

// GetAuthenticatedUserIDFromContext retrieves the authenticated user ID from context.
// Returns an error if no authenticated token is found in the context.
func GetAuthenticatedUserIDFromContext(ctx context.Context) (string, error) {
	tokenInfo, ok := GetAuthenticatedTokenFromContext(ctx)
	if !ok {
		return "", errors.New("no authenticated token found in context")
	}
	if tokenInfo.UserID == "" {
		return "", errors.New("token does not contain a valid user ID")
	}
	return tokenInfo.UserID, nil
}
