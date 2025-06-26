package federation

import "errors"

var (
	ErrProviderNotFound      = errors.New("provider not found or not enabled")
	ErrInvalidAuthState      = errors.New("invalid auth state parameter")
	ErrExchangeCodeFailed    = errors.New("failed to exchange authorization code for token")
	ErrFetchUserInfoFailed   = errors.New("failed to fetch user info from provider")
	ErrProviderMisconfigured = errors.New("provider is misconfigured")
	ErrAccountAlreadyLinked  = errors.New("this external account is already linked to another user")
	ErrLocalUserLinkConflict = errors.New("this local user is already linked to an account from this provider")
	ErrUserNotFound          = errors.New("user not found")
	ErrInvalidCredentials    = errors.New("invalid credentials")
)
