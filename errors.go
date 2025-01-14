package ssso

import "errors"

var (
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrClientNotFound           = errors.New("client not found")
	ErrInvalidRefreshToken      = errors.New("invalid refresh token")
	ErrTokenExpiredOrRevoked    = errors.New("token expired or revoked")
)
