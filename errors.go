package ssso

import (
	"errors"
	serrors "github.com/pilab-dev/shadow-sso/errors"
)

var (
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrClientNotFound           = errors.New("client not found")
	ErrInvalidRefreshToken      = errors.New("invalid refresh token")
	ErrTokenExpiredOrRevoked    = errors.New("token expired or revoked")

	// Device Flow Errors (re-exported from errors package)
	ErrDeviceCodeNotFound      = serrors.ErrDeviceCodeNotFound
	ErrUserCodeNotFound        = serrors.ErrUserCodeNotFound
	ErrCannotApproveDeviceAuth = serrors.ErrCannotApproveDeviceAuth
	ErrAuthorizationPending    = serrors.ErrAuthorizationPending
	ErrSlowDown                = serrors.ErrSlowDown
	ErrDeviceFlowAccessDenied  = serrors.ErrDeviceFlowAccessDenied
	ErrDeviceFlowTokenExpired  = serrors.ErrDeviceFlowTokenExpired
)
