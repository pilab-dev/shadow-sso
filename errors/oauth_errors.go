package errors

import "fmt"

// OAuth2Error represents a standardized OAuth 2.0 error
type OAuth2Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	State       string `json:"state,omitempty"`
}

func (e *OAuth2Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// Standard OAuth2 error codes
const (
	InvalidRequest         = "invalid_request"
	UnauthorizedClient     = "unauthorized_client"
	AccessDenied           = "access_denied"
	UnsupportedGrantType   = "unsupported_grant_type"
	InvalidScope           = "invalid_scope"
	InvalidClient          = "invalid_client"
	InvalidGrant           = "invalid_grant"
	ServerError            = "server_error"
	TemporarilyUnavailable = "temporarily_unavailable"
)

// Common error constructors
func NewInvalidRequest(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidRequest,
		Description: description,
	}
}

func NewInvalidClient(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidClient,
		Description: description,
	}
}

func NewInvalidGrant(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidGrant,
		Description: description,
	}
}

func NewServerError(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        ServerError,
		Description: description,
	}
}

// PKCE specific errors
func NewPKCERequired() *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidRequest,
		Description: "PKCE is required for this client",
	}
}

func NewInvalidPKCE(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidRequest,
		Description: fmt.Sprintf("PKCE validation failed: %s", description),
	}
}

func NewInvalidScope(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        "invalid_scope",
		Description: description,
	}
}

func NewUnauthorizedClient(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        UnauthorizedClient,
		Description: description,
	}
}

func NewUnsupportedGrantType() *OAuth2Error {
	return &OAuth2Error{
		Code:        UnsupportedGrantType,
		Description: "The authorization grant type is not supported",
	}
}
