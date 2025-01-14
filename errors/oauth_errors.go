//nolint:tagliatelle
package errors

import (
	"errors"
	"fmt"
)

var ErrMissingRequiredParameter = errors.New("missing required parameter")

// OAuth2Error represents a standardized OAuth 2.0 error.
type OAuth2Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	State       string `json:"state,omitempty"`
}

func (e *OAuth2Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// Standard OAuth2 error codes.
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

// NewInvalidRequest creates a new OAuth2Error with the InvalidRequest.
func NewInvalidRequest(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidRequest,
		Description: description,
		URI:         "",
		State:       "",
	}
}

// NewInvalidClient creates a new OAuth2Error with the InvalidClient.
func NewInvalidClient(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidClient,
		Description: description,
		URI:         "",
		State:       "",
	}
}

// NewInvalidGrant creates a new OAuth2Error with the InvalidGrant.
func NewInvalidGrant(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidGrant,
		Description: description,
		URI:         "",
		State:       "",
	}
}

// NewServerError creates a new OAuth2Error with the ServerError
// code and the provided description.
func NewServerError(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        ServerError,
		Description: description,
		URI:         "",
		State:       "",
	}
}

// PKCE specific errors.
func NewPKCERequired() *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidRequest,
		Description: "PKCE is required for this client",
		URI:         "",
		State:       "",
	}
}

func NewInvalidPKCE(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        InvalidRequest,
		Description: "PKCE validation failed: " + description,
		URI:         "",
		State:       "",
	}
}

func NewInvalidScope(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        "invalid_scope",
		Description: description,
		URI:         "",
		State:       "",
	}
}

func NewUnauthorizedClient(description string) *OAuth2Error {
	return &OAuth2Error{
		Code:        UnauthorizedClient,
		Description: description,
		URI:         "",
		State:       "",
	}
}

func NewUnsupportedGrantType() *OAuth2Error {
	return &OAuth2Error{
		Code:        UnsupportedGrantType,
		Description: "The authorization grant type is not supported",
		URI:         "",
		State:       "",
	}
}
