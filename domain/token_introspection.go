package domain

import "encoding/json"

// TokenIntrospection represents the response format defined in RFC 7662
//
//nolint:tagliatelle
type TokenIntrospection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
	// AuthorizationDetails is the RFC 9396 authorization_details array.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
}
