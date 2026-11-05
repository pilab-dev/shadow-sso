package domain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RequestObjectAlgs are the signature algorithms accepted for JAR request
// objects (RFC 9101). "none" is never accepted.
var RequestObjectAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

// requestObjectParams are the authorization request parameters a request
// object may carry.
var requestObjectParams = []string{
	"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "prompt",
	"code_challenge", "code_challenge_method", "authorization_details", "response_mode",
}

// VerifyRequestObject verifies a signed JWT authorization request (RFC 9101)
// against the client's registered JWKS and returns its authorization request
// parameters. The object must be addressed to issuer and, when it names a
// client_id, that must equal clientID.
func VerifyRequestObject(client *Client, raw, issuer string) (map[string]string, error) {
	if client == nil || client.JWKS == nil || len(client.JWKS.Keys) == 0 {
		return nil, fmt.Errorf("client has no JWKS configured for request objects")
	}

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, &claims, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		var candidate *JSONWebKey
		for i := range client.JWKS.Keys {
			key := &client.JWKS.Keys[i]
			if (key.Use != "" && key.Use != "sig") || (kid != "" && key.Kid != kid) {
				continue
			}
			if candidate != nil {
				return nil, ErrInvalidClientAssertion
			}
			candidate = key
		}
		if candidate == nil {
			return nil, ErrInvalidClientAssertion
		}

		return candidate.ToRSAPublicKey()
	}, jwt.WithValidMethods(RequestObjectAlgs), jwt.WithLeeway(30*time.Second),
		jwt.WithIssuer(client.ID), jwt.WithAudience(issuer))
	if err != nil {
		return nil, fmt.Errorf("invalid request object: %w", err)
	}

	if cid, ok := claims["client_id"].(string); ok && cid != client.ID {
		return nil, fmt.Errorf("request object client_id mismatch")
	}

	params := map[string]string{}
	for _, name := range requestObjectParams {
		switch v := claims[name].(type) {
		case nil:
		case string:
			params[name] = v
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("invalid request object claim %q", name)
			}
			params[name] = string(b)
		}
	}
	params["client_id"] = client.ID

	return params, nil
}
