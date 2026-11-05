package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

type authorizationDetailsKey struct{}

// ContextWithAuthorizationDetails carries the RFC 9396 authorization_details
// JSON array through the code/token issuance call chain without widening every
// signature. An empty value returns ctx unchanged.
func ContextWithAuthorizationDetails(ctx context.Context, details string) context.Context {
	if details == "" {
		return ctx
	}

	return context.WithValue(ctx, authorizationDetailsKey{}, details)
}

// AuthorizationDetailsFromContext returns the authorization_details JSON array, or "".
func AuthorizationDetailsFromContext(ctx context.Context) string {
	v, _ := ctx.Value(authorizationDetailsKey{}).(string)

	return v
}

// ParseAuthorizationDetails validates an RFC 9396 authorization_details JSON
// array: every element must be an object with a non-empty string "type".
// It returns the decoded elements and their types.
func ParseAuthorizationDetails(raw string) ([]map[string]any, []string, error) {
	var details []map[string]any
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		return nil, nil, fmt.Errorf("authorization_details must be a JSON array of objects: %w", err)
	}

	if len(details) == 0 {
		return nil, nil, errors.New("authorization_details must not be empty")
	}

	types := make([]string, 0, len(details))
	for _, d := range details {
		t, _ := d["type"].(string)
		if t == "" {
			return nil, nil, errors.New("each authorization_details entry requires a type")
		}

		types = append(types, t)
	}

	return details, types, nil
}
