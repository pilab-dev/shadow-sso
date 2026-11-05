package domain

import (
	"context"
	"slices"
)

// Authentication method references (RFC 8176) recorded in the amr claim.
const (
	AMRPassword = "pwd"
	AMROTP      = "otp"
	AMRMFA      = "mfa"
	AMRHardware = "hwk"
)

// Authentication context class references advertised in acr_values_supported.
const (
	ACRLevel1 = "loa1" // single factor
	ACRLevel2 = "loa2" // multi-factor or phishing-resistant authenticator
)

// SupportedACRValues lists the acr values this server can assert.
var SupportedACRValues = []string{ACRLevel1, ACRLevel2}

type authMethodsKey struct{}

// ContextWithAuthMethods carries the amr values of the login that produced an
// authorization code, so the session created for it records them.
func ContextWithAuthMethods(ctx context.Context, amr []string) context.Context {
	if len(amr) == 0 {
		return ctx
	}

	return context.WithValue(ctx, authMethodsKey{}, slices.Clone(amr))
}

// AuthMethodsFromContext returns the amr values, or nil.
func AuthMethodsFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(authMethodsKey{}).([]string)

	return v
}

// ACRForAMR derives the assurance level from the authentication methods.
func ACRForAMR(amr []string) string {
	if slices.Contains(amr, AMRMFA) || slices.Contains(amr, AMRHardware) {
		return ACRLevel2
	}

	return ACRLevel1
}

// AddAMR appends the given methods that are not already present.
func AddAMR(amr []string, methods ...string) []string {
	for _, m := range methods {
		if !slices.Contains(amr, m) {
			amr = append(amr, m)
		}
	}

	return amr
}
