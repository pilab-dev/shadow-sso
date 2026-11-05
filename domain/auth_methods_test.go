package domain_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pilab-dev/shadow-sso/domain"
)

func TestAuthMethods(t *testing.T) {
	assert.Equal(t, domain.ACRLevel1, domain.ACRForAMR([]string{domain.AMRPassword}))
	assert.Equal(t, domain.ACRLevel2, domain.ACRForAMR([]string{"pwd", "otp", "mfa"}))
	assert.Equal(t, domain.ACRLevel2, domain.ACRForAMR([]string{domain.AMRHardware}))

	amr := domain.AddAMR([]string{"pwd"}, "otp", "pwd", "mfa")
	assert.Equal(t, []string{"pwd", "otp", "mfa"}, amr)

	ctx := domain.ContextWithAuthMethods(context.Background(), amr)
	assert.Equal(t, amr, domain.AuthMethodsFromContext(ctx))
	assert.Nil(t, domain.AuthMethodsFromContext(context.Background()))
}
