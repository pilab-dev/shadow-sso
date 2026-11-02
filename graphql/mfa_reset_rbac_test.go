package graphql_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestResetUserTwoFactor_RequiresAdmin guards against an authenticated user
// clearing another account's second factor.
func TestResetUserTwoFactor_RequiresAdmin(t *testing.T) {
	resolver := newTestResolver(t)

	_, err := resolver.Mutation().ResetUserTwoFactor(userCtx(), "target-user")

	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connectErrCode(err))
}

func TestDeleteUserCredentials_RequiresAdmin(t *testing.T) {
	resolver := newTestResolver(t)

	_, err := resolver.Mutation().DeleteUserCredentials(userCtx(), "target-user", "method-1")

	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connectErrCode(err))
}

func TestResetUserTwoFactor_AdminClearsStoredSecrets(t *testing.T) {
	resolver := newTestResolver(t)
	userRepo := resolver.UserRepo.(*mock_domain.MockUserRepository)

	user := &domain.User{
		ID:                     "target-user",
		IsTwoFactorEnabled:     true,
		TwoFactorMethod:        "TOTP",
		TwoFactorSecret:        "SECRET",
		TwoFactorRecoveryCodes: []string{"hash"},
		EmailMFAEnabled:        true,
		PushMFAEnabled:         true,
		MfaMethods:             []domain.MfaMethod{{ID: "m1", Verified: true}},
	}
	userRepo.EXPECT().GetUserByID(gomock.Any(), "target-user").Return(user, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.False(t, u.IsTwoFactorEnabled)
		assert.Equal(t, "NONE", u.TwoFactorMethod)
		assert.Empty(t, u.TwoFactorSecret)
		assert.Empty(t, u.TwoFactorRecoveryCodes)
		assert.False(t, u.EmailMFAEnabled)
		assert.False(t, u.PushMFAEnabled)
		assert.Empty(t, u.MfaMethods)
		return nil
	})

	ok, err := resolver.Mutation().ResetUserTwoFactor(adminCtx(), "target-user")
	require.NoError(t, err)
	assert.True(t, ok)
}
