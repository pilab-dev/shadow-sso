package services

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestGetMFAStatus_ReportsUnusableEmailFactor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	server := NewTwoFactorServer(userRepo, nil, nil, nil, "ShadowSSO")

	user := &domain.User{
		ID:              "user-1",
		Email:           "user@example.com",
		EmailMFAEnabled: true,
		// The 2FA aggregate flag is what the login runner sees.
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "EMAIL",
	}
	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-1").Return(user, nil)

	ctx := createAuthenticatedContextWithRoles(context.Background(), "admin-1", rbac.RoleAdmin)
	resp, err := server.GetMFAStatus(ctx, connect.NewRequest(&ssov1.GetMFAStatusRequest{UserId: "user-1"}))
	require.NoError(t, err)

	status := resp.Msg.GetStatus()
	require.NotNil(t, status)
	assert.Equal(t, "EMAIL", status.GetEffectiveTrigger())
	assert.False(t, status.GetTotpEnabled())
	assert.True(t, status.GetEmailMfaEnabled())
	assert.Contains(t, status.GetNotes(), "The effective trigger is EMAIL but the /mfa page only verifies TOTP; this account cannot complete the second factor until it is reset or TOTP is enrolled.")
}

func TestGetMFAStatus_NonAdminCannotReadAnotherUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	server := NewTwoFactorServer(userRepo, nil, nil, nil, "ShadowSSO")

	ctx := createAuthenticatedContextWithRoles(context.Background(), "user-2", rbac.RoleUser)
	_, err := server.GetMFAStatus(ctx, connect.NewRequest(&ssov1.GetMFAStatusRequest{UserId: "user-1"}))

	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestResetUserMFA_ClearsEverythingAndOptionallyPasskeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	server := NewTwoFactorServer(userRepo, nil, nil, nil, "ShadowSSO")

	user := &domain.User{
		ID:                     "user-1",
		Email:                  "user@example.com",
		IsTwoFactorEnabled:     true,
		TwoFactorMethod:        "TOTP",
		TwoFactorSecret:        "SECRET",
		TwoFactorRecoveryCodes: []string{"hash1", "hash2"},
		EmailMFAEnabled:        true,
		PushMFAEnabled:         true,
		PushMFADeviceTokens:    []string{"token"},
		MfaMethods:             []domain.MfaMethod{{ID: "m1", Type: domain.MfaMethodTypeTOTP, Verified: true}},
		WebAuthnDevices:        []domain.WebAuthnDevice{{ID: "d1"}},
		MFARequired:            true,
	}
	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-1").Return(user, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		return nil
	})

	ctx := createAuthenticatedContextWithRoles(context.Background(), "admin-1", rbac.RoleAdmin)
	resp, err := server.ResetUserMFA(ctx, connect.NewRequest(&ssov1.ResetUserMFARequest{
		UserId:         "user-1",
		RemovePasskeys: true,
	}))
	require.NoError(t, err)

	assert.Equal(t, "TOTP", resp.Msg.GetPrevious().GetEffectiveTrigger())
	assert.True(t, resp.Msg.GetRemovedPasskeys())

	assert.False(t, user.IsTwoFactorEnabled)
	assert.Equal(t, "NONE", user.TwoFactorMethod)
	assert.Empty(t, user.TwoFactorSecret)
	assert.Empty(t, user.TwoFactorRecoveryCodes)
	assert.False(t, user.EmailMFAEnabled)
	assert.False(t, user.PushMFAEnabled)
	assert.Empty(t, user.MfaMethods)
	assert.Empty(t, user.WebAuthnDevices)
	// The enforcement flag is deliberately preserved.
	assert.True(t, user.MFARequired)
}

func TestResetUserMFA_RequiresAdmin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	server := NewTwoFactorServer(userRepo, nil, nil, nil, "ShadowSSO")

	ctx := createAuthenticatedContextWithRoles(context.Background(), "user-2", rbac.RoleUser)
	_, err := server.ResetUserMFA(ctx, connect.NewRequest(&ssov1.ResetUserMFARequest{UserId: "user-1"}))

	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestSetUserMFARequired_AdminCanForceAndClear(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	server := NewTwoFactorServer(userRepo, nil, nil, nil, "ShadowSSO")

	user := &domain.User{ID: "user-1", Email: "user@example.com"}
	userRepo.EXPECT().GetUserByID(gomock.Any(), "user-1").Return(user, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.True(t, u.MFARequired)
		return nil
	})

	ctx := createAuthenticatedContextWithRoles(context.Background(), "admin-1", rbac.RoleAdmin)
	_, err := server.SetUserMFARequired(ctx, connect.NewRequest(&ssov1.SetUserMFARequiredRequest{
		UserId:   "user-1",
		Required: true,
	}))
	require.NoError(t, err)
	assert.True(t, user.MFARequired)
}

func TestGenerateRecoveryCodes_AdminTargetsAnotherUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	server := NewTwoFactorServer(userRepo, nil, nil, nil, "ShadowSSO")

	user := &domain.User{
		ID:                 "user-1",
		Email:              "user@example.com",
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
		TwoFactorSecret:    "SECRET",
	}
	userRepo.EXPECT().GetUserByID(gomock.Any(), "target-user").Return(user, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		assert.Len(t, u.TwoFactorRecoveryCodes, 10)
		return nil
	})

	ctx := createAuthenticatedContextWithRoles(context.Background(), "admin-1", rbac.RoleAdmin)
	resp, err := server.GenerateRecoveryCodes(ctx, connect.NewRequest(&ssov1.GenerateRecoveryCodesRequest{
		UserId: "target-user",
	}))
	require.NoError(t, err)

	assert.Len(t, resp.Msg.GetRecoveryCodes(), 10)
	for _, code := range resp.Msg.GetRecoveryCodes() {
		assert.NotEmpty(t, code)
	}
}

func TestSetMFAPolicy_PersistsRealmSetting(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mock_domain.NewMockUserRepository(ctrl)
	realmRepo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	server := NewTwoFactorServer(userRepo, nil, nil, nil, "ShadowSSO", WithTwoFactorRealmSettings(realmRepo))

	settings := &domain.RealmSettings{ID: "realm-1", Realm: "master"}
	realmRepo.EXPECT().GetRealmSettings(gomock.Any()).Return(settings, nil)
	realmRepo.EXPECT().UpdateRealmSettings(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, s *domain.RealmSettings) error {
		assert.True(t, s.RequireMFA)
		return nil
	})

	ctx := createAuthenticatedContextWithRoles(context.Background(), "admin-1", rbac.RoleAdmin)
	_, err := server.SetMFAPolicy(ctx, connect.NewRequest(&ssov1.SetMFAPolicyRequest{RequireMfa: true}))
	require.NoError(t, err)

	assert.True(t, settings.RequireMFA)
	assert.False(t, settings.UpdatedAt.IsZero())
	assert.WithinDuration(t, time.Now(), settings.UpdatedAt, time.Minute)
}
