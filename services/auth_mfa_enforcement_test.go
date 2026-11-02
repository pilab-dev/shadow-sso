package services_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	client_mocks "github.com/pilab-dev/shadow-sso/client/mocks"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newAuthServerForMFATest(ctrl *gomock.Controller, realm *mock_domain.MockRealmSettingsRepository) (*services.AuthServer, *mock_domain.MockUserRepository, *mock_domain.MockPasswordHasher) {
	userRepo := mock_domain.NewMockUserRepository(ctrl)
	hasher := mock_domain.NewMockPasswordHasher(ctrl)
	server := services.NewAuthServer(
		userRepo,
		nil,
		mock_domain.NewMockTokenServiceInterface(ctrl),
		hasher,
		mock_domain.NewMockFlowStore(ctrl),
		mock_domain.NewMockOAuthServiceInterface(ctrl),
		client_mocks.NewMockClientServiceInterface(ctrl),
		services.WithAuthRealmSettings(realm),
	)
	return server, userRepo, hasher
}

func TestAuthServer_Login_MFARequiredWithoutFactorFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	server, userRepo, hasher := newAuthServerForMFATest(ctrl, nil)
	user := &domain.User{
		ID:           "user-1",
		Email:        "user@example.com",
		PasswordHash: "hashed",
		Status:       domain.UserStatusActive,
		MFARequired:  true,
	}
	userRepo.EXPECT().GetUserByEmail(gomock.Any(), user.Email).Return(user, nil)
	hasher.EXPECT().Verify("hashed", "password").Return(nil)

	_, err := server.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    user.Email,
		Password: "password",
	}))

	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestAuthServer_Login_RealmRequiresMFAWithoutFactorFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	realm := mock_domain.NewMockRealmSettingsRepository(ctrl)
	realm.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{RequireMFA: true}, nil)

	server, userRepo, hasher := newAuthServerForMFATest(ctrl, realm)
	user := &domain.User{
		ID:           "user-1",
		Email:        "user@example.com",
		PasswordHash: "hashed",
		Status:       domain.UserStatusActive,
	}
	userRepo.EXPECT().GetUserByEmail(gomock.Any(), user.Email).Return(user, nil)
	hasher.EXPECT().Verify("hashed", "password").Return(nil)

	_, err := server.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    user.Email,
		Password: "password",
	}))

	require.Error(t, err)
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestAuthServer_Login_ForcedUserWithTOTPStillChallenges(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	server, userRepo, hasher := newAuthServerForMFATest(ctrl, nil)
	user := &domain.User{
		ID:                 "user-1",
		Email:              "user@example.com",
		PasswordHash:       "hashed",
		Status:             domain.UserStatusActive,
		MFARequired:        true,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "TOTP",
		TwoFactorSecret:    "SECRET",
	}
	userRepo.EXPECT().GetUserByEmail(gomock.Any(), user.Email).Return(user, nil)
	hasher.EXPECT().Verify("hashed", "password").Return(nil)

	resp, err := server.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    user.Email,
		Password: "password",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.GetTwoFactorRequired())
	assert.NotEmpty(t, resp.Msg.GetTwoFactorSessionToken())
}
