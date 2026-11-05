package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type userAdminFixture struct {
	users  *mock_domain.MockUserRepository
	hasher *mock_domain.MockPasswordHasher
	email  *mock_domain.MockEmailService
	server *UserAdminServiceServer
}

func newUserAdminFixture(t *testing.T) *userAdminFixture {
	ctrl := gomock.NewController(t)
	f := &userAdminFixture{
		users:  mock_domain.NewMockUserRepository(ctrl),
		hasher: mock_domain.NewMockPasswordHasher(ctrl),
		email:  mock_domain.NewMockEmailService(ctrl),
	}
	f.server = NewUserAdminServer(f.users, f.hasher, f.email, "https://sso.test/")
	return f
}

func TestUserAdmin_SetUserPassword_TemporaryAddsAction(t *testing.T) {
	f := newUserAdminFixture(t)
	user := &domain.User{ID: "u1", PasswordResetToken: "x"}
	f.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(user, nil)
	f.hasher.EXPECT().Hash("s3cret").Return("hashed", nil)
	f.users.EXPECT().UpdateUser(gomock.Any(), user).Return(nil)

	resp, err := f.server.SetUserPassword(context.Background(), connect.NewRequest(&ssov1.SetUserPasswordRequest{
		UserId: "u1", Password: "s3cret", Temporary: true,
	}))
	require.NoError(t, err)
	assert.Equal(t, "hashed", user.PasswordHash)
	assert.Contains(t, user.RequiredActions, domain.RequiredActionUpdatePassword)
	assert.NotContains(t, resp.Msg.String(), "s3cret")
}

func TestUserAdmin_AdminResetPassword_ErrorsDoNotLeakPassword(t *testing.T) {
	f := newUserAdminFixture(t)
	f.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", PasswordResetToken: "tok"}, nil)
	f.hasher.EXPECT().Hash("s3cret").Return("", errors.New("hash failed for s3cret"))

	_, err := f.server.AdminResetPassword(context.Background(), connect.NewRequest(&ssov1.AdminResetPasswordRequest{
		UserId: "u1", NewPassword: "s3cret",
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	assert.False(t, strings.Contains(err.Error(), "s3cret"))
}

func TestUserAdmin_AdminResetPassword_ClearsResetToken(t *testing.T) {
	f := newUserAdminFixture(t)
	user := &domain.User{ID: "u1", PasswordResetToken: "tok"}
	f.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(user, nil)
	f.hasher.EXPECT().Hash("pw").Return("h", nil)
	f.users.EXPECT().UpdateUser(gomock.Any(), user).Return(nil)

	_, err := f.server.AdminResetPassword(context.Background(), connect.NewRequest(&ssov1.AdminResetPasswordRequest{UserId: "u1", NewPassword: "pw"}))
	require.NoError(t, err)
	assert.Empty(t, user.PasswordResetToken)
	assert.Equal(t, "h", user.PasswordHash)
}

func TestUserAdmin_SetPassword_Validation(t *testing.T) {
	f := newUserAdminFixture(t)
	_, err := f.server.SetUserPassword(context.Background(), connect.NewRequest(&ssov1.SetUserPasswordRequest{UserId: "u1"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	f.users.EXPECT().GetUserByID(gomock.Any(), "missing").Return(nil, errors.New("user not found"))
	_, err = f.server.SetUserPassword(context.Background(), connect.NewRequest(&ssov1.SetUserPasswordRequest{UserId: "missing", Password: "x"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestUserAdmin_RequiredActions(t *testing.T) {
	f := newUserAdminFixture(t)
	_, err := f.server.AddRequiredAction(context.Background(), connect.NewRequest(&ssov1.AddRequiredActionRequest{UserId: "u1", Action: "BOGUS"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = f.server.ExecuteActions(context.Background(), connect.NewRequest(&ssov1.ExecuteActionsRequest{UserId: "u1", Actions: []string{"BOGUS"}}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	user := &domain.User{ID: "u1"}
	f.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(user, nil).Times(2)
	f.users.EXPECT().UpdateUser(gomock.Any(), user).Return(nil).Times(2)
	_, err = f.server.AddRequiredAction(context.Background(), connect.NewRequest(&ssov1.AddRequiredActionRequest{UserId: "u1", Action: domain.RequiredActionUpdatePassword}))
	require.NoError(t, err)
	assert.Contains(t, user.RequiredActions, domain.RequiredActionUpdatePassword)
	_, err = f.server.RemoveRequiredAction(context.Background(), connect.NewRequest(&ssov1.RemoveRequiredActionRequest{UserId: "u1", Action: domain.RequiredActionUpdatePassword}))
	require.NoError(t, err)
	assert.NotContains(t, user.RequiredActions, domain.RequiredActionUpdatePassword)
}

func TestUserAdmin_SendPasswordResetEmail(t *testing.T) {
	f := newUserAdminFixture(t)
	f.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", Email: "a@b.c", FirstName: "A"}, nil)
	f.users.EXPECT().StorePasswordResetToken(gomock.Any(), "u1", gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _, digest string, exp time.Time) error {
			assert.NotEmpty(t, digest)
			return nil
		})
	f.email.EXPECT().SendPasswordResetEmail("a@b.c", "A", gomock.Any()).DoAndReturn(func(_, _, link string) error {
		assert.True(t, strings.HasPrefix(link, "https://sso.test/reset-password?token="))
		return nil
	})
	_, err := f.server.SendPasswordResetEmail(context.Background(), connect.NewRequest(&ssov1.SendPasswordResetEmailRequest{UserId: "u1"}))
	require.NoError(t, err)
}

func TestUserAdmin_SendEmailWithoutProvider(t *testing.T) {
	s := NewUserAdminServer(nil, nil, nil, "")
	_, err := s.SendVerificationEmail(context.Background(), connect.NewRequest(&ssov1.SendVerificationEmailRequest{UserId: "u1"}))
	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestUserAdmin_DeleteUserCredential(t *testing.T) {
	f := newUserAdminFixture(t)
	f.users.EXPECT().RemoveMfaMethod(gomock.Any(), "u1", "c1").Return(nil)
	f.users.EXPECT().RemoveMfaMethod(gomock.Any(), "u1", "c2").Return(errors.New("not found"))
	_, err := f.server.DeleteUserCredential(context.Background(), connect.NewRequest(&ssov1.DeleteUserCredentialRequest{UserId: "u1", CredentialId: "c1"}))
	require.NoError(t, err)
	_, err = f.server.DeleteUserCredential(context.Background(), connect.NewRequest(&ssov1.DeleteUserCredentialRequest{UserId: "u1", CredentialId: "c2"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}
