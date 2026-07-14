package graphql_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/graphql"
	"go.uber.org/mock/gomock"
)

func adminCtx() context.Context {
	return context.WithValue(context.Background(), domain.TokenContextKey, &domain.TokenInfo{
		Roles:  []string{"ROLE_ADMIN"},
		UserID: "admin-1",
	})
}

func userCtx() context.Context {
	return context.WithValue(context.Background(), domain.TokenContextKey, &domain.TokenInfo{
		Roles:  []string{"ROLE_USER"},
		UserID: "user-1",
	})
}

func noTokenCtx() context.Context {
	return context.Background()
}

func connectErrCode(err error) connect.Code {
	connectErr := &connect.Error{}
	if ok := errors.As(err, &connectErr); ok {
		return connectErr.Code()
	}
	return connect.CodeUnknown
}

func newTestResolver(t *testing.T) *graphql.Resolver {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	return &graphql.Resolver{
		UserRepo:          mock_domain.NewMockUserRepository(ctrl),
		ClientRepo:        mock_domain.NewMockClientRepository(ctrl),
		SessionRepo:       mock_domain.NewMockSessionRepository(ctrl),
		IdPRepo:           mock_domain.NewMockIdPRepository(ctrl),
		EmailService:      &MockEmailService{},
		PasswordHasher:    &MockPasswordHasher{},
		GroupRepo:         &stubGroupRepo{},
		RealmSettingsRepo: &stubRealmSettingsRepo{},
	}
}

type stubGroupRepo struct{}

func (s *stubGroupRepo) CreateGroup(_ context.Context, _ *domain.Group) error { return nil }
func (s *stubGroupRepo) GetGroupByID(_ context.Context, _ string) (*domain.Group, error) {
	return &domain.Group{}, nil
}
func (s *stubGroupRepo) GetGroupByPath(_ context.Context, _ string) (*domain.Group, error) {
	return &domain.Group{}, nil
}
func (s *stubGroupRepo) UpdateGroup(_ context.Context, _ *domain.Group) error { return nil }
func (s *stubGroupRepo) DeleteGroup(_ context.Context, _ string) error       { return nil }
func (s *stubGroupRepo) ListGroups(_ context.Context) ([]*domain.Group, error) {
	return nil, nil
}
func (s *stubGroupRepo) AddMember(_ context.Context, _, _ string) error    { return nil }
func (s *stubGroupRepo) RemoveMember(_ context.Context, _, _ string) error { return nil }
func (s *stubGroupRepo) GetMemberCount(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
func (s *stubGroupRepo) AddRealmRole(_ context.Context, _, _ string) error { return nil }
func (s *stubGroupRepo) RemoveRealmRole(_ context.Context, _, _ string) error {
	return nil
}
func (s *stubGroupRepo) AddClientRole(_ context.Context, _, _, _ string) error { return nil }
func (s *stubGroupRepo) RemoveClientRole(_ context.Context, _, _, _ string) error {
	return nil
}

type stubRealmSettingsRepo struct{}

func (s *stubRealmSettingsRepo) GetRealmSettings(_ context.Context) (*domain.RealmSettings, error) {
	return &domain.RealmSettings{}, nil
}
func (s *stubRealmSettingsRepo) UpdateRealmSettings(_ context.Context, _ *domain.RealmSettings) error {
	return nil
}

func TestDeleteUser_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)
	userRepo.EXPECT().DeleteUser(gomock.Any(), "u1").Return(nil)

	ok, err := r.Mutation().DeleteUser(adminCtx(), "u1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestDeleteUser_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().DeleteUser(userCtx(), "u1")
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestDeleteUser_NoToken(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().DeleteUser(noTokenCtx(), "u1")
	if err == nil {
		t.Fatal("expected error for unauthenticated caller")
	}
	if connectErrCode(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", connectErrCode(err))
	}
}

func TestCreateUser_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)
	userRepo.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(nil)

	user, err := r.Mutation().CreateUser(adminCtx(), graphql.CreateUserInput{Email: "a@b.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user")
	}
}

func TestCreateUser_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().CreateUser(userCtx(), graphql.CreateUserInput{Email: "a@b.com"})
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestCreateUser_NoToken(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().CreateUser(noTokenCtx(), graphql.CreateUserInput{Email: "a@b.com"})
	if err == nil {
		t.Fatal("expected error for unauthenticated caller")
	}
	if connectErrCode(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", connectErrCode(err))
	}
}

func TestResetPassword_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)
	userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1"}, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)

	ok, err := r.Mutation().ResetPassword(adminCtx(), "u1", "newpass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestResetPassword_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().ResetPassword(userCtx(), "u1", "newpass")
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestResetPassword_NoToken(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().ResetPassword(noTokenCtx(), "u1", "newpass")
	if err == nil {
		t.Fatal("expected error for unauthenticated caller")
	}
	if connectErrCode(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", connectErrCode(err))
	}
}

func TestDeleteClient_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	clientRepo := r.ClientRepo.(*mock_domain.MockClientRepository)
	clientRepo.EXPECT().DeleteClient(gomock.Any(), "c1").Return(nil)

	ok, err := r.Mutation().DeleteClient(adminCtx(), "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestDeleteClient_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().DeleteClient(userCtx(), "c1")
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestDeleteClient_NoToken(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().DeleteClient(noTokenCtx(), "c1")
	if err == nil {
		t.Fatal("expected error for unauthenticated caller")
	}
	if connectErrCode(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", connectErrCode(err))
	}
}

func TestRevokeAllSessions_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sessionRepo := r.SessionRepo.(*mock_domain.MockSessionRepository)
	sessionRepo.EXPECT().DeleteSessionsByUserID(gomock.Any(), "u1").Return(int64(3), nil)

	ok, err := r.Mutation().RevokeAllSessions(adminCtx(), "u1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestRevokeAllSessions_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().RevokeAllSessions(userCtx(), "u1")
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestRevokeAllSessions_NoToken(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().RevokeAllSessions(noTokenCtx(), "u1")
	if err == nil {
		t.Fatal("expected error for unauthenticated caller")
	}
	if connectErrCode(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", connectErrCode(err))
	}
}

func TestUpdateRealm_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)

	result, err := r.Mutation().UpdateRealm(adminCtx(), graphql.UpdateRealmInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected realm settings")
	}
}

func TestUpdateRealm_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().UpdateRealm(userCtx(), graphql.UpdateRealmInput{})
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestUpdateRealm_NoToken(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().UpdateRealm(noTokenCtx(), graphql.UpdateRealmInput{})
	if err == nil {
		t.Fatal("expected error for unauthenticated caller")
	}
	if connectErrCode(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", connectErrCode(err))
	}
}

func TestSetUserPassword_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := r.UserRepo.(*mock_domain.MockUserRepository)
	userRepo.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1"}, nil)
	userRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)

	ok, err := r.Mutation().SetUserPassword(adminCtx(), "u1", "newpass", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestSetUserPassword_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().SetUserPassword(userCtx(), "u1", "newpass", false)
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestSetUserPassword_NoToken(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().SetUserPassword(noTokenCtx(), "u1", "newpass", false)
	if err == nil {
		t.Fatal("expected error for unauthenticated caller")
	}
	if connectErrCode(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", connectErrCode(err))
	}
}

func TestCreateClient_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	clientRepo := r.ClientRepo.(*mock_domain.MockClientRepository)
	clientRepo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).Return(nil)

	client, err := r.Mutation().CreateClient(adminCtx(), graphql.CreateClientInput{
		ClientID:   "new-client",
		ClientName: "New Client",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected client")
	}
}

func TestCreateClient_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().CreateClient(userCtx(), graphql.CreateClientInput{
		ClientID:   "new-client",
		ClientName: "New Client",
	})
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestCreateClient_NoToken(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().CreateClient(noTokenCtx(), graphql.CreateClientInput{
		ClientID:   "new-client",
		ClientName: "New Client",
	})
	if err == nil {
		t.Fatal("expected error for unauthenticated caller")
	}
	if connectErrCode(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", connectErrCode(err))
	}
}

func TestDeleteGroup_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)

	ok, err := r.Mutation().DeleteGroup(adminCtx(), "g1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestDeleteGroup_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().DeleteGroup(userCtx(), "g1")
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestDeleteIdentityProvider_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idpRepo := r.IdPRepo.(*mock_domain.MockIdPRepository)
	idpRepo.EXPECT().DeleteIdP(gomock.Any(), "idp1").Return(nil)

	ok, err := r.Mutation().DeleteIdentityProvider(adminCtx(), "idp1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestDeleteIdentityProvider_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().DeleteIdentityProvider(userCtx(), "idp1")
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestUpdateIdentityProvider_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idpRepo := r.IdPRepo.(*mock_domain.MockIdPRepository)
	idpRepo.EXPECT().GetIdPByID(gomock.Any(), "idp1").Return(&domain.IdentityProvider{ID: "idp1"}, nil)
	idpRepo.EXPECT().UpdateIdP(gomock.Any(), gomock.Any()).Return(nil)

	_, err := r.Mutation().UpdateIdentityProvider(adminCtx(), "idp1", graphql.UpdateIdentityProviderInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateIdentityProvider_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().UpdateIdentityProvider(userCtx(), "idp1", graphql.UpdateIdentityProviderInput{})
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}

func TestGenerateClientSecret_AdminAllowed(t *testing.T) {
	r := newTestResolver(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	clientRepo := r.ClientRepo.(*mock_domain.MockClientRepository)
	clientRepo.EXPECT().GetClient(gomock.Any(), "c1").Return(&domain.Client{ID: "c1"}, nil)
	clientRepo.EXPECT().UpdateClient(gomock.Any(), gomock.Any()).Return(nil)

	secret, err := r.Mutation().GenerateClientSecret(adminCtx(), "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
}

func TestGenerateClientSecret_UserDenied(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Mutation().GenerateClientSecret(userCtx(), "c1")
	if err == nil {
		t.Fatal("expected error for non-admin user")
	}
	if connectErrCode(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connectErrCode(err))
	}
}
