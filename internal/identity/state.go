package identity

import (
	"context"
	"errors"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
)

// repoState is the SSO-owned state store over the local user collection. The
// directory identity's objectGUID is the _id of the record, so MFA methods,
// required actions, WebAuthn devices and local roles stay keyed by the
// identity they belong to and are never confused with a local account.
type repoState struct {
	users domain.UserRepository
}

// LocalUserState is implemented by repoState.
var _ LocalUserState = repoState{}

// NewLocalState builds the state store over the local user repository.
func NewLocalState(users domain.UserRepository) LocalUserState {
	return repoState{users: users}
}

// Get implements LocalUserState.
func (r repoState) Get(ctx context.Context, id string) (*domain.User, error) {
	return r.users.GetUserByID(ctx, id)
}

// Ensure implements LocalUserState: create the record if it is not there yet.
func (r repoState) Ensure(ctx context.Context, user *domain.User) error {
	err := r.users.UpdateUser(ctx, user)
	if !errors.Is(err, domain.ErrUserNotFound) {
		return err
	}
	// CreateUser hands the first user it ever sees the admin role. A directory
	// identity must not become the SSO administrator just because it was the
	// first to sign in here, so the roles are set before the insert; directory
	// roles are mapped onto this record later.
	if len(user.Roles) == 0 {
		user.Roles = []string{rbac.RoleUser}
	}
	return r.users.CreateUser(ctx, user)
}
