package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/pilab-dev/shadow-sso/domain"
)

// LocalSource is the default identity source: MongoDB holds the identity and
// the password is a local bcrypt hash. It is what ShadowSSO uses standalone,
// and what every deployment uses until it points at a directory.
type LocalSource struct {
	users  domain.UserRepository
	hasher domain.PasswordHasher
}

// IdentitySource is implemented by LocalSource.
var _ IdentitySource = (*LocalSource)(nil)

// NewLocalSource builds the local source. The record it resolves is its own
// state record, so it needs no LocalUserState: see Identity.Record.
func NewLocalSource(users domain.UserRepository, hasher domain.PasswordHasher) *LocalSource {
	return &LocalSource{users: users, hasher: hasher}
}

// Name implements IdentitySource.
func (s *LocalSource) Name() string { return SourceLocal }

// Resolve implements IdentitySource. The whole user record travels on the
// identity so the facade can return it without a second read.
func (s *LocalSource) Resolve(ctx context.Context, login string) (*Identity, error) {
	user, err := s.users.GetUserByEmail(ctx, login)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Identity{
		ID:     user.ID,
		Status: user.Status,
		Email:  user.Email,
		Record: user,
	}, nil
}

// Authenticate implements IdentitySource. It compares against the hash in the
// record Resolve returned; no other read is needed.
func (s *LocalSource) Authenticate(_ context.Context, ident *Identity, password string) (*AuthResult, error) {
	if ident == nil || ident.Record == nil || ident.Record.PasswordHash == "" {
		// A record with no hash can never match: bcrypt would only report a
		// malformed hash, which is the same answer for a wrong password.
		return &AuthResult{Code: CodeInvalid}, nil
	}
	if err := s.hasher.Verify(ident.Record.PasswordHash, password); err != nil {
		return &AuthResult{Code: CodeInvalid}, nil
	}
	return &AuthResult{Code: CodeOK}, nil
}

// Get implements IdentitySource.
func (s *LocalSource) Get(ctx context.Context, id string) (*Identity, error) {
	user, err := s.users.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Identity{
		ID:     user.ID,
		Status: user.Status,
		Email:  user.Email,
		Record: user,
	}, nil
}

// Memberships implements IdentitySource. The local source has no group
// directory of its own: local roles live on domain.User.Roles and are read
// from the record, which is why this reports no memberships rather than
// inventing one. Directory groups come from PiRectory.
func (s *LocalSource) Memberships(context.Context, string, bool) ([]Group, error) {
	return nil, nil
}
