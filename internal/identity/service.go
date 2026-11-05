package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/pilab-dev/shadow-sso/domain"
)

// Service is the facade every login path authenticates through. It resolves
// the identity, applies the source's account state, verifies the password and
// merges the SSO-owned state, so AuthServer, OAuthService and the OIDC flow
// keep working with the domain.User shape they already have.
//
// It is deliberately not a repository: it holds no data of its own beyond the
// source and, for an external directory, the local state store.
type Service struct {
	source IdentitySource
	state  LocalUserState
}

// Verifier is implemented by Service.
var _ Verifier = (*Service)(nil)

// New builds a Service over source. state may be nil when the source keeps
// the SSO-owned record itself, which is what the local source does; an
// external directory needs one, or an identity has nowhere to keep its MFA
// state, required actions and local roles.
func New(source IdentitySource, state LocalUserState) *Service {
	return &Service{source: source, state: state}
}

// Name reports the configured identity source.
func (s *Service) Name() string { return s.source.Name() }

// Resolve returns the current projection for a login without checking a
// password. It fails with ErrLocked or ErrPending when the account may not
// authenticate, so a caller that only wants to know "does this login exist
// and may it sign in" does not have to re-implement the state mapping.
func (s *Service) Resolve(ctx context.Context, login string) (*domain.User, error) {
	ident, err := s.source.Resolve(ctx, login)
	if err != nil {
		return nil, err
	}
	user, _, err := s.project(ctx, ident)
	if err != nil {
		return nil, err
	}
	if err := statusError(ident.Status); err != nil {
		return user, err
	}
	return user, nil
}

// Verify resolves a login and checks its password. The user is returned
// whenever the identity was found, even when err is non-nil, so callers can
// audit with the account id; it is nil only when the login is unknown or the
// source could not be read.
func (s *Service) Verify(ctx context.Context, login, password string) (*domain.User, error) {
	ident, err := s.source.Resolve(ctx, login)
	if err != nil {
		return nil, err
	}
	user, fresh, err := s.project(ctx, ident)
	if err != nil {
		return nil, err
	}
	if err := statusError(ident.Status); err != nil {
		return user, err
	}

	res, err := s.source.Authenticate(ctx, ident, password)
	if err != nil {
		return user, err
	}
	if res == nil {
		return user, fmt.Errorf("%w: source %q gave no result", ErrUnavailable, s.source.Name())
	}
	switch {
	case res.Code == CodeOK && res.MustChange:
		// The credential is accepted by the directory but may not be used
		// any more. ShadowSSO has no directory password-change flow yet, so
		// accepting it would bypass the directory's policy and refusing
		// silently would look like a bad password.
		return user, ErrExpired
	case res.Code == CodeOK:
		if fresh {
			s.ensureState(ctx, user)
		}
		return user, nil
	case res.Code == CodeLocked:
		return user, ErrLocked
	case res.Code == CodeExpired:
		return user, ErrExpired
	default:
		return user, ErrInvalidCredentials
	}
}

// Get returns the current projection for an id.
func (s *Service) Get(ctx context.Context, id string) (*domain.User, error) {
	ident, err := s.source.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	user, _, err := s.project(ctx, ident)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// project combines the source projection with the SSO-owned state record.
// fresh reports that the state record does not exist yet, which is when a
// directory identity first signs in here.
func (s *Service) project(ctx context.Context, ident *Identity) (user *domain.User, fresh bool, err error) {
	if ident == nil || ident.ID == "" {
		return nil, false, ErrNotFound
	}
	// The source keeps the record itself: it is both the identity and the
	// state, so there is nothing to merge.
	if ident.Record != nil {
		return ident.Record, false, nil
	}
	if s.state == nil {
		return nil, false, fmt.Errorf("%w: source %q keeps no record and no local state is configured", ErrUnavailable, s.source.Name())
	}
	state, err := s.state.Get(ctx, ident.ID)
	switch {
	case err == nil:
		return merge(s.source.Name(), ident, state), false, nil
	case errors.Is(err, domain.ErrUserNotFound):
		return merge(s.source.Name(), ident, nil), true, nil
	default:
		return nil, false, fmt.Errorf("%w: local state for %s: %v", ErrUnavailable, ident.ID, err)
	}
}

// ensureState creates the SSO-owned record for an identity that is signing in
// here for the first time. A failure is not fatal: the login still succeeds
// and the record is retried on the next write, exactly as a session store
// failure is today.
func (s *Service) ensureState(ctx context.Context, user *domain.User) {
	if s.state == nil || user == nil {
		return
	}
	if err := s.state.Ensure(ctx, user); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("user.id", user.ID).Str("source", s.source.Name()).
			Msg("identity: could not create the local state record")
	}
}

// statusError maps the account state onto the login failure it means. Only
// the explicit states fail: a record with no state at all is treated as
// usable, which is what the local store has always done.
func statusError(status domain.UserStatus) error {
	switch status {
	case domain.UserStatusLocked:
		return ErrLocked
	case domain.UserStatusPending:
		return ErrPending
	default:
		return nil
	}
}

// merge projects an external identity onto its SSO-owned state record. The
// directory owns the identity fields; everything SSO-owned (MFA, required
// actions, local roles, WebAuthn devices, last login) comes from state, which
// is nil for an identity that has never signed in here.
func merge(source string, ident *Identity, state *domain.User) *domain.User {
	var u domain.User
	if state != nil {
		u = *state
	}
	u.ID = ident.ID
	u.Source = source
	u.DirectoryID = ident.ID
	u.Status = ident.Status
	u.Email = ident.Email
	u.FirstName = ident.GivenName
	u.LastName = ident.Surname
	// A directory password is never stored here, not even a stale one.
	u.PasswordHash = ""
	u.Groups = groupNames(ident.Groups)
	u.Attributes = ident.Attributes
	u.USN = ident.USN
	return &u
}

func groupNames(groups []Group) []string {
	if len(groups) == 0 {
		return nil
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		name := g.Name
		if name == "" {
			name = g.DN
		}
		if name == "" {
			name = g.ID
		}
		names = append(names, name)
	}
	return names
}
