package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/pilab-dev/shadow-sso/domain"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
)

// newTestHasher is bcrypt at its cheapest cost: the tests care about the
// seam, not about the work factor.
func newTestHasher() domain.PasswordHasher {
	return pkgauth.NewBcryptPasswordHasher(bcrypt.MinCost)
}

// fakeUsers is a UserRepository that answers only what the tests ask for; the
// embedded nil interface fails loudly if anything else is reached.
type fakeUsers struct {
	domain.UserRepository
	byEmail map[string]*domain.User
	byID    map[string]*domain.User

	created []*domain.User
	updated []*domain.User
}

func (f *fakeUsers) GetUserByEmail(_ context.Context, email string) (*domain.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUsers) GetUserByID(_ context.Context, id string) (*domain.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeUsers) UpdateUser(_ context.Context, u *domain.User) error {
	if _, ok := f.byID[u.ID]; !ok {
		return domain.ErrUserNotFound
	}
	f.updated = append(f.updated, u)
	return nil
}

func (f *fakeUsers) CreateUser(_ context.Context, u *domain.User) error {
	f.byID[u.ID] = u
	f.created = append(f.created, u)
	return nil
}

// fakeState is the SSO-owned record store for an external directory.
type fakeState struct {
	records map[string]*domain.User
	ensured []*domain.User
	err     error
}

func (f *fakeState) Get(_ context.Context, id string) (*domain.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	u, ok := f.records[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakeState) Ensure(_ context.Context, user *domain.User) error {
	if f.err != nil {
		return f.err
	}
	f.ensured = append(f.ensured, user)
	f.records[user.ID] = user
	return nil
}

// fakeSource is a directory: no record of its own, so the facade has to merge
// the projection with the local state.
type fakeSource struct {
	resolve *Identity
	auth    *AuthResult

	resolveErr error
	authErr    error

	authCalls int
}

func (f *fakeSource) Name() string { return SourceDirectory }

func (f *fakeSource) Resolve(context.Context, string) (*Identity, error) {
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	return f.resolve, nil
}

func (f *fakeSource) Authenticate(context.Context, *Identity, string) (*AuthResult, error) {
	f.authCalls++
	if f.authErr != nil {
		return nil, f.authErr
	}
	return f.auth, nil
}

func (f *fakeSource) Get(context.Context, string) (*Identity, error) {
	return f.resolve, nil
}

func (f *fakeSource) Memberships(context.Context, string, bool) ([]Group, error) {
	return nil, nil
}

func localRig(t *testing.T) (*Service, *fakeUsers, *domain.User) {
	t.Helper()
	hash, err := newTestHasher().Hash("correct horse")
	require.NoError(t, err)
	user := &domain.User{
		ID:           "local-1",
		Email:        "alice@pi.lab",
		PasswordHash: hash,
		Status:       domain.UserStatusActive,
		Roles:        []string{"ROLE_USER"},
	}
	users := &fakeUsers{byEmail: map[string]*domain.User{"alice@pi.lab": user}, byID: map[string]*domain.User{}}
	return New(NewLocalSource(users, newTestHasher()), nil), users, user
}

func TestLocalVerifySucceedsWithTheStoredHash(t *testing.T) {
	svc, _, user := localRig(t)

	got, err := svc.Verify(context.Background(), "alice@pi.lab", "correct horse")
	require.NoError(t, err)
	// The local record is both the identity and the state, so it comes back
	// whole: the caller still needs the hash to update it.
	assert.Same(t, user, got)
}

func TestLocalVerifyRejectsAWrongPassword(t *testing.T) {
	svc, _, _ := localRig(t)

	got, err := svc.Verify(context.Background(), "alice@pi.lab", "wrong")
	require.ErrorIs(t, err, ErrInvalidCredentials)
	// The identity was found, so the caller can audit with its id.
	require.NotNil(t, got)
	assert.Equal(t, "local-1", got.ID)
}

func TestLocalVerifySaysNotFoundWithoutSayingWhy(t *testing.T) {
	svc, _, _ := localRig(t)

	got, err := svc.Verify(context.Background(), "nobody@pi.lab", "correct horse")
	require.ErrorIs(t, err, ErrNotFound)
	assert.Nil(t, got)
}

func TestLocalVerifyRefusesLockedAndPendingAccounts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status domain.UserStatus
		want   error
	}{
		{"locked", domain.UserStatusLocked, ErrLocked},
		{"pending", domain.UserStatusPending, ErrPending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, users, user := localRig(t)
			user.Status = tc.status
			users.byEmail["alice@pi.lab"] = user

			got, err := svc.Verify(context.Background(), "alice@pi.lab", "correct horse")
			require.ErrorIs(t, err, tc.want)
			// Still resolved, for the audit trail.
			require.NotNil(t, got)
			assert.Equal(t, "local-1", got.ID)
		})
	}
}

func TestLocalVerifyDoesNotRunWhenTheAccountIsNotActive(t *testing.T) {
	svc, _, user := localRig(t)
	user.Status = domain.UserStatusLocked
	src := svc.source.(*LocalSource)
	calls := 0
	svc.source = &countingSource{IdentitySource: src, onAuth: func() { calls++ }}

	_, err := svc.Verify(context.Background(), "alice@pi.lab", "correct horse")
	require.ErrorIs(t, err, ErrLocked)
	assert.Zero(t, calls, "a locked account must not reach the password check")
}

func TestDirectoryVerifyProjectsTheIdentityOntoTheState(t *testing.T) {
	state := &fakeState{records: map[string]*domain.User{
		"guid-1": {
			ID:                 "guid-1",
			Source:             SourceDirectory,
			Roles:              []string{"ROLE_USER"},
			IsTwoFactorEnabled: true,
			TwoFactorMethod:    "TOTP",
		},
	}}
	src := &fakeSource{
		resolve: &Identity{
			ID:         "guid-1",
			Status:     domain.UserStatusActive,
			Email:      "alice@pi.lab",
			GivenName:  "Alice",
			Surname:    "Example",
			Attributes: map[string][]string{"sAMAccountName": {"alice"}},
			Groups:     []Group{{ID: "g1", Name: "engineering"}},
		},
		auth: &AuthResult{Code: CodeOK},
	}
	svc := New(src, state)

	got, err := svc.Verify(context.Background(), "alice", "pw")
	require.NoError(t, err)

	assert.Equal(t, SourceDirectory, got.Source)
	assert.Equal(t, "guid-1", got.DirectoryID)
	assert.Equal(t, "alice@pi.lab", got.Email)
	assert.Equal(t, "Alice", got.FirstName)
	assert.Equal(t, []string{"engineering"}, got.Groups)
	// SSO-owned state survives the projection.
	assert.True(t, got.IsTwoFactorEnabled)
	assert.Equal(t, "TOTP", got.TwoFactorMethod)
	assert.Equal(t, []string{"ROLE_USER"}, got.Roles)
	// A directory password is never stored here.
	assert.Empty(t, got.PasswordHash)
	// Nothing to create: the state record already existed.
	assert.Empty(t, state.ensured)
}

func TestDirectoryVerifyCreatesTheStateRecordOnFirstLogin(t *testing.T) {
	state := &fakeState{records: map[string]*domain.User{}}
	src := &fakeSource{
		resolve: &Identity{ID: "guid-2", Status: domain.UserStatusActive, Email: "bob@pi.lab"},
		auth:    &AuthResult{Code: CodeOK},
	}
	svc := New(src, state)

	got, err := svc.Verify(context.Background(), "bob", "pw")
	require.NoError(t, err)
	require.NotNil(t, got)

	require.Len(t, state.ensured, 1)
	assert.Equal(t, "guid-2", state.ensured[0].ID)
	assert.Equal(t, SourceDirectory, state.ensured[0].Source)
	assert.Empty(t, state.ensured[0].PasswordHash)
	// The identity is handed back even though it has no record yet.
	assert.Equal(t, "bob@pi.lab", got.Email)
}

func TestDirectoryVerifyMapsEveryCredentialOutcome(t *testing.T) {
	tests := []struct {
		name    string
		result  *AuthResult
		wantErr error
	}{
		{"ok", &AuthResult{Code: CodeOK}, nil},
		{"invalid", &AuthResult{Code: CodeInvalid}, ErrInvalidCredentials},
		{"locked", &AuthResult{Code: CodeLocked}, ErrLocked},
		{"expired", &AuthResult{Code: CodeExpired}, ErrExpired},
		{"must change", &AuthResult{Code: CodeOK, MustChange: true}, ErrExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &fakeState{records: map[string]*domain.User{"guid": {ID: "guid"}}}
			src := &fakeSource{
				resolve: &Identity{ID: "guid", Status: domain.UserStatusActive},
				auth:    tc.result,
			}
			svc := New(src, state)

			got, err := svc.Verify(context.Background(), "alice", "pw")
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			require.NotNil(t, got, "the identity was found, so it is auditable")
		})
	}
}

func TestVerifyInteractiveParksAForcedChangeOnTheRequiredAction(t *testing.T) {
	state := &fakeState{records: map[string]*domain.User{"guid": {ID: "guid"}}}
	src := &fakeSource{
		resolve: &Identity{ID: "guid", Status: domain.UserStatusActive},
		auth:    &AuthResult{Code: CodeOK, MustChange: true},
	}
	svc := New(src, state)

	got, err := svc.VerifyInteractive(context.Background(), "alice", "pw")
	require.NoError(t, err)
	assert.True(t, got.HasRequiredAction(domain.RequiredActionUpdatePassword))

	// A wrong password is still a failure on the interactive path.
	src.auth = &AuthResult{Code: CodeInvalid}
	_, err = svc.VerifyInteractive(context.Background(), "alice", "pw")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	// The non-interactive path never lets a must-change credential through.
	src.auth = &AuthResult{Code: CodeOK, MustChange: true}
	_, err = svc.Verify(context.Background(), "alice", "pw")
	require.ErrorIs(t, err, ErrExpired)
}

func TestDirectoryVerifyNeverReportsAnOutageAsABadPassword(t *testing.T) {
	state := &fakeState{records: map[string]*domain.User{"guid": {ID: "guid"}}}
	src := &fakeSource{resolveErr: ErrUnavailable}
	svc := New(src, state)

	_, err := svc.Verify(context.Background(), "alice", "pw")
	require.ErrorIs(t, err, ErrUnavailable)
	assert.NotErrorIs(t, err, ErrInvalidCredentials)
}

func TestDirectoryVerifyFailsClosedWhenTheStateCannotBeRead(t *testing.T) {
	state := &fakeState{err: errors.New("mongo is down")}
	src := &fakeSource{resolve: &Identity{ID: "guid", Status: domain.UserStatusActive}}
	svc := New(src, state)

	// An unreadable state record means the MFA requirements are unknown.
	_, err := svc.Verify(context.Background(), "alice", "pw")
	require.ErrorIs(t, err, ErrUnavailable)
	assert.Zero(t, src.authCalls, "the password must not be checked first")
}

func TestDirectoryVerifyRejectsAnAccountBeforeCheckingThePassword(t *testing.T) {
	state := &fakeState{records: map[string]*domain.User{"guid": {ID: "guid"}}}
	src := &fakeSource{
		resolve: &Identity{ID: "guid", Status: domain.UserStatusLocked},
		auth:    &AuthResult{Code: CodeOK},
	}
	svc := New(src, state)

	_, err := svc.Verify(context.Background(), "alice", "pw")
	require.ErrorIs(t, err, ErrLocked)
	assert.Zero(t, src.authCalls)
}

func TestServiceResolveDoesNotCheckAPassword(t *testing.T) {
	state := &fakeState{records: map[string]*domain.User{"guid": {ID: "guid"}}}
	src := &fakeSource{
		resolve: &Identity{ID: "guid", Status: domain.UserStatusActive},
		auth:    &AuthResult{Code: CodeOK},
	}
	svc := New(src, state)

	got, err := svc.Resolve(context.Background(), "alice")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Zero(t, src.authCalls)
}

// countingSource counts Authenticate calls through an embedded source.
type countingSource struct {
	IdentitySource
	onAuth func()
}

func (c *countingSource) Authenticate(ctx context.Context, ident *Identity, password string) (*AuthResult, error) {
	c.onAuth()
	return c.IdentitySource.Authenticate(ctx, ident, password)
}
