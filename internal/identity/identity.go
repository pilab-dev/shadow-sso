// Package identity is the seam between ShadowSSO and the system that owns
// user identity. ShadowSSO owns clients, sessions, consent and token issuing;
// it does not own passwords.
//
// The port is the IdentitySource of docs/architecture/16 in the PiRectory
// repository: `local` (MongoDB, the default for standalone use) implements it
// in this package, `pirectory` implements it in internal/directory over
// accounts.v1 and credentials.v1. Service is the facade every login path
// goes through; it merges the source projection with the SSO-owned state and
// hands the callers the domain.User shape they already expect.
package identity

import (
	"context"
	"errors"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
)

// The identity sources ShadowSSO can be configured with. The values are the
// ones domain.User.Source stores.
const (
	// SourceLocal is MongoDB: the identity record and the SSO state are the
	// same document, and the password is a local bcrypt hash.
	SourceLocal = domain.SourceLocal
	// SourceDirectory is an external directory that owns the password and the
	// attributes. PiRectory is the first one; its source name is `pirectory`.
	SourceDirectory = domain.SourceDirectory
)

// The failures a login can end in. Callers map them onto their own protocol
// errors; the messages are the ones the login endpoints already return.
var (
	// ErrNotFound means no identity answers to the login. A directory outage
	// is not this: see ErrUnavailable.
	ErrNotFound = errors.New("identity not found")
	// ErrInvalidCredentials means the identity exists and the password does
	// not match. It never says which of the two was wrong to the client.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrLocked means the account may not authenticate right now.
	ErrLocked = errors.New("account is locked")
	// ErrPending means the account exists but has not finished activation.
	// Only the local source has this state; a directory only has enabled.
	ErrPending = errors.New("account pending activation")
	// ErrExpired means the credential is valid but may no longer be used.
	ErrExpired = errors.New("password has expired")
	// ErrUnavailable means the source could not be reached or its state could
	// not be read. It is never reported as a credential failure.
	ErrUnavailable = errors.New("identity source unavailable")
)

// Code is the outcome of an authentication attempt, as the source reports it.
type Code int

const (
	// CodeOK means the credential matched.
	CodeOK Code = iota
	// CodeInvalid means the credential did not match, or the principal is
	// unknown to the source.
	CodeInvalid
	// CodeLocked means the account is locked out; the credential may be right.
	CodeLocked
	// CodeExpired means the credential has expired and must be changed.
	CodeExpired
)

// String renders the code for logs.
func (c Code) String() string {
	switch c {
	case CodeOK:
		return "ok"
	case CodeInvalid:
		return "invalid"
	case CodeLocked:
		return "locked"
	case CodeExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// AuthResult is what a source says about one password check.
type AuthResult struct {
	Code Code
	// MustChange is set when the credential matched but has to be replaced
	// before it may be used again.
	MustChange bool
	// LockedUntil is set when Code is CodeLocked and the lock expires.
	LockedUntil time.Time
}

// Group is one group an identity belongs to.
type Group struct {
	ID   string
	Name string
	SID  string
	DN   string
	// Depth is the shortest nesting distance; 1 is a direct membership.
	Depth int
}

// Identity is what a source knows about one principal. It is the projection
// the login paths authenticate; the SSO-owned state around it comes from
// Record (local) or from LocalUserState (directory).
type Identity struct {
	// ID is the stable subject: the directory objectGUID, or the local user
	// id. It becomes the OIDC `sub`.
	ID string
	DN string
	// Class is the directory object class ("user", "service"); empty for the
	// local source.
	Class string
	// Status is the account state. The directory only has enabled, which maps
	// to ACTIVE or LOCKED; the local source also has pending activation.
	Status domain.UserStatus
	// Login is the sAMAccountName, UPN the userPrincipalName and Email the
	// mail address; the local source fills Email only.
	Login     string
	UPN       string
	Email     string
	GivenName string
	Surname   string
	// Attributes are the directory attributes projected for claims, keyed by
	// attribute name.
	Attributes map[string][]string
	// Groups are the identity's transitive group memberships.
	Groups []Group
	// USN is the directory update sequence the projection was read at.
	USN int64

	// Record is the source's own user record when the source keeps one. The
	// local source sets it: its document is both the identity and the
	// SSO-owned state, so the facade returns it instead of merging a second
	// record. A directory source leaves it nil, because PiRectory owns the
	// record and ShadowSSO keeps only its own state in LocalUserState.
	Record *domain.User
}

// IdentitySource is where identity comes from. Resolve is the only call made
// before authentication; nothing here ever returns a password or a hash to a
// caller outside the source itself.
type IdentitySource interface {
	// Name is the configured source name (SourceLocal, SourceDirectory).
	Name() string

	// Resolve finds an identity behind a login before authentication. It is
	// the pre-authentication call: no password is checked here.
	Resolve(ctx context.Context, login string) (*Identity, error)

	// Authenticate verifies a password for an identity that Resolve or Get
	// returned. The local source compares against the hash in its own record;
	// the directory source calls credentials.VerifyPassword and never sees a
	// hash.
	Authenticate(ctx context.Context, ident *Identity, password string) (*AuthResult, error)

	// Get returns the current projection for an id.
	Get(ctx context.Context, id string) (*Identity, error)

	// Memberships is transitive by default when transitive is true.
	Memberships(ctx context.Context, id string, transitive bool) ([]Group, error)
}

// LocalUserState is the SSO-owned record for an identity: MFA methods,
// required actions, local roles, WebAuthn devices, last login. It is keyed by
// the identity id, which for a directory identity is the objectGUID. It is
// nil when the source keeps that record itself, which is what the local
// source does.
type LocalUserState interface {
	// Get returns the state record, or domain.ErrUserNotFound when the
	// identity has never signed in here.
	Get(ctx context.Context, id string) (*domain.User, error)
	// Ensure creates the state record when it does not exist yet.
	Ensure(ctx context.Context, user *domain.User) error
}

// Verifier is the part of Service the login paths depend on. Keeping it a
// small interface lets them be tested without a directory.
type Verifier interface {
	// Verify resolves a login and checks its password. The user is returned
	// whenever the identity was found, even when err is non-nil, so a caller
	// can audit with the account id.
	Verify(ctx context.Context, login, password string) (*domain.User, error)
}

// PasswordChanger is implemented by a source that owns passwords and can
// change them. It is optional: the local source stores its own hashes and
// does not implement it.
type PasswordChanger interface {
	ChangePassword(ctx context.Context, id, oldPassword, newPassword string) error
	CompleteForcedChange(ctx context.Context, id, newPassword string) error
}
