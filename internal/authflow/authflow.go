// Package authflow evaluates Keycloak-style authentication flow/execution
// data in the login path. It resolves the executions of a named flow, honors
// the REQUIRED/ALTERNATIVE/DISABLED requirements, and dispatches
// authenticators to the existing services (password via a hasher, MFA via
// the user's configured methods).
package authflow

import (
	"context"
	"errors"
	"sort"

	"github.com/pilab-dev/shadow-sso/domain"
)

// Authenticator identifiers referenced by AuthenticationExecution.Authenticator.
const (
	// AuthenticatorPassword is the username/password form execution.
	AuthenticatorPassword = "password"
	// AuthenticatorOTP is the one-time-password (TOTP/HOTP/email/push/SMS) execution.
	AuthenticatorOTP = "otp"
)

// DefaultFlowAlias is the alias of the seeded top-level browser flow.
const DefaultFlowAlias = "browser"

// Execution requirement values. They mirror the string values persisted on
// domain.AuthenticationExecution.Requirement.
const (
	RequirementRequired    = "REQUIRED"
	RequirementAlternative = "ALTERNATIVE"
	RequirementDisabled    = "DISABLED"
)

// FlowResolver resolves the executions of a named authentication flow.
type FlowResolver interface {
	GetFlowByAlias(ctx context.Context, alias string) (*domain.AuthenticationFlow, error)
	GetExecutions(ctx context.Context, flowID string) ([]*domain.AuthenticationExecution, error)
}

// PasswordVerifier verifies a password against its stored hash.
type PasswordVerifier interface {
	Verify(hashedPassword, password string) error
}

// Runner evaluates authentication flow data for a login attempt.
type Runner struct {
	flows  FlowResolver
	hasher PasswordVerifier
}

// NewRunner returns a Runner. A nil flows resolver (or a resolver that yields
// no flow/executions) makes the runner degrade to the legacy password->MFA
// behavior so existing deployments keep working before a flow is seeded.
func NewRunner(flows FlowResolver, hasher PasswordVerifier) *Runner {
	return &Runner{flows: flows, hasher: hasher}
}

// Authenticate evaluates the configured browser flow for the given user and
// password and reports whether an MFA challenge is required.
//
// Executions are sorted by Priority and evaluated in order: DISABLED
// executions are skipped; a password execution (REQUIRED or ALTERNATIVE) is
// dispatched to the hasher; any other REQUIRED execution forces MFA; an
// ALTERNATIVE group is satisfied by a single applicable option and is skipped
// entirely when the user has no MFA configured.
//
// When no flow or executions resolve (nil resolver, unknown alias, empty
// execution list), the legacy password->MFA behavior applies.
func (r *Runner) Authenticate(ctx context.Context, user *domain.User, password string) (bool, error) {
	flow, execs, err := r.resolveFlow(ctx)
	if err != nil || flow == nil || len(execs) == 0 {
		if verr := r.verifyPassword(user, password); verr != nil {
			return false, verr
		}
		return r.UserHasMFA(user), nil
	}
	return r.evaluate(user, password, execs)
}

func (r *Runner) resolveFlow(ctx context.Context) (*domain.AuthenticationFlow, []*domain.AuthenticationExecution, error) {
	if r.flows == nil {
		return nil, nil, nil
	}
	flow, err := r.flows.GetFlowByAlias(ctx, DefaultFlowAlias)
	if err != nil {
		return nil, nil, err
	}
	if flow == nil {
		return nil, nil, nil
	}
	execs, err := r.flows.GetExecutions(ctx, flow.ID)
	if err != nil {
		return nil, nil, err
	}
	return flow, execs, nil
}

func (r *Runner) evaluate(user *domain.User, password string, execs []*domain.AuthenticationExecution) (bool, error) {
	sorted := make([]*domain.AuthenticationExecution, len(execs))
	copy(sorted, execs)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Priority < sorted[j].Priority })

	var (
		passwordRequired bool
		requiresMFA      bool
		alternatives     []*domain.AuthenticationExecution
	)

	for _, ex := range sorted {
		switch ex.Requirement {
		case RequirementDisabled:
			continue
		case RequirementAlternative:
			if ex.Authenticator == AuthenticatorPassword {
				passwordRequired = true
			} else {
				alternatives = append(alternatives, ex)
			}
		default:
			// REQUIRED and any unknown requirement fail closed: the execution
			// must be satisfied.
			if ex.Authenticator == AuthenticatorPassword {
				passwordRequired = true
			} else {
				requiresMFA = true
			}
		}
	}

	if passwordRequired {
		if err := r.verifyPassword(user, password); err != nil {
			return false, err
		}
	}

	// An ALTERNATIVE group is satisfied by any single applicable option; when
	// the user has no MFA configured none of the options apply.
	if len(alternatives) > 0 && r.UserHasMFA(user) {
		requiresMFA = true
	}
	return requiresMFA, nil
}

func (r *Runner) verifyPassword(user *domain.User, password string) error {
	if r.hasher == nil {
		return nil
	}
	if user == nil {
		return errors.New("authflow: cannot verify password for nil user")
	}
	return r.hasher.Verify(user.PasswordHash, password)
}

// UserHasMFA reports whether the user has any enabled or verified MFA method.
func (r *Runner) UserHasMFA(user *domain.User) bool {
	if user == nil {
		return false
	}
	if user.IsTwoFactorEnabled || user.EmailMFAEnabled || user.PushMFAEnabled {
		return true
	}
	for _, m := range user.MfaMethods {
		if m.Verified {
			return true
		}
	}
	return false
}
