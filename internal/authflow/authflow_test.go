package authflow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/authflow"
)

// stubFlows is a test double for authflow.FlowResolver.
type stubFlows struct {
	flow  *domain.AuthenticationFlow
	execs []*domain.AuthenticationExecution
	err   error
}

func (s *stubFlows) GetFlowByAlias(_ context.Context, alias string) (*domain.AuthenticationFlow, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.flow == nil || s.flow.Alias != alias {
		return nil, errors.New("flow not found: " + alias)
	}
	return s.flow, nil
}

func (s *stubFlows) GetExecutions(_ context.Context, _ string) ([]*domain.AuthenticationExecution, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.execs, nil
}

// stubHasher is a test double for authflow.PasswordVerifier.
type stubHasher struct {
	err error
}

func (h *stubHasher) Verify(_, _ string) error { return h.err }

func exec(authenticator, requirement string, priority int) *domain.AuthenticationExecution {
	return &domain.AuthenticationExecution{
		Authenticator: authenticator,
		Requirement:   requirement,
		Priority:      priority,
	}
}

func browserFlow() *domain.AuthenticationFlow {
	return &domain.AuthenticationFlow{ID: "flow-1", Alias: authflow.DefaultFlowAlias}
}

// browserFlowExecs is the default seeded flow: password REQUIRED + OTP ALTERNATIVE.
func browserFlowExecs() []*domain.AuthenticationExecution {
	return []*domain.AuthenticationExecution{
		exec("password", "REQUIRED", 10),
		exec("otp", "ALTERNATIVE", 20),
	}
}

func userWithMFA() *domain.User {
	return &domain.User{ID: "user-1", Email: "mfa@example.com", PasswordHash: "hash", IsTwoFactorEnabled: true}
}

func userWithoutMFA() *domain.User {
	return &domain.User{ID: "user-2", Email: "plain@example.com", PasswordHash: "hash"}
}

// TestAuthenticate_OTPAlternativeSkippedWithoutMFA is acceptance (a): a flow
// with password REQUIRED + OTP ALTERNATIVE must skip the OTP step when the
// user has no MFA configured.
func TestAuthenticate_OTPAlternativeSkippedWithoutMFA(t *testing.T) {
	hasher := &stubHasher{}
	runner := authflow.NewRunner(&stubFlows{flow: browserFlow(), execs: browserFlowExecs()}, hasher)

	requiresMFA, err := runner.Authenticate(context.Background(), userWithoutMFA(), "secret")

	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if requiresMFA {
		t.Fatal("expected MFA to be skipped for a user without MFA configured")
	}
}

// TestAuthenticate_RequiresMFAWhenUserHasMFA is the counterpart: the same
// flow must require MFA when the user does have MFA configured.
func TestAuthenticate_RequiresMFAWhenUserHasMFA(t *testing.T) {
	hasher := &stubHasher{}
	runner := authflow.NewRunner(&stubFlows{flow: browserFlow(), execs: browserFlowExecs()}, hasher)

	requiresMFA, err := runner.Authenticate(context.Background(), userWithMFA(), "secret")

	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !requiresMFA {
		t.Fatal("expected MFA to be required for a user with MFA configured")
	}
}

// TestAuthenticate_WrongPasswordRejectedBeforeOTP is the QA failure scenario:
// a wrong password at the REQUIRED password execution is rejected before any
// MFA step is offered.
func TestAuthenticate_WrongPasswordRejectedBeforeOTP(t *testing.T) {
	hasher := &stubHasher{err: errors.New("password mismatch")}
	runner := authflow.NewRunner(&stubFlows{flow: browserFlow(), execs: browserFlowExecs()}, hasher)

	_, err := runner.Authenticate(context.Background(), userWithMFA(), "wrong-password")

	if err == nil {
		t.Fatal("expected password rejection error")
	}
}

// TestAuthenticate_DisabledExecutionSkipped is acceptance (b): a DISABLED
// execution must never be evaluated, even when the user has MFA configured.
func TestAuthenticate_DisabledExecutionSkipped(t *testing.T) {
	hasher := &stubHasher{}
	runner := authflow.NewRunner(&stubFlows{
		flow: browserFlow(),
		execs: []*domain.AuthenticationExecution{
			exec("password", "REQUIRED", 10),
			exec("otp", "DISABLED", 20),
		},
	}, hasher)

	requiresMFA, err := runner.Authenticate(context.Background(), userWithMFA(), "secret")

	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if requiresMFA {
		t.Fatal("expected DISABLED execution to be skipped even for an MFA user")
	}
}

// TestAuthenticate_AlternativeSatisfiedByOneOption is acceptance (c): an
// ALTERNATIVE group is satisfied when at least one of its options applies.
func TestAuthenticate_AlternativeSatisfiedByOneOption(t *testing.T) {
	hasher := &stubHasher{}
	runner := authflow.NewRunner(&stubFlows{
		flow: browserFlow(),
		execs: []*domain.AuthenticationExecution{
			exec("password", "REQUIRED", 10),
			exec("otp", "ALTERNATIVE", 20),
			exec("email-otp", "ALTERNATIVE", 30),
		},
	}, hasher)

	requiresMFA, err := runner.Authenticate(context.Background(), userWithMFA(), "secret")

	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !requiresMFA {
		t.Fatal("expected one applicable ALTERNATIVE option to satisfy the group")
	}
}

// TestAuthenticate_RequiredNonPasswordExecutionForcesMFA: a REQUIRED
// non-password execution forces an MFA challenge regardless of the user's
// configured methods.
func TestAuthenticate_RequiredNonPasswordExecutionForcesMFA(t *testing.T) {
	hasher := &stubHasher{}
	runner := authflow.NewRunner(&stubFlows{
		flow: browserFlow(),
		execs: []*domain.AuthenticationExecution{
			exec("password", "REQUIRED", 10),
			exec("push", "REQUIRED", 20),
		},
	}, hasher)

	requiresMFA, err := runner.Authenticate(context.Background(), userWithoutMFA(), "secret")

	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !requiresMFA {
		t.Fatal("expected REQUIRED non-password execution to force MFA")
	}
}

// TestAuthenticate_ExecutionsEvaluatedInPriorityOrder: execution ordering in
// the store must not affect the outcome (the runner sorts by Priority).
func TestAuthenticate_ExecutionsEvaluatedInPriorityOrder(t *testing.T) {
	hasher := &stubHasher{}
	runner := authflow.NewRunner(&stubFlows{
		flow: browserFlow(),
		execs: []*domain.AuthenticationExecution{
			exec("otp", "ALTERNATIVE", 20),
			exec("password", "REQUIRED", 10),
		},
	}, hasher)

	requiresMFA, err := runner.Authenticate(context.Background(), userWithMFA(), "secret")

	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !requiresMFA {
		t.Fatal("expected MFA to be required regardless of execution store order")
	}
}

// TestAuthenticate_NoFlowDataFallsBackToLegacy: without resolvable flow data
// the runner degrades to the legacy password -> MFA behavior so existing
// deployments keep working.
func TestAuthenticate_NoFlowDataFallsBackToLegacy(t *testing.T) {
	// No resolver at all.
	runner := authflow.NewRunner(nil, &stubHasher{})

	requiresMFA, err := runner.Authenticate(context.Background(), userWithMFA(), "secret")
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !requiresMFA {
		t.Fatal("expected legacy fallback to require MFA for an MFA user")
	}

	requiresMFA, err = runner.Authenticate(context.Background(), userWithoutMFA(), "secret")
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if requiresMFA {
		t.Fatal("expected legacy fallback to skip MFA for a user without MFA")
	}

	// Wrong password in the fallback is still rejected. Use a separate runner
	// whose hasher always rejects — the original runner's hasher accepts all.
	wrongPwRunner := authflow.NewRunner(nil, &stubHasher{err: errors.New("password mismatch")})
	_, err = wrongPwRunner.Authenticate(context.Background(), userWithMFA(), "wrong")
	if err == nil {
		t.Fatal("expected password rejection error in legacy fallback")
	}
}

// TestAuthenticate_FlowResolutionErrorFallsBack: a flow store error degrades
// to the legacy behavior instead of failing the login outright.
func TestAuthenticate_FlowResolutionErrorFallsBack(t *testing.T) {
	runner := authflow.NewRunner(&stubFlows{err: errors.New("db unavailable")}, &stubHasher{})

	requiresMFA, err := runner.Authenticate(context.Background(), userWithMFA(), "secret")

	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !requiresMFA {
		t.Fatal("expected legacy fallback on flow resolution error")
	}
}

// TestUserHasMFA covers the MFA detection logic moved out of the login handler.
func TestUserHasMFA(t *testing.T) {
	tests := []struct {
		name string
		user *domain.User
		want bool
	}{
		{"nil user", nil, false},
		{"no mfa", &domain.User{}, false},
		{"is two factor enabled", &domain.User{IsTwoFactorEnabled: true}, true},
		{"email mfa enabled", &domain.User{EmailMFAEnabled: true}, true},
		{"push mfa enabled", &domain.User{PushMFAEnabled: true}, true},
		{"verified method", &domain.User{MfaMethods: []domain.MfaMethod{{Verified: true}}}, true},
		{"unverified method", &domain.User{MfaMethods: []domain.MfaMethod{{Verified: false}}}, false},
	}

	runner := authflow.NewRunner(nil, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runner.UserHasMFA(tt.user); got != tt.want {
				t.Errorf("UserHasMFA() = %v, want %v", got, tt.want)
			}
		})
	}
}
