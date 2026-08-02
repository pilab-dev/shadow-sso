package mongodb_test

import (
	"context"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/mongodb"
)

type fakeFlowRepo struct {
	flows map[string]*domain.AuthenticationFlow
	execs map[string][]*domain.AuthenticationExecution
}

func newFakeFlowRepo() *fakeFlowRepo {
	return &fakeFlowRepo{
		flows: make(map[string]*domain.AuthenticationFlow),
		execs: make(map[string][]*domain.AuthenticationExecution),
	}
}

func (r *fakeFlowRepo) CreateFlow(_ context.Context, flow *domain.AuthenticationFlow) error {
	r.flows[flow.Alias] = flow
	return nil
}

func (r *fakeFlowRepo) GetFlowByID(_ context.Context, id string) (*domain.AuthenticationFlow, error) {
	for _, f := range r.flows {
		if f.ID == id {
			return f, nil
		}
	}
	return nil, nil
}

func (r *fakeFlowRepo) GetFlowByAlias(_ context.Context, alias string) (*domain.AuthenticationFlow, error) {
	f, ok := r.flows[alias]
	if !ok {
		return nil, nil
	}
	return f, nil
}

func (r *fakeFlowRepo) UpdateFlow(_ context.Context, flow *domain.AuthenticationFlow) error {
	r.flows[flow.Alias] = flow
	return nil
}

func (r *fakeFlowRepo) DeleteFlow(_ context.Context, id string) error {
	for alias, f := range r.flows {
		if f.ID == id {
			delete(r.flows, alias)
			return nil
		}
	}
	return nil
}

func (r *fakeFlowRepo) ListFlows(_ context.Context) ([]*domain.AuthenticationFlow, error) {
	var out []*domain.AuthenticationFlow
	for _, f := range r.flows {
		out = append(out, f)
	}
	return out, nil
}

func (r *fakeFlowRepo) UpsertExecution(_ context.Context, exec *domain.AuthenticationExecution) error {
	r.execs[exec.FlowID] = append(r.execs[exec.FlowID], exec)
	return nil
}

func (r *fakeFlowRepo) GetExecutions(_ context.Context, flowID string) ([]*domain.AuthenticationExecution, error) {
	return r.execs[flowID], nil
}

func (r *fakeFlowRepo) DeleteExecution(_ context.Context, id string) error {
	return nil
}

func TestSeedDefaultBrowserFlow_CreatesFlowAndExecutions(t *testing.T) {
	repo := newFakeFlowRepo()

	if err := mongodb.SeedDefaultBrowserFlow(context.Background(), repo); err != nil {
		t.Fatalf("SeedDefaultBrowserFlow returned error: %v", err)
	}

	flow, err := repo.GetFlowByAlias(context.Background(), "browser")
	if err != nil {
		t.Fatalf("GetFlowByAlias returned error: %v", err)
	}
	if flow == nil {
		t.Fatal("expected browser flow to be created")
	}
	if !flow.BuiltIn {
		t.Fatal("expected browser flow to be built-in")
	}
	if !flow.TopLevel {
		t.Fatal("expected browser flow to be top-level")
	}

	execs, err := repo.GetExecutions(context.Background(), flow.ID)
	if err != nil {
		t.Fatalf("GetExecutions returned error: %v", err)
	}
	if len(execs) != 2 {
		t.Fatalf("expected 2 executions, got %d", len(execs))
	}

	var hasPassword, hasOTP bool
	for _, ex := range execs {
		switch ex.Authenticator {
		case "password":
			hasPassword = true
			if ex.Requirement != "REQUIRED" {
				t.Errorf("password execution requirement = %q, want REQUIRED", ex.Requirement)
			}
		case "otp":
			hasOTP = true
			if ex.Requirement != "ALTERNATIVE" {
				t.Errorf("otp execution requirement = %q, want ALTERNATIVE", ex.Requirement)
			}
		}
	}
	if !hasPassword {
		t.Error("expected password execution")
	}
	if !hasOTP {
		t.Error("expected otp execution")
	}
}

func TestSeedDefaultBrowserFlow_Idempotent(t *testing.T) {
	repo := newFakeFlowRepo()

	if err := mongodb.SeedDefaultBrowserFlow(context.Background(), repo); err != nil {
		t.Fatalf("first seed returned error: %v", err)
	}
	if err := mongodb.SeedDefaultBrowserFlow(context.Background(), repo); err != nil {
		t.Fatalf("second seed returned error: %v", err)
	}

	flow, _ := repo.GetFlowByAlias(context.Background(), "browser")
	if flow == nil {
		t.Fatal("expected browser flow to exist after idempotent seed")
	}
}
