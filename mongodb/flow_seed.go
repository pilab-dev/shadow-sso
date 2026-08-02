package mongodb

import (
	"context"
	"fmt"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
)

// SeedDefaultBrowserFlow ensures the default "browser" authentication flow
// exists with password REQUIRED and OTP ALTERNATIVE executions. If the flow
// already exists the seed is a no-op (idempotent).
func SeedDefaultBrowserFlow(ctx context.Context, repo domain.AuthenticationFlowRepository) error {
	if repo == nil {
		return nil
	}

	existing, err := repo.GetFlowByAlias(ctx, "browser")
	if err == nil && existing != nil {
		return nil
	}

	now := time.Now().UTC()
	flow := &domain.AuthenticationFlow{
		ID:          NewID(),
		Alias:       "browser",
		DisplayName: "Browser Flow",
		BuiltIn:     true,
		TopLevel:    true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := repo.CreateFlow(ctx, flow); err != nil {
		return fmt.Errorf("failed to seed browser flow: %w", err)
	}

	if err := repo.UpsertExecution(ctx, &domain.AuthenticationExecution{
		FlowID:        flow.ID,
		Execution:     "basic-authentication",
		Authenticator: "password",
		Requirement:   "REQUIRED",
		Priority:      10,
	}); err != nil {
		return fmt.Errorf("failed to seed password execution: %w", err)
	}

	if err := repo.UpsertExecution(ctx, &domain.AuthenticationExecution{
		FlowID:        flow.ID,
		Execution:     "otp-form",
		Authenticator: "otp",
		Requirement:   "ALTERNATIVE",
		Priority:      20,
	}); err != nil {
		return fmt.Errorf("failed to seed OTP execution: %w", err)
	}

	return nil
}
