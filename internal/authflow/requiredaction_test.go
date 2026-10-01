package authflow

import (
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
)

func TestNextRequiredActionOrderAndSupport(t *testing.T) {
	all := func(string) bool { return true }
	u := &domain.User{RequiredActions: []string{domain.RequiredActionConfigureTOTP, domain.RequiredActionUpdatePassword}}

	next, skipped := NextRequiredAction(u, all)
	assert.Equal(t, domain.RequiredActionUpdatePassword, next, "password change precedes TOTP regardless of storage order")
	assert.Empty(t, skipped)

	onlyTOTP := func(a string) bool { return a == domain.RequiredActionConfigureTOTP }
	next, skipped = NextRequiredAction(u, onlyTOTP)
	assert.Equal(t, domain.RequiredActionConfigureTOTP, next)
	assert.Equal(t, []string{domain.RequiredActionUpdatePassword}, skipped)

	next, skipped = NextRequiredAction(u, nil)
	assert.Empty(t, next)
	assert.Len(t, skipped, 2)

	next, _ = NextRequiredAction(nil, all)
	assert.Empty(t, next)
	next, _ = NextRequiredAction(&domain.User{}, all)
	assert.Empty(t, next)
}

func TestUserRequiredActionHelpers(t *testing.T) {
	u := &domain.User{}
	u.AddRequiredAction(domain.RequiredActionVerifyEmail)
	u.AddRequiredAction(domain.RequiredActionVerifyEmail)
	assert.Equal(t, []string{domain.RequiredActionVerifyEmail}, u.RequiredActions)
	u.RemoveRequiredAction(domain.RequiredActionVerifyEmail)
	assert.Empty(t, u.RequiredActions)
	assert.True(t, domain.IsKnownRequiredAction(domain.RequiredActionTerms))
	assert.False(t, domain.IsKnownRequiredAction("NOPE"))
}

func TestFlowStateAuthenticated(t *testing.T) {
	f := &domain.LoginFlowState{UserID: "u1"}
	assert.True(t, f.Authenticated())
	f.Pending = domain.FlowPendingMFA
	assert.False(t, f.Authenticated())
	f.Pending = domain.FlowPendingActionPrefix + domain.RequiredActionUpdatePassword
	assert.False(t, f.Authenticated())
	assert.Equal(t, domain.RequiredActionUpdatePassword, f.PendingAction())
	assert.False(t, (&domain.LoginFlowState{}).Authenticated())
}
