package openidv2_1

import (
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
)

func TestUserHasMFA(t *testing.T) {
	tests := []struct {
		name string
		user *domain.User
		want bool
	}{
		{name: "nil user", user: nil, want: false},
		{name: "no MFA", user: &domain.User{}, want: false},
		{name: "TOTP enabled", user: &domain.User{IsTwoFactorEnabled: true}, want: true},
		{name: "email MFA enabled", user: &domain.User{EmailMFAEnabled: true}, want: true},
		{name: "push MFA enabled", user: &domain.User{PushMFAEnabled: true}, want: true},
		{
			name: "verified method",
			user: &domain.User{MfaMethods: []domain.MfaMethod{{Verified: true}}},
			want: true,
		},
		{
			name: "unverified method",
			user: &domain.User{MfaMethods: []domain.MfaMethod{{Verified: false}}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, userHasMFA(tt.user))
		})
	}
}
