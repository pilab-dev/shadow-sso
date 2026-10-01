package authflow

import "github.com/pilab-dev/shadow-sso/domain"

// NextRequiredAction returns the first pending required action of user that
// supported reports as implemented, honouring domain.KnownRequiredActions order
// (e.g. a password change always precedes TOTP enrolment).
//
// Aliases that are pending but unsupported are returned in skipped so callers
// can log them; they never block the login (an unknown alias must not lock users
// out), whereas a supported one blocks authorization until completed.
func NextRequiredAction(user *domain.User, supported func(alias string) bool) (next string, skipped []string) {
	if user == nil {
		return "", nil
	}
	for _, alias := range domain.KnownRequiredActions {
		if !user.HasRequiredAction(alias) {
			continue
		}
		if supported != nil && supported(alias) {
			if next == "" {
				next = alias
			}
			continue
		}
		skipped = append(skipped, alias)
	}
	return next, skipped
}
