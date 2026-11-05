package webauth

import pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"

// newEmailToken and hashEmailToken delegate to the shared implementation, which the GraphQL admin
// mutations (sendPasswordResetEmail, sendVerificationEmail) use as well so that links they send
// are redeemable by /reset-password and /verify-email.
func newEmailToken() (token, digest string, err error) { return pkgauth.NewEmailToken() }

func hashEmailToken(token string) string { return pkgauth.HashEmailToken(token) }
