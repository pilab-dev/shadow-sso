package domain

import (
	"context"
	"errors"
	"strings"
)

// PasswordPolicyError carries the policy violations the directory reported
// for a rejected new password.
type PasswordPolicyError struct {
	Violations []string
}

func (e *PasswordPolicyError) Error() string {
	return "password policy: " + strings.Join(e.Violations, "; ")
}

// ErrIncorrectPassword means the current password given for a change was wrong.
var ErrIncorrectPassword = errors.New("the current password is incorrect")

// ErrPasswordChangeNotAllowed means the directory refused to set the password
// because the account is not waiting for a forced change.
var ErrPasswordChangeNotAllowed = errors.New("the password cannot be changed here")

// DirectoryPasswords changes the password of a directory user in the
// directory itself. The plaintext goes to the directory over its mTLS channel;
// it hashes, applies its policy and derives its protocol keys, and the SSO
// stores nothing.
type DirectoryPasswords interface {
	// ChangePassword is the voluntary change: the current password is verified.
	ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error
	// CompleteForcedChange finishes a "must change at next logon" change. The
	// directory accepts it only for an account flagged for it.
	CompleteForcedChange(ctx context.Context, userID, newPassword string) error
}
