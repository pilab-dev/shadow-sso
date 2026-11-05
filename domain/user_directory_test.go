package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetPasswordHashRefusesDirectoryUsers(t *testing.T) {
	local := &User{Source: SourceLocal}
	assert.NoError(t, local.SetPasswordHash("h"))
	assert.Equal(t, "h", local.PasswordHash)

	legacy := &User{} // records from before sources existed are local
	assert.NoError(t, legacy.SetPasswordHash("h"))

	dir := &User{Source: SourceDirectory}
	assert.ErrorIs(t, dir.SetPasswordHash("h"), ErrDirectoryManaged)
	assert.Empty(t, dir.PasswordHash, "nothing is stored")
}
