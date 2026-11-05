package domain_test

import (
	"context"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAuthorizationDetails(t *testing.T) {
	_, types, err := domain.ParseAuthorizationDetails(`[{"type":"a"},{"type":"b","x":1}]`)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, types)

	for _, bad := range []string{``, `{}`, `[]`, `[{"x":1}]`, `["a"]`, `[{"type":""}]`} {
		_, _, err := domain.ParseAuthorizationDetails(bad)
		assert.Error(t, err, bad)
	}
}

func TestAuthorizationDetailsContext(t *testing.T) {
	assert.Empty(t, domain.AuthorizationDetailsFromContext(context.Background()))
	ctx := domain.ContextWithAuthorizationDetails(context.Background(), `[{"type":"a"}]`)
	assert.Equal(t, `[{"type":"a"}]`, domain.AuthorizationDetailsFromContext(ctx))
}
