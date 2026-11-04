package services

import (
	"context"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expiryFakeRepo struct {
	domain.TokenRepository
	tokens []*domain.Token
	marked []string
}

func (f *expiryFakeRepo) ListUnauditedExpired(_ context.Context, _ time.Time, _ int) ([]*domain.Token, error) {
	return f.tokens, nil
}

func (f *expiryFakeRepo) MarkExpiryAudited(_ context.Context, ids []string) error {
	f.marked = append(f.marked, ids...)
	return nil
}

func (f *expiryFakeRepo) ListByUserID(context.Context, domain.TokenFilter, int, int) ([]*domain.Token, error) {
	return nil, nil
}

func (f *expiryFakeRepo) CountByUserID(context.Context, domain.TokenFilter) (int64, error) {
	return 0, nil
}

func (f *expiryFakeRepo) GetTokenByID(context.Context, string) (*domain.Token, error) {
	return nil, nil
}

func TestTokenExpirySweeper_SweepOnce(t *testing.T) {
	repo := &expiryFakeRepo{tokens: []*domain.Token{{
		ID:        "jti-expired",
		UserID:    "u1",
		ClientID:  "app",
		SessionID: "s1",
		TokenType: "access_token",
		ExpiresAt: time.Now().Add(-time.Minute),
	}}}
	sweeper := NewTokenExpirySweeper(repo)
	require.NotNil(t, sweeper)

	sweeper.SweepOnce(context.Background())
	assert.Equal(t, []string{"jti-expired"}, repo.marked)
}

func TestNewTokenExpirySweeper_UnsupportedStore(t *testing.T) {
	// A store that only implements issuing/validation has no query surface.
	assert.Nil(t, NewTokenExpirySweeper(nil))
}
