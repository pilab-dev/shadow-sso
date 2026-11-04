package services

import (
	"context"
	"fmt"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/rs/zerolog/log"
)

// TokenExpirySweeper emits one TokenExpired audit event per token when it
// crosses its expires_at boundary. It does not revoke or delete anything;
// expired tokens are already rejected by validation and cleanup.
type TokenExpirySweeper struct {
	repo     domain.TokenQueryRepository
	interval time.Duration
	batch    int
}

// NewTokenExpirySweeper returns a sweeper for a query-capable token store.
// A nil query repo (for example, a DTS-backed store) yields nil.
func NewTokenExpirySweeper(tokenRepo domain.TokenRepository) *TokenExpirySweeper {
	query, ok := tokenRepo.(domain.TokenQueryRepository)
	if !ok {
		return nil
	}
	return &TokenExpirySweeper{repo: query, interval: time.Minute, batch: 200}
}

// Run sweeps immediately and then on the configured interval until ctx is
// canceled. It is safe to call in a goroutine.
func (s *TokenExpirySweeper) Run(ctx context.Context) {
	if s == nil || s.repo == nil {
		return
	}
	s.sweep(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep(ctx)
		}
	}
}

// SweepOnce is exposed for tests and for a one-shot administrative job.
func (s *TokenExpirySweeper) SweepOnce(ctx context.Context) {
	if s == nil || s.repo == nil {
		return
	}
	s.sweep(ctx)
}

func (s *TokenExpirySweeper) sweep(ctx context.Context) {
	now := time.Now().UTC()
	tokens, err := s.repo.ListUnauditedExpired(ctx, now, s.batch)
	if err != nil {
		log.Warn().Err(err).Msg("Token expiry sweep failed")
		return
	}
	if len(tokens) == 0 {
		return
	}

	ids := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if t == nil {
			continue
		}
		ids = append(ids, t.ID)
		details := fmt.Sprintf("type=%s client=%s session=%s expired_at=%s",
			t.TokenType, t.ClientID, t.SessionID, t.ExpiresAt.UTC().Format(time.RFC3339))
		audit.Log("TokenService", "TokenExpired", t.UserID, t.ID, details, true, nil)
	}
	if err := s.repo.MarkExpiryAudited(ctx, ids); err != nil {
		log.Warn().Err(err).Int("count", len(ids)).Msg("Failed to mark expired tokens as audited")
	}
}

// StartTokenExpirySweeper runs the sweeper for the lifetime of the process.
func StartTokenExpirySweeper(tokenRepo domain.TokenRepository) {
	sweeper := NewTokenExpirySweeper(tokenRepo)
	if sweeper == nil {
		return
	}
	go sweeper.Run(context.Background())
}
