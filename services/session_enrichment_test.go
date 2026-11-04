package services

import (
	"context"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/internal/geo"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestEnrichSession_GeoIPRiskFlags(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	repo := mock_domain.NewMockSessionRepository(ctrl)
	repo.EXPECT().ListSessionsByUserID(gomock.Any(), "user-1", domain.SessionFilter{}).Return([]*domain.Session{
		{ID: "prior", IPCountry: "US", Browser: "chrome", OS: "macos", IPASN: "AS1"},
	}, nil)
	repo.EXPECT().StoreSessionEvent(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	now := time.Now()
	session := &domain.Session{
		ID:        "new",
		UserID:    "user-1",
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120",
		IPAddress: "1.2.3.4",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	enrichSession(context.Background(), session, geo.StaticResolver{Info: geo.GeoInfo{Country: "HU", ASN: "AS2"}}, repo, nil)
	require.Contains(t, session.RiskFlags, "new_country")
	require.Contains(t, session.RiskFlags, "new_asn")
	require.Equal(t, "HU", session.IPCountry)
}
