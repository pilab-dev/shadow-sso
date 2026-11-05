package services_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type memDeviceRepo struct {
	mu sync.Mutex
	m  map[string]*domain.DeviceCode
}

func (r *memDeviceRepo) SaveDeviceAuth(_ context.Context, a *domain.DeviceCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := *a
	r.m[a.DeviceCode] = &c
	return nil
}
func (r *memDeviceRepo) GetDeviceAuthByDeviceCode(_ context.Context, id string) (*domain.DeviceCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.m[id]; ok {
		c := *a
		return &c, nil
	}
	return nil, domain.ErrDeviceCodeNotFound
}
func (r *memDeviceRepo) GetDeviceAuthByUserCode(_ context.Context, uc string) (*domain.DeviceCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.m {
		if a.UserCode == uc {
			c := *a
			return &c, nil
		}
	}
	return nil, domain.ErrUserCodeNotFound
}
func (r *memDeviceRepo) ApproveDeviceAuth(_ context.Context, uc, uid string) (*domain.DeviceCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.m {
		if a.UserCode == uc {
			a.Status, a.UserID = domain.DeviceCodeStatusAuthorized, uid
			c := *a
			return &c, nil
		}
	}
	return nil, domain.ErrUserCodeNotFound
}
func (r *memDeviceRepo) UpdateDeviceAuthStatus(_ context.Context, id string, s domain.DeviceCodeStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[id].Status = s
	return nil
}
func (r *memDeviceRepo) UpdateDeviceAuthLastPolledAt(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[id].LastPolledAt = time.Now()
	return nil
}
func (r *memDeviceRepo) DeleteExpiredDeviceAuths(context.Context) error { return nil }

func newCIBAFixture(t *testing.T) (services.CIBAService, services.OAuthService, *domain.Client, *mock_domain.MockTokenServiceInterface) {
	ctrl := gomock.NewController(t)
	userRepo := mock_domain.NewMockUserRepository(ctrl)
	userRepo.EXPECT().GetUserByEmail(gomock.Any(), "alice@example.com").Return(&domain.User{ID: "u1", Status: domain.UserStatusActive}, nil).AnyTimes()
	userRepo.EXPECT().GetUserByEmail(gomock.Any(), gomock.Any()).Return(nil, domain.ErrUserNotFound).AnyTimes()
	userRepo.EXPECT().GetUserByID(gomock.Any(), gomock.Any()).Return(nil, domain.ErrUserNotFound).AnyTimes()
	ts := mock_domain.NewMockTokenServiceInterface(ctrl)
	svc := services.NewOAuthService(
		mock_domain.NewMockTokenRepository(ctrl), mock_domain.NewMockAuthorizationCodeRepository(ctrl),
		&memDeviceRepo{m: map[string]*domain.DeviceCode{}}, mock_domain.NewMockClientRepository(ctrl),
		userRepo, mock_domain.NewMockSessionRepository(ctrl), ts, "iss")
	cli := &domain.Client{ID: "c1", AllowedScopes: []string{"openid", "profile"}}
	return svc, svc, cli, ts
}

func TestCIBA_ApproveThenRedeemOnce(t *testing.T) {
	ciba, _, cli, ts := newCIBAFixture(t)
	ctx := context.Background()
	res, err := ciba.InitiateBackchannelAuth(ctx, cli, "alice@example.com", "openid", "code 42")
	require.NoError(t, err)

	_, err = ciba.IssueTokenForBackchannelAuth(ctx, res.AuthReqID, "c1")
	require.ErrorIs(t, err, domain.ErrAuthorizationPending)
	_, err = ciba.IssueTokenForBackchannelAuth(ctx, res.AuthReqID, "c1")
	require.ErrorIs(t, err, domain.ErrSlowDown)

	require.ErrorIs(t, ciba.ResolveBackchannelAuth(ctx, res.AuthReqID, "u2", true), domain.ErrDeviceCodeNotFound)
	require.NoError(t, ciba.ResolveBackchannelAuth(ctx, res.AuthReqID, "u1", true))

	_, err = ciba.IssueTokenForBackchannelAuth(ctx, res.AuthReqID, "other")
	require.Error(t, err)

	ts.EXPECT().GenerateTokenPair(gomock.Any(), "c1", "u1", "openid", gomock.Any(), gomock.Any()).Return(&api.TokenResponse{AccessToken: "at"}, nil).Times(1)
	tok, err := ciba.IssueTokenForBackchannelAuth(ctx, res.AuthReqID, "c1")
	require.NoError(t, err)
	require.Equal(t, "at", tok.AccessToken)

	_, err = ciba.IssueTokenForBackchannelAuth(ctx, res.AuthReqID, "c1")
	require.Error(t, err)
}

func TestCIBA_DenyAndValidation(t *testing.T) {
	ciba, oauth, cli, _ := newCIBAFixture(t)
	ctx := context.Background()

	_, err := ciba.InitiateBackchannelAuth(ctx, cli, "nobody@example.com", "openid", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.UnknownUserID)
	_, err = ciba.InitiateBackchannelAuth(ctx, cli, "alice@example.com", "profile", "")
	require.Error(t, err)

	res, err := ciba.InitiateBackchannelAuth(ctx, cli, "alice@example.com", "openid", "")
	require.NoError(t, err)

	// The device user-code page must not be able to approve a CIBA request.
	got, _, _ := ciba.GetBackchannelAuth(ctx, res.AuthReqID)
	_, err = oauth.VerifyUserCode(ctx, got.UserCode, "u1")
	require.Error(t, err)

	require.NoError(t, ciba.ResolveBackchannelAuth(ctx, res.AuthReqID, "u1", false))
	_, err = ciba.IssueTokenForBackchannelAuth(ctx, res.AuthReqID, "c1")
	require.ErrorIs(t, err, domain.ErrDeviceFlowAccessDenied)
}
