package services

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/internal/browserpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestBrowserPolicyServer_GetAndCheck(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	repo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{
		BrowserPolicy: &domain.BrowserPolicy{
			Enabled:     true,
			Enforcement: "block",
			MinVersions: map[string]string{"chrome": "120"},
		},
	}, nil).AnyTimes()

	provider := browserpolicy.NewProvider(repo)
	server := NewBrowserPolicyServer(repo, provider)

	resp, err := server.GetBrowserPolicy(context.Background(), connect.NewRequest(&ssov1.GetBrowserPolicyRequest{}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.GetPolicy().GetEnabled())
	assert.Equal(t, "120", resp.Msg.GetPolicy().GetMinVersions()["chrome"])
	assert.Equal(t, "120", resp.Msg.GetDefaults()["chrome"])

	old := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/90.0.0.0 Safari/537.36"
	check, err := server.CheckBrowser(context.Background(), connect.NewRequest(&ssov1.CheckBrowserRequest{UserAgent: old}))
	require.NoError(t, err)
	assert.False(t, check.Msg.GetAllowed())
	assert.Equal(t, browserpolicy.ReasonOutdated, check.Msg.GetReason())
	assert.Equal(t, "120", check.Msg.GetRequiredVersion())
}

func TestBrowserPolicyServer_UpdateValidatesAndPersists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	settings := &domain.RealmSettings{ID: "master", Realm: "master"}
	repo.EXPECT().GetRealmSettings(gomock.Any()).Return(settings, nil)
	repo.EXPECT().UpdateRealmSettings(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, got *domain.RealmSettings) error {
			require.NotNil(t, got.BrowserPolicy)
			assert.True(t, got.BrowserPolicy.Enabled)
			assert.Equal(t, domain.BrowserPolicyEnforcementWarn, got.BrowserPolicy.Enforcement)
			assert.Equal(t, "126", got.BrowserPolicy.MinVersions["chrome"])
			assert.Equal(t, []string{"MyCorpUpdater/"}, got.BrowserPolicy.ExemptUserAgents)
			return nil
		})

	server := NewBrowserPolicyServer(repo, browserpolicy.NewProvider(repo))
	resp, err := server.UpdateBrowserPolicy(context.Background(), connect.NewRequest(&ssov1.UpdateBrowserPolicyRequest{
		Policy: &ssov1.BrowserPolicy{
			Enabled:          true,
			Enforcement:      "warn",
			BlockUnknown:     true,
			BlockBots:        true,
			MinVersions:      map[string]string{"chrome": "126"},
			ExemptUserAgents: []string{"MyCorpUpdater/"},
		},
	}))
	require.NoError(t, err)
	assert.Equal(t, "warn", resp.Msg.GetPolicy().GetEnforcement())
}

func TestBrowserPolicyServer_UpdateRejectsInvalidEnforcement(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	repo.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{ID: "master"}, nil)
	server := NewBrowserPolicyServer(repo, browserpolicy.NewProvider(repo))

	_, err := server.UpdateBrowserPolicy(context.Background(), connect.NewRequest(&ssov1.UpdateBrowserPolicyRequest{
		Policy: &ssov1.BrowserPolicy{Enabled: true, Enforcement: "explode"},
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestBrowserPolicyServer_Reset(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := mock_domain.NewMockRealmSettingsRepository(ctrl)
	settings := &domain.RealmSettings{ID: "master", BrowserPolicy: &domain.BrowserPolicy{Enabled: true}}
	repo.EXPECT().GetRealmSettings(gomock.Any()).Return(settings, nil)
	repo.EXPECT().UpdateRealmSettings(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, got *domain.RealmSettings) error {
			assert.Nil(t, got.BrowserPolicy)
			return nil
		})
	server := NewBrowserPolicyServer(repo, browserpolicy.NewProvider(repo))

	_, err := server.UpdateBrowserPolicy(context.Background(), connect.NewRequest(&ssov1.UpdateBrowserPolicyRequest{Reset_: true}))
	require.NoError(t, err)
}
