package services

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRealmSettingsRepo struct {
	settings *domain.RealmSettings
	err      error
}

func (f *fakeRealmSettingsRepo) GetRealmSettings(context.Context) (*domain.RealmSettings, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.settings == nil {
		f.settings = &domain.RealmSettings{}
	}
	return f.settings, nil
}

func (f *fakeRealmSettingsRepo) UpdateRealmSettings(_ context.Context, settings *domain.RealmSettings) error {
	if f.err != nil {
		return f.err
	}
	f.settings = settings
	return nil
}

func TestResolveOIDCDiscoveryMetadata_Precedence(t *testing.T) {
	cfg := &sssoapi.OpenIDProviderConfig{
		Issuer: "https://sso.example.com",
		ClaimsConfig: sssoapi.ClaimsConfig{
			SupportedScopes: []string{"openid", "profile"},
			SupportedClaims: []string{"sub", "email"},
		},
		TokenConfig: sssoapi.TokenConfig{
			SupportedTokenEndpointAuth: []string{"client_secret_post"},
			SupportedResponseTypes:     []string{"code"},
			SupportedResponseModes:     []string{"query"},
		},
	}

	// No overrides: static config wins over built-in defaults.
	meta := ResolveOIDCDiscoveryMetadata(nil, cfg, false)
	assert.Equal(t, []string{"openid", "profile"}, meta.ScopesSupported)
	assert.Equal(t, []string{"sub", "email"}, meta.ClaimsSupported)
	assert.Equal(t, []string{"client_secret_post"}, meta.TokenEndpointAuthMethodsSupported)
	assert.Equal(t, []string{"code"}, meta.ResponseTypesSupported)
	assert.Equal(t, []string{"query"}, meta.ResponseModesSupported)

	// Realm settings win over static config; empty lists fall through.
	settings := &domain.RealmSettings{
		ScopesSupported: []string{"openid", "custom"},
	}
	meta = ResolveOIDCDiscoveryMetadata(settings, cfg, false)
	assert.Equal(t, []string{"openid", "custom"}, meta.ScopesSupported)
	assert.Equal(t, []string{"sub", "email"}, meta.ClaimsSupported)

	// JARM appends jwt exactly once.
	meta = ResolveOIDCDiscoveryMetadata(nil, cfg, true)
	assert.Equal(t, []string{"query", "jwt"}, meta.ResponseModesSupported)
	settings.ResponseModesSupported = []string{"query", "jwt"}
	meta = ResolveOIDCDiscoveryMetadata(settings, cfg, true)
	assert.Equal(t, []string{"query", "jwt"}, meta.ResponseModesSupported)

	// JARM configured but unavailable: jwt must be filtered out.
	cfg.TokenConfig.SupportedResponseModes = []string{"query", "jwt"}
	meta = ResolveOIDCDiscoveryMetadata(nil, cfg, false)
	assert.Equal(t, []string{"query"}, meta.ResponseModesSupported)

	// No config at all: built-in defaults.
	meta = ResolveOIDCDiscoveryMetadata(nil, nil, false)
	assert.Equal(t, sssoapi.DefaultScopesSupported, meta.ScopesSupported)
	assert.Equal(t, sssoapi.DefaultClaimsSupported, meta.ClaimsSupported)
	assert.Equal(t, []string{"code"}, meta.ResponseTypesSupported)
}

func TestOIDCConfigurationService_GetUsesDefaults(t *testing.T) {
	repo := &fakeRealmSettingsRepo{}
	server := NewOIDCConfigurationServer(repo, &sssoapi.OpenIDProviderConfig{Issuer: "https://sso.example.com"}, false)

	resp, err := server.GetOIDCConfiguration(context.Background(), connect.NewRequest(&ssov1.GetOIDCConfigurationRequest{}))
	require.NoError(t, err)
	assert.Equal(t, "https://sso.example.com", resp.Msg.Configuration.Issuer)
	assert.Equal(t, sssoapi.DefaultScopesSupported, resp.Msg.Configuration.ScopesSupported)
	assert.Equal(t, sssoapi.DefaultClaimsSupported, resp.Msg.Configuration.ClaimsSupported)
}

func TestOIDCConfigurationService_UpdateAndReset(t *testing.T) {
	repo := &fakeRealmSettingsRepo{}
	server := NewOIDCConfigurationServer(repo, &sssoapi.OpenIDProviderConfig{Issuer: "https://sso.example.com"}, false)

	resp, err := server.UpdateOIDCConfiguration(context.Background(), connect.NewRequest(&ssov1.UpdateOIDCConfigurationRequest{
		ScopesSupported:                   &ssov1.StringList{Values: []string{"openid", "profile", "custom", "custom", ""}},
		ClaimsSupported:                   &ssov1.StringList{Values: []string{"sub", "tenant_id"}},
		ResponseModesSupported:            &ssov1.StringList{Values: []string{"query", "form_post"}},
		ResponseTypesSupported:            &ssov1.StringList{Values: []string{"code"}},
		TokenEndpointAuthMethodsSupported: &ssov1.StringList{Values: []string{"client_secret_post"}},
	}))
	require.NoError(t, err)

	// Lists are trimmed and de-duplicated before persisting.
	assert.Equal(t, []string{"openid", "profile", "custom"}, repo.settings.ScopesSupported)
	assert.Equal(t, []string{"sub", "tenant_id"}, repo.settings.ClaimsSupported)
	assert.Equal(t, []string{"query", "form_post"}, resp.Msg.Configuration.ResponseModesSupported)
	assert.Equal(t, []string{"client_secret_post"}, resp.Msg.Configuration.TokenEndpointAuthMethodsSupported)

	getResp, err := server.GetOIDCConfiguration(context.Background(), connect.NewRequest(&ssov1.GetOIDCConfigurationRequest{}))
	require.NoError(t, err)
	assert.Equal(t, []string{"openid", "profile", "custom"}, getResp.Msg.Configuration.ScopesSupported)
	assert.Equal(t, []string{"sub", "tenant_id"}, getResp.Msg.Configuration.ClaimsSupported)

	// An empty list clears the override and falls back to the default.
	reset, err := server.UpdateOIDCConfiguration(context.Background(), connect.NewRequest(&ssov1.UpdateOIDCConfigurationRequest{
		ScopesSupported: &ssov1.StringList{},
	}))
	require.NoError(t, err)
	assert.Equal(t, sssoapi.DefaultScopesSupported, reset.Msg.Configuration.ScopesSupported)
	assert.Nil(t, repo.settings.ScopesSupported)
	assert.Equal(t, []string{"sub", "tenant_id"}, repo.settings.ClaimsSupported, "other overrides are preserved")
}

func TestOIDCConfigurationService_UpdateRequiresAField(t *testing.T) {
	server := NewOIDCConfigurationServer(&fakeRealmSettingsRepo{}, &sssoapi.OpenIDProviderConfig{}, false)
	_, err := server.UpdateOIDCConfiguration(context.Background(), connect.NewRequest(&ssov1.UpdateOIDCConfigurationRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestOIDCConfigurationService_RepositoryError(t *testing.T) {
	repo := &fakeRealmSettingsRepo{err: errors.New("mongo down")}
	server := NewOIDCConfigurationServer(repo, &sssoapi.OpenIDProviderConfig{}, false)

	_, err := server.GetOIDCConfiguration(context.Background(), connect.NewRequest(&ssov1.GetOIDCConfigurationRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}
