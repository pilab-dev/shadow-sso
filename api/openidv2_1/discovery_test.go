package openidv2_1_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/stretchr/testify/require"
)

// discoveryGoldenPath is the checked-in expected discovery document.
const discoveryGoldenPath = "testdata/openid_configuration.golden.json"

// newDiscoveryAPI builds an OAuth2API with every optional dependency the
// discovery handler inspects: an RSA signer (enables JARM advertisement) and
// a back-channel logout notifier.
func newDiscoveryAPI(t *testing.T, cfg *sssoapi.OpenIDProviderConfig, withRSASigner bool, settings *domain.RealmSettings) *sssogin.OAuth2API {
	t.Helper()

	var signer *services.TokenSigner
	if withRSASigner {
		keyPath := filepath.Join(t.TempDir(), "signing-key.pem")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		require.NoError(t, os.WriteFile(keyPath, pemBytes, 0o600))

		signer = services.NewTokenSigner()
		require.NoError(t, signer.AddRSASigner(keyPath))
	}

	var settingsRepo domain.RealmSettingsRepository
	if settings != nil {
		settingsRepo = &fakeRealmSettingsRepository{settings: settings}
	}
	api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		Config:                    cfg,
		TokenSigner:               signer,
		RealmSettingsRepo:         settingsRepo,
		BackchannelLogoutNotifier: newFakeLogoutNotifier(),
	})
	require.NotNil(t, api)
	return api
}

func fetchDiscovery(t *testing.T, api *sssogin.OAuth2API) map[string]any {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/.well-known/openid-configuration", api.OpenIDConfigurationHandler)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "sso.example.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	return doc
}

func fullDiscoveryConfig() *sssoapi.OpenIDProviderConfig {
	return &sssoapi.OpenIDProviderConfig{
		Issuer: "https://sso.example.com",
		EnabledEndpoints: sssoapi.EndpointConfig{
			Authorization:       true,
			Token:               true,
			UserInfo:            true,
			JWKS:                true,
			Registration:        true,
			Revocation:          true,
			Introspection:       true,
			EndSession:          true,
			DeviceAuthorization: true,
		},
		EnabledGrantTypes: sssoapi.GrantTypesConfig{
			AuthorizationCode: true,
			ClientCredentials: true,
			RefreshToken:      true,
			Password:          true,
			DeviceCode:        true,
		},
		SecurityConfig: sssoapi.SecurityConfig{
			AllowedSigningAlgs: []string{"RS256"},
		},
		TokenConfig: sssoapi.TokenConfig{
			AccessTokenFormat:      "jwt",
			SupportedResponseTypes: []string{"code"},
		},
		PKCEConfig: sssoapi.PKCEConfig{
			Enabled:          true,
			SupportedMethods: []string{"S256"},
		},
	}
}

// TestOpenIDConfiguration_Golden pins the complete discovery document. Update
// it with UPDATE_GOLDEN=1 go test ./api/openidv2_1 -run TestOpenIDConfiguration_Golden
// after intentionally changing the metadata.
func TestOpenIDConfiguration_Golden(t *testing.T) {
	doc := fetchDiscovery(t, newDiscoveryAPI(t, fullDiscoveryConfig(), true, nil))

	got, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(discoveryGoldenPath), 0o755))
		require.NoError(t, os.WriteFile(discoveryGoldenPath, got, 0o600))
		t.Logf("updated %s", discoveryGoldenPath)
		return
	}

	want, err := os.ReadFile(discoveryGoldenPath)
	require.NoError(t, err, "run with UPDATE_GOLDEN=1 to create the golden file")
	require.JSONEq(t, string(want), string(got))
}

// TestOpenIDConfiguration_IsTruthful guards against re-introducing metadata
// for features the server does not implement.
func TestOpenIDConfiguration_IsTruthful(t *testing.T) {
	doc := fetchDiscovery(t, newDiscoveryAPI(t, fullDiscoveryConfig(), true, nil))

	require.Equal(t, []any{"public"}, doc["subject_types_supported"], "pairwise is not implemented")
	require.Equal(t, false, doc["request_parameter_supported"], "request objects are not parsed")
	require.Equal(t, true, doc["authorization_response_iss_parameter_supported"], "iss is sent on success and error redirects")
	require.Equal(t, false, doc["tls_client_certificate_bound_access_tokens"])
	require.Contains(t, doc["scopes_supported"], "openid")
	require.Contains(t, doc["claims_supported"], "email")
	require.NotEmpty(t, doc["token_endpoint_auth_methods_supported"])
	require.NotContains(t, doc["token_endpoint_auth_methods_supported"], "client_secret_basic",
		"basic auth is not parsed at the token endpoint")
	require.NotContains(t, doc, "userinfo_signing_alg_values_supported",
		"UserInfo responses are plain JSON")
	require.NotContains(t, doc, "request_object_signing_alg_values_supported",
		"request objects are not supported")
	require.Equal(t, "https://sso.example.com/oauth2/par", doc["pushed_authorization_request_endpoint"])
	require.Equal(t, true, doc["backchannel_logout_supported"])
	require.Equal(t, true, doc["backchannel_logout_session_supported"])
	require.Contains(t, doc["response_modes_supported"], "jwt", "JARM is available with an RSA signer")
}

// TestOpenIDConfiguration_DefaultsWhenUnconfigured ensures the document never
// ships empty required arrays even when the caller builds a bare config.
func TestOpenIDConfiguration_DefaultsWhenUnconfigured(t *testing.T) {
	cfg := &sssoapi.OpenIDProviderConfig{Issuer: "https://sso.example.com"}
	doc := fetchDiscovery(t, newDiscoveryAPI(t, cfg, false, nil))

	require.NotEmpty(t, doc["scopes_supported"])
	require.NotEmpty(t, doc["claims_supported"])
	require.NotEmpty(t, doc["token_endpoint_auth_methods_supported"])
	require.NotContains(t, doc["response_modes_supported"], "jwt",
		"JARM must not be advertised when no RSA signer is configured")
}

// fakeRealmSettingsRepository is a minimal read/write settings store for the
// discovery overlay test.
type fakeRealmSettingsRepository struct {
	settings *domain.RealmSettings
}

func (f *fakeRealmSettingsRepository) GetRealmSettings(context.Context) (*domain.RealmSettings, error) {
	return f.settings, nil
}

func (f *fakeRealmSettingsRepository) UpdateRealmSettings(_ context.Context, settings *domain.RealmSettings) error {
	f.settings = settings
	return nil
}

// TestOpenIDConfiguration_RealmSettingsOverride verifies that metadata managed
// over OIDCConfigurationService (stored in realm settings) is reflected by the
// live discovery endpoint without a restart.
func TestOpenIDConfiguration_RealmSettingsOverride(t *testing.T) {
	settings := &domain.RealmSettings{
		ScopesSupported:          []string{"openid", "tenant"},
		ClaimsSupported:          []string{"sub", "tenant_id"},
		TokenEndpointAuthMethods: []string{"client_secret_post"},
		ResponseTypesSupported:   []string{"code"},
		ResponseModesSupported:   []string{"form_post"},
	}
	doc := fetchDiscovery(t, newDiscoveryAPI(t, fullDiscoveryConfig(), true, settings))

	require.Equal(t, []any{"openid", "tenant"}, doc["scopes_supported"])
	require.Equal(t, []any{"sub", "tenant_id"}, doc["claims_supported"])
	require.Equal(t, []any{"client_secret_post"}, doc["token_endpoint_auth_methods_supported"])
	require.Equal(t, []any{"form_post", "jwt"}, doc["response_modes_supported"],
		"JARM is appended to the configured modes when an RSA signer exists")
}
