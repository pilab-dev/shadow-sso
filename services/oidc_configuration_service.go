package services

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/codes"
)

const oidcConfigurationServiceTracerName = "oidc-configuration-service"

// OIDCDiscoveryMetadata is the effective metadata published by the discovery
// endpoint, after applying realm-settings overrides over the static provider
// configuration and built-in defaults.
type OIDCDiscoveryMetadata struct {
	Issuer                            string
	ScopesSupported                   []string
	ClaimsSupported                   []string
	TokenEndpointAuthMethodsSupported []string
	ResponseTypesSupported            []string
	ResponseModesSupported            []string
}

// ResolveOIDCDiscoveryMetadata applies the precedence realm settings > static
// provider config > built-in defaults. jarmAvailable appends the JARM "jwt"
// response mode when it is not configured explicitly.
func ResolveOIDCDiscoveryMetadata(settings *domain.RealmSettings, cfg *sssoapi.OpenIDProviderConfig, jarmAvailable bool) OIDCDiscoveryMetadata {
	meta := OIDCDiscoveryMetadata{}
	if cfg != nil {
		meta.Issuer = cfg.Issuer
		meta.ScopesSupported = cfg.ClaimsConfig.SupportedScopes
		meta.ClaimsSupported = cfg.ClaimsConfig.SupportedClaims
		meta.TokenEndpointAuthMethodsSupported = cfg.TokenConfig.SupportedTokenEndpointAuth
		meta.ResponseTypesSupported = cfg.TokenConfig.SupportedResponseTypes
		meta.ResponseModesSupported = cfg.TokenConfig.SupportedResponseModes
	}
	if settings != nil {
		meta.ScopesSupported = firstNonEmpty(settings.ScopesSupported, meta.ScopesSupported)
		meta.ClaimsSupported = firstNonEmpty(settings.ClaimsSupported, meta.ClaimsSupported)
		meta.TokenEndpointAuthMethodsSupported = firstNonEmpty(settings.TokenEndpointAuthMethods, meta.TokenEndpointAuthMethodsSupported)
		meta.ResponseTypesSupported = firstNonEmpty(settings.ResponseTypesSupported, meta.ResponseTypesSupported)
		meta.ResponseModesSupported = firstNonEmpty(settings.ResponseModesSupported, meta.ResponseModesSupported)
	}

	meta.ScopesSupported = copyOr(meta.ScopesSupported, sssoapi.DefaultScopesSupported)
	meta.ClaimsSupported = copyOr(meta.ClaimsSupported, sssoapi.DefaultClaimsSupported)
	meta.TokenEndpointAuthMethodsSupported = copyOr(meta.TokenEndpointAuthMethodsSupported, sssoapi.DefaultTokenEndpointAuthMethods)
	meta.ResponseTypesSupported = copyOr(meta.ResponseTypesSupported, []string{"code"})
	meta.ResponseModesSupported = copyOr(meta.ResponseModesSupported, []string{"query", "fragment", "form_post"})
	if jarmAvailable {
		if !contains(meta.ResponseModesSupported, "jwt") {
			meta.ResponseModesSupported = append(meta.ResponseModesSupported, "jwt")
		}
	} else {
		// Never advertise JARM without an RSA signing key: the authorization
		// endpoint silently falls back to query mode in that case.
		meta.ResponseModesSupported = removeString(meta.ResponseModesSupported, "jwt")
	}
	return meta
}

// OIDCConfigurationServiceServer implements ssov1.OIDCConfigurationService.
type OIDCConfigurationServiceServer struct {
	ssov1connect.UnimplementedOIDCConfigurationServiceHandler

	realmSettingsRepo domain.RealmSettingsRepository
	config            *sssoapi.OpenIDProviderConfig
	jarmAvailable     bool
}

// NewOIDCConfigurationServer creates the discovery metadata admin service.
// config provides the static fallbacks; jarmAvailable mirrors whether the
// authorization endpoint can emit signed JARM responses.
func NewOIDCConfigurationServer(repo domain.RealmSettingsRepository, cfg *sssoapi.OpenIDProviderConfig, jarmAvailable bool) *OIDCConfigurationServiceServer {
	return &OIDCConfigurationServiceServer{
		realmSettingsRepo: repo,
		config:            cfg,
		jarmAvailable:     jarmAvailable,
	}
}

var _ ssov1connect.OIDCConfigurationServiceHandler = (*OIDCConfigurationServiceServer)(nil)

// GetOIDCConfiguration returns the effective discovery metadata.
func (s *OIDCConfigurationServiceServer) GetOIDCConfiguration(ctx context.Context, _ *connect.Request[ssov1.GetOIDCConfigurationRequest]) (*connect.Response[ssov1.GetOIDCConfigurationResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, oidcConfigurationServiceTracerName, "GetOIDCConfiguration")
	defer span.End()

	settings, err := s.loadSettings(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to load realm settings")
		span.SetStatus(codes.Error, "failed to load realm settings")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to load OIDC configuration"))
	}

	return connect.NewResponse(&ssov1.GetOIDCConfigurationResponse{
		Configuration: toOIDCConfigurationProto(ResolveOIDCDiscoveryMetadata(settings, s.config, s.jarmAvailable)),
	}), nil
}

// UpdateOIDCConfiguration persists discovery metadata overrides. An empty
// StringList clears the override and falls back to the server defaults.
func (s *OIDCConfigurationServiceServer) UpdateOIDCConfiguration(ctx context.Context, req *connect.Request[ssov1.UpdateOIDCConfigurationRequest]) (*connect.Response[ssov1.UpdateOIDCConfigurationResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, oidcConfigurationServiceTracerName, "UpdateOIDCConfiguration")
	defer span.End()

	if req.Msg.ScopesSupported == nil && req.Msg.ClaimsSupported == nil &&
		req.Msg.TokenEndpointAuthMethodsSupported == nil && req.Msg.ResponseTypesSupported == nil &&
		req.Msg.ResponseModesSupported == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("at least one field must be provided for update"))
	}
	if s.realmSettingsRepo == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("realm settings storage is not configured"))
	}

	settings, err := s.loadSettings(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to load realm settings")
		span.SetStatus(codes.Error, "failed to load realm settings")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to load OIDC configuration"))
	}

	if req.Msg.ScopesSupported != nil {
		settings.ScopesSupported = normalizeStringList(req.Msg.ScopesSupported.Values)
	}
	if req.Msg.ClaimsSupported != nil {
		settings.ClaimsSupported = normalizeStringList(req.Msg.ClaimsSupported.Values)
	}
	if req.Msg.TokenEndpointAuthMethodsSupported != nil {
		settings.TokenEndpointAuthMethods = normalizeStringList(req.Msg.TokenEndpointAuthMethodsSupported.Values)
	}
	if req.Msg.ResponseTypesSupported != nil {
		settings.ResponseTypesSupported = normalizeStringList(req.Msg.ResponseTypesSupported.Values)
	}
	if req.Msg.ResponseModesSupported != nil {
		settings.ResponseModesSupported = normalizeStringList(req.Msg.ResponseModesSupported.Values)
	}

	if err := s.realmSettingsRepo.UpdateRealmSettings(ctx, settings); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update realm settings")
		span.SetStatus(codes.Error, "failed to update OIDC configuration")
		log.Ctx(ctx).Error().Err(err).Msg("Failed to update OIDC discovery configuration")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update OIDC configuration"))
	}

	meta := ResolveOIDCDiscoveryMetadata(settings, s.config, s.jarmAvailable)
	audit.Log("OIDCConfiguration", "OIDCConfigurationUpdated", "", "discovery", strings.Join(meta.ScopesSupported, " "), true, nil)
	return connect.NewResponse(&ssov1.UpdateOIDCConfigurationResponse{
		Configuration: toOIDCConfigurationProto(meta),
	}), nil
}

func (s *OIDCConfigurationServiceServer) loadSettings(ctx context.Context) (*domain.RealmSettings, error) {
	if s.realmSettingsRepo == nil {
		return &domain.RealmSettings{}, nil
	}
	return s.realmSettingsRepo.GetRealmSettings(ctx)
}

func toOIDCConfigurationProto(meta OIDCDiscoveryMetadata) *ssov1.OIDCConfiguration {
	return &ssov1.OIDCConfiguration{
		Issuer:                            meta.Issuer,
		ScopesSupported:                   meta.ScopesSupported,
		ClaimsSupported:                   meta.ClaimsSupported,
		TokenEndpointAuthMethodsSupported: meta.TokenEndpointAuthMethodsSupported,
		ResponseTypesSupported:            meta.ResponseTypesSupported,
		ResponseModesSupported:            meta.ResponseModesSupported,
	}
}

func firstNonEmpty(values, fallback []string) []string {
	if len(values) > 0 {
		return values
	}
	return fallback
}

func copyOr(values, fallback []string) []string {
	if len(values) > 0 {
		return append([]string{}, values...)
	}
	return append([]string{}, fallback...)
}

func removeString(values []string, target string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
