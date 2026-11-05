package services

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const realmServiceTracerName = "realm-service"

// RealmServiceServer implements ssov1.RealmService.
type RealmServiceServer struct {
	ssov1connect.UnimplementedRealmServiceHandler
	settingsRepo domain.RealmSettingsRepository
	keysRepo     domain.RealmKeysRepository

	encryptionKey []byte
	reloadKeys    func(context.Context) error
}

// NewRealmServer creates the realm settings and keys admin service.
func NewRealmServer(settingsRepo domain.RealmSettingsRepository, keysRepo domain.RealmKeysRepository) *RealmServiceServer {
	return &RealmServiceServer{settingsRepo: settingsRepo, keysRepo: keysRepo}
}

var _ ssov1connect.RealmServiceHandler = (*RealmServiceServer)(nil)

func realmRepoError(err error, msg, notFound string) error {
	if isNotFoundError(err) {
		return connect.NewError(connect.CodeNotFound, errors.New(notFound))
	}
	return connect.NewError(connect.CodeInternal, errors.New(msg))
}

// GetRealm returns the realm settings.
func (s *RealmServiceServer) GetRealm(ctx context.Context, _ *connect.Request[ssov1.GetRealmRequest]) (*connect.Response[ssov1.GetRealmResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, realmServiceTracerName, "GetRealm")
	defer span.End()

	settings, err := s.settingsRepo.GetRealmSettings(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get realm settings")
		span.SetStatus(codes.Error, "failed to get realm settings")
		return nil, realmRepoError(err, "failed to retrieve realm settings", "realm settings not found")
	}
	return connect.NewResponse(&ssov1.GetRealmResponse{Realm: toRealmProto(settings)}), nil
}

// UpdateRealm applies a partial update to the realm settings.
func (s *RealmServiceServer) UpdateRealm(ctx context.Context, req *connect.Request[ssov1.UpdateRealmRequest]) (*connect.Response[ssov1.UpdateRealmResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, realmServiceTracerName, "UpdateRealm")
	defer span.End()

	m := req.Msg
	if m.SslRequired != nil {
		switch strings.ToLower(*m.SslRequired) {
		case "none", "external", "all":
		default:
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("ssl_required must be one of none, external, all"))
		}
	}
	if m.DisplayName != nil && strings.TrimSpace(*m.DisplayName) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("display_name must not be empty"))
	}

	settings, err := s.settingsRepo.GetRealmSettings(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get realm settings")
		span.SetStatus(codes.Error, "failed to get realm settings")
		return nil, realmRepoError(err, "failed to retrieve realm settings", "realm settings not found")
	}

	if m.DisplayName != nil {
		settings.DisplayName = *m.DisplayName
	}
	if m.Enabled != nil {
		settings.Enabled = *m.Enabled
	}
	if m.RegistrationAllowed != nil {
		settings.RegistrationAllowed = *m.RegistrationAllowed
	}
	if m.LoginWithEmailAllowed != nil {
		settings.LoginWithEmailAllowed = *m.LoginWithEmailAllowed
	}
	if m.DuplicateEmailsAllowed != nil {
		settings.DuplicateEmailsAllowed = *m.DuplicateEmailsAllowed
	}
	if m.ResetPasswordAllowed != nil {
		settings.ResetPasswordAllowed = *m.ResetPasswordAllowed
	}
	if m.EditUsernameAllowed != nil {
		settings.EditUsernameAllowed = *m.EditUsernameAllowed
	}
	if m.BruteForceProtected != nil {
		settings.BruteForceProtected = *m.BruteForceProtected
	}
	if m.SslRequired != nil {
		settings.SSLRequired = strings.ToLower(*m.SslRequired)
	}
	if m.AccessTokenLifespan != nil {
		settings.AccessTokenLifespan = int(*m.AccessTokenLifespan)
	}
	if m.AccessCodeLifespan != nil {
		settings.AccessCodeLifespan = int(*m.AccessCodeLifespan)
	}
	if m.RefreshTokenLifespan != nil {
		settings.RefreshTokenLifespan = int(*m.RefreshTokenLifespan)
	}
	if m.SsoSessionIdleTimeout != nil {
		settings.SSOSessionIdleTimeout = int(*m.SsoSessionIdleTimeout)
	}
	if m.SsoSessionMaxLifespan != nil {
		settings.SSOSessionMaxLifespan = int(*m.SsoSessionMaxLifespan)
	}

	if err := s.settingsRepo.UpdateRealmSettings(ctx, settings); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update realm settings")
		span.SetStatus(codes.Error, "failed to update realm settings")
		audit.Log("Realm", "RealmSettingsUpdated", "", settings.ID, settings.Realm, false, err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update realm settings"))
	}

	audit.Log("Realm", "RealmSettingsUpdated", "", settings.ID, settings.Realm, true, nil)
	return connect.NewResponse(&ssov1.UpdateRealmResponse{Realm: toRealmProto(settings)}), nil
}

// ListRealmKeys lists the realm-default keys (without private material).
func (s *RealmServiceServer) ListRealmKeys(ctx context.Context, _ *connect.Request[ssov1.ListRealmKeysRequest]) (*connect.Response[ssov1.ListRealmKeysResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, realmServiceTracerName, "ListRealmKeys")
	defer span.End()

	keys, err := s.keysRepo.ListRealmKeys(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list realm keys")
		span.SetStatus(codes.Error, "failed to list realm keys")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list realm keys"))
	}
	return connect.NewResponse(&ssov1.ListRealmKeysResponse{Keys: toRealmKeyProtos(keys)}), nil
}

// UpdateRealmKeys bulk-replaces the realm-default key set.
func (s *RealmServiceServer) UpdateRealmKeys(ctx context.Context, req *connect.Request[ssov1.UpdateRealmKeysRequest]) (*connect.Response[ssov1.UpdateRealmKeysResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, realmServiceTracerName, "UpdateRealmKeys")
	defer span.End()

	keys := make([]*domain.RealmKey, 0, len(req.Msg.GetKeys()))
	for _, in := range req.Msg.GetKeys() {
		if strings.TrimSpace(in.GetName()) == "" || strings.TrimSpace(in.GetType()) == "" || strings.TrimSpace(in.GetProviderId()) == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("key name, type and provider_id are required"))
		}
		keys = append(keys, &domain.RealmKey{
			Name:        in.GetName(),
			Type:        in.GetType(),
			ProviderID:  in.GetProviderId(),
			Active:      in.GetActive(),
			Priority:    int(in.GetPriority()),
			PublicKey:   in.GetPublicKey(),
			Certificate: in.GetCertificate(),
		})
	}

	if err := s.keysRepo.UpdateRealmKeys(ctx, keys); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update realm keys")
		span.SetStatus(codes.Error, "failed to update realm keys")
		audit.Log("Realm", "RealmKeysUpdated", "", "", "", false, err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update realm keys"))
	}

	audit.Log("Realm", "RealmKeysUpdated", "", "", "", true, nil)
	return connect.NewResponse(&ssov1.UpdateRealmKeysResponse{Keys: toRealmKeyProtos(keys)}), nil
}

func toRealmKeyProtos(keys []*domain.RealmKey) []*ssov1.RealmKey {
	out := make([]*ssov1.RealmKey, 0, len(keys))
	for _, k := range keys {
		if k == nil {
			continue
		}
		out = append(out, &ssov1.RealmKey{
			Id:          k.ID,
			Name:        k.Name,
			Type:        k.Type,
			ProviderId:  k.ProviderID,
			Active:      k.Active,
			Priority:    int32(k.Priority),
			PublicKey:   k.PublicKey,
			Certificate: k.Certificate,
			Status:      string(k.Status),
		})
	}
	return out
}

func toRealmProto(r *domain.RealmSettings) *ssov1.RealmSettings {
	if r == nil {
		return nil
	}
	out := &ssov1.RealmSettings{
		Id:                     r.ID,
		Realm:                  r.Realm,
		DisplayName:            r.DisplayName,
		Enabled:                r.Enabled,
		RegistrationAllowed:    r.RegistrationAllowed,
		LoginWithEmailAllowed:  r.LoginWithEmailAllowed,
		DuplicateEmailsAllowed: r.DuplicateEmailsAllowed,
		ResetPasswordAllowed:   r.ResetPasswordAllowed,
		EditUsernameAllowed:    r.EditUsernameAllowed,
		BruteForceProtected:    r.BruteForceProtected,
		SslRequired:            r.SSLRequired,
		PasswordPolicy: &ssov1.PasswordPolicy{
			MinLength:    int32(r.PasswordMinLength),
			MaxLength:    int32(r.PasswordMaxLength),
			LowerCase:    int32(r.PasswordLowerCase),
			UpperCase:    int32(r.PasswordUpperCase),
			Digits:       int32(r.PasswordDigits),
			SpecialChars: int32(r.PasswordSpecialChars),
		},
		AccessTokenLifespan:   int32(r.AccessTokenLifespan),
		AccessCodeLifespan:    int32(r.AccessCodeLifespan),
		RefreshTokenLifespan:  int32(r.RefreshTokenLifespan),
		SsoSessionIdleTimeout: int32(r.SSOSessionIdleTimeout),
		SsoSessionMaxLifespan: int32(r.SSOSessionMaxLifespan),
	}
	if !r.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(r.UpdatedAt)
	}
	return out
}
