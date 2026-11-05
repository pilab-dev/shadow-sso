package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

const (
	cibaLifetime     = 5 * time.Minute
	cibaPollInterval = 5
)

// CIBAAuthResponse is the CIBA authentication response (CIBA Core §7.3).
type CIBAAuthResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval,omitempty"`
}

// CIBAService implements poll mode of OpenID Connect CIBA. Requests live in
// the device authorization repository (so they follow its Mongo/DTS backend)
// and are tagged through DeviceCodeData.Claims.
type CIBAService interface {
	InitiateBackchannelAuth(ctx context.Context, cli *domain.Client, loginHint, scope, bindingMessage string) (*CIBAAuthResponse, error)
	IssueTokenForBackchannelAuth(ctx context.Context, authReqID, clientID string) (*api.TokenResponse, error)
	// ResolveBackchannelAuth records the approval or denial of userID.
	ResolveBackchannelAuth(ctx context.Context, authReqID, userID string, approve bool) error
	GetBackchannelAuth(ctx context.Context, authReqID string) (*domain.DeviceCode, *domain.CIBAMeta, error)
}

var _ CIBAService = (*defaultOAuthService)(nil)

// SetCIBANotifier sets the channel used to reach the user's device.
func (s *defaultOAuthService) SetCIBANotifier(n domain.CIBANotifier) { s.cibaNotifier = n }

func (s *defaultOAuthService) InitiateBackchannelAuth(ctx context.Context, cli *domain.Client, loginHint, scope, bindingMessage string) (*CIBAAuthResponse, error) {
	if loginHint == "" {
		return nil, domain.NewInvalidRequest("login_hint is required")
	}
	if len(bindingMessage) > 128 {
		return nil, &domain.OAuth2Error{Code: "invalid_binding_message", Description: "binding_message is too long"}
	}
	scopes := strings.Fields(scope)
	hasOpenID := false
	for _, sc := range scopes {
		if sc == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		return nil, domain.NewInvalidScope("openid scope is required")
	}
	if !s.validateScope(ctx, scope, cli.AllowedScopes) {
		return nil, domain.NewInvalidScope("requested scope not allowed")
	}

	user, err := s.userRepo.GetUserByEmail(ctx, loginHint)
	if err != nil || user == nil {
		user, err = s.userRepo.GetUserByID(ctx, loginHint)
	}
	if err != nil || user == nil || user.Status != domain.UserStatusActive {
		return nil, &domain.OAuth2Error{Code: domain.UnknownUserID, Description: "unknown user"}
	}

	authReqID, err := generateRandomString(deviceCodeLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth_req_id: %w", err)
	}
	meta, _ := json.Marshal(domain.CIBAMeta{CIBA: true, Subject: user.ID, BindingMessage: bindingMessage})
	now := time.Now().UTC()
	req := &domain.DeviceCode{
		ID:             uuid.NewString(),
		DeviceCode:     authReqID,
		UserCode:       "ciba-" + uuid.NewString(),
		ClientID:       cli.ID,
		Scope:          scope,
		Status:         domain.DeviceCodeStatusPending,
		ExpiresAt:      now.Add(cibaLifetime),
		Interval:       cibaPollInterval,
		CreatedAt:      now,
		DeviceCodeData: domain.DeviceCodeData{Claims: string(meta)},
	}
	if err := s.deviceAuthRepo.SaveDeviceAuth(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to save backchannel authentication request: %w", err)
	}

	if s.cibaNotifier != nil {
		note := domain.CIBANotification{
			AuthReqID: authReqID, UserID: user.ID, ClientID: cli.ID, ClientName: cli.Name,
			Scope: scope, BindingMessage: bindingMessage, ExpiresIn: int(cibaLifetime.Seconds()),
		}
		if nErr := s.cibaNotifier.NotifyAuthenticationRequest(ctx, note); nErr != nil {
			_ = s.deviceAuthRepo.UpdateDeviceAuthStatus(ctx, authReqID, domain.DeviceCodeStatusDenied)
			log.Ctx(ctx).Error().Err(nErr).Str("client_id", cli.ID).Msg("CIBA: user notification failed")
			return nil, domain.NewServerError("could not reach the user's authentication device")
		}
	} else {
		log.Ctx(ctx).Warn().Str("client_id", cli.ID).Msg("CIBA: no notifier configured; request must be resolved via gRPC")
	}

	return &CIBAAuthResponse{AuthReqID: authReqID, ExpiresIn: int(cibaLifetime.Seconds()), Interval: cibaPollInterval}, nil
}

func (s *defaultOAuthService) GetBackchannelAuth(ctx context.Context, authReqID string) (*domain.DeviceCode, *domain.CIBAMeta, error) {
	d, err := s.deviceAuthRepo.GetDeviceAuthByDeviceCode(ctx, authReqID)
	if err != nil {
		return nil, nil, domain.ErrDeviceCodeNotFound
	}
	meta := domain.ParseCIBAMeta(d)
	if meta == nil {
		return nil, nil, domain.ErrDeviceCodeNotFound
	}
	return d, meta, nil
}

func (s *defaultOAuthService) ResolveBackchannelAuth(ctx context.Context, authReqID, userID string, approve bool) error {
	d, meta, err := s.GetBackchannelAuth(ctx, authReqID)
	if err != nil {
		return err
	}
	if meta.Subject != userID {
		return domain.ErrDeviceCodeNotFound
	}
	if d.Status != domain.DeviceCodeStatusPending || time.Now().UTC().After(d.ExpiresAt) {
		return domain.ErrCannotApproveDeviceAuth
	}
	if !approve {
		return s.deviceAuthRepo.UpdateDeviceAuthStatus(ctx, authReqID, domain.DeviceCodeStatusDenied)
	}
	_, err = s.deviceAuthRepo.ApproveDeviceAuth(ctx, d.UserCode, userID)
	return err
}

func (s *defaultOAuthService) IssueTokenForBackchannelAuth(ctx context.Context, authReqID, clientID string) (*api.TokenResponse, error) {
	d, meta, err := s.GetBackchannelAuth(ctx, authReqID)
	if err != nil {
		return nil, domain.ErrDeviceFlowTokenExpired
	}
	if d.ClientID != clientID {
		return nil, domain.NewInvalidGrant("auth_req_id was not issued to this client")
	}
	if time.Now().UTC().After(d.ExpiresAt) && d.Status != domain.DeviceCodeStatusRedeemed {
		return nil, domain.ErrDeviceFlowTokenExpired
	}

	switch d.Status {
	case domain.DeviceCodeStatusPending:
		if !d.LastPolledAt.IsZero() && time.Since(d.LastPolledAt) < time.Duration(cibaPollInterval)*time.Second {
			return nil, domain.ErrSlowDown
		}
		_ = s.deviceAuthRepo.UpdateDeviceAuthLastPolledAt(ctx, authReqID)
		return nil, domain.ErrAuthorizationPending
	case domain.DeviceCodeStatusDenied:
		return nil, domain.ErrDeviceFlowAccessDenied
	case domain.DeviceCodeStatusAuthorized:
		if d.UserID != meta.Subject {
			return nil, domain.NewInvalidGrant("authentication was not approved by the requested user")
		}
		// Burn the request before issuing so concurrent polls cannot both succeed.
		if err := s.deviceAuthRepo.UpdateDeviceAuthStatus(ctx, authReqID, domain.DeviceCodeStatusRedeemed); err != nil {
			return nil, fmt.Errorf("failed to redeem auth_req_id: %w", err)
		}
		ttl, ttlErr := s.realmAccessTokenLifespan(ctx)
		if ttlErr != nil {
			return nil, ttlErr
		}
		return s.tokenService.GenerateTokenPair(ctx, d.ClientID, d.UserID, d.Scope, ttl, "")
	default:
		return nil, domain.ErrDeviceFlowTokenExpired
	}
}
