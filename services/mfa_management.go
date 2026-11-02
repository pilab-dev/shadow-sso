package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
	"github.com/pilab-dev/shadow-sso/internal/authflow"
	"google.golang.org/protobuf/types/known/emptypb"
)

// MFA trigger identifiers reported by GetMFAStatus. They mirror the values the
// login flow can actually act on.
const (
	mfaTriggerNone     = "NONE"
	mfaTriggerTOTP     = "TOTP"
	mfaTriggerHOTP     = "HOTP"
	mfaTriggerEmail    = "EMAIL"
	mfaTriggerPush     = "PUSH"
	mfaTriggerSMS      = "SMS"
	mfaTriggerMethod   = "METHOD"
	mfaTriggerWebAuthn = "WEBAUTHN"
	mfaTriggerFlow     = "FLOW"
)

// resolveAuthenticatedToken returns the token info attached by the auth
// interceptor or an Unauthenticated error.
func resolveAuthenticatedToken(ctx context.Context) (*domain.TokenInfo, error) {
	token, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || token == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return token, nil
}

// requireMFAAdmin enforces the admin permission needed to mutate another
// user's second-factor state.
func requireMFAAdmin(ctx context.Context) (*domain.TokenInfo, error) {
	token, err := resolveAuthenticatedToken(ctx)
	if err != nil {
		return nil, err
	}
	if !rbac.HasPermission(token.Roles, rbac.Perm2FAManageOthers) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied to manage MFA for another user"))
	}
	return token, nil
}

// resolveMFAUser looks up a user by ID, falling back to email so the CLI can
// accept either identifier.
func (s *TwoFactorServer) resolveMFAUser(ctx context.Context, idOrEmail string) (*domain.User, error) {
	if strings.TrimSpace(idOrEmail) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("user_id is required"))
	}
	user, err := s.userRepo.GetUserByID(ctx, idOrEmail)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, domain.ErrUserNotFound) {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}
	user, err = s.userRepo.GetUserByEmail(ctx, idOrEmail)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}
	return user, nil
}

// resolveTOTPTarget resolves the user a management/setup operation acts on.
// An empty requestedUserID means the authenticated user. Acting on another
// user requires the 2fa:manage_others permission.
func (s *TwoFactorServer) resolveTOTPTarget(ctx context.Context, requestedUserID string) (*domain.User, *domain.TokenInfo, error) {
	token, err := resolveAuthenticatedToken(ctx)
	if err != nil {
		return nil, nil, err
	}
	target := requestedUserID
	if strings.TrimSpace(target) == "" {
		target = token.UserID
	}
	user, err := s.resolveMFAUser(ctx, target)
	if err != nil {
		return nil, nil, err
	}
	if user.ID != token.UserID && !rbac.HasPermission(token.Roles, rbac.Perm2FAManageOthers) {
		return nil, nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied to manage MFA for another user"))
	}
	return user, token, nil
}

// totpReady reports whether the login page can actually verify a TOTP code for
// this user. This is the only second factor the server-rendered /mfa page
// implements today, so it is the source of truth for "usable factor".
func totpReady(user *domain.User) bool {
	return user != nil &&
		user.IsTwoFactorEnabled &&
		user.TwoFactorMethod == "TOTP" &&
		user.TwoFactorSecret != ""
}

func verifiedMethodCount(user *domain.User) int {
	n := 0
	for _, m := range user.MfaMethods {
		if m.Verified {
			n++
		}
	}
	return n
}

func firstVerifiedMethod(user *domain.User) string {
	for _, m := range user.MfaMethods {
		if !m.Verified {
			continue
		}
		switch m.Type {
		case domain.MfaMethodTypeTOTP:
			return mfaTriggerTOTP
		case domain.MfaMethodTypeSMS:
			return mfaTriggerSMS
		case domain.MfaMethodTypeEmail:
			return mfaTriggerEmail
		case domain.MfaMethodTypePush:
			return mfaTriggerPush
		case domain.MfaMethodTypeWebAuthn:
			return mfaTriggerWebAuthn
		}
		return mfaTriggerMethod
	}
	return ""
}

// flowRequiresMFA reports whether the configured browser flow has a REQUIRED
// non-password execution, which forces every user to a second factor.
func (s *TwoFactorServer) flowRequiresMFA(ctx context.Context) bool {
	if s.authFlowRepo == nil {
		return false
	}
	flow, err := s.authFlowRepo.GetFlowByAlias(ctx, authflow.DefaultFlowAlias)
	if err != nil || flow == nil {
		return false
	}
	execs, err := s.authFlowRepo.GetExecutions(ctx, flow.ID)
	if err != nil {
		return false
	}
	for _, ex := range execs {
		if ex.Requirement == authflow.RequirementDisabled {
			continue
		}
		if ex.Authenticator != authflow.AuthenticatorPassword && ex.Requirement == authflow.RequirementRequired {
			return true
		}
	}
	return false
}

func (s *TwoFactorServer) realmRequiresMFA(ctx context.Context) bool {
	if s.realmSettingsRepo == nil {
		return false
	}
	settings, err := s.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil || settings == nil {
		return false
	}
	return settings.RequireMFA
}

// buildMFAStatus computes the operator-facing view of a user's second-factor
// configuration, including the traps that make the login page unpassable.
func (s *TwoFactorServer) buildMFAStatus(ctx context.Context, user *domain.User) *ssov1.MFAStatus {
	realmRequired := s.realmRequiresMFA(ctx)
	flowRequired := s.flowRequiresMFA(ctx)
	verified := verifiedMethodCount(user)

	status := &ssov1.MFAStatus{
		Enabled:                user.IsTwoFactorEnabled || user.EmailMFAEnabled || user.PushMFAEnabled || verified > 0 || len(user.WebAuthnDevices) > 0,
		MfaRequired:            user.MFARequired,
		RealmRequiresMfa:       realmRequired,
		TotpEnabled:            totpReady(user),
		TotpSecretSet:          user.TwoFactorSecret != "",
		EmailMfaEnabled:        user.EmailMFAEnabled,
		PushMfaEnabled:         user.PushMFAEnabled,
		VerifiedMethods:        int32(verified),
		WebauthnDevices:        int32(len(user.WebAuthnDevices)),
		RecoveryCodesRemaining: int32(len(user.TwoFactorRecoveryCodes)),
		FlowRequiresMfa:        flowRequired,
	}

	switch {
	case user.IsTwoFactorEnabled && user.TwoFactorMethod != "" && user.TwoFactorMethod != "NONE":
		status.EffectiveTrigger = strings.ToUpper(user.TwoFactorMethod)
	case user.EmailMFAEnabled:
		status.EffectiveTrigger = mfaTriggerEmail
	case user.PushMFAEnabled:
		status.EffectiveTrigger = mfaTriggerPush
	default:
		if t := firstVerifiedMethod(user); t != "" {
			status.EffectiveTrigger = t
		} else if len(user.WebAuthnDevices) > 0 {
			status.EffectiveTrigger = mfaTriggerWebAuthn
		} else if flowRequired {
			status.EffectiveTrigger = mfaTriggerFlow
		} else {
			status.EffectiveTrigger = mfaTriggerNone
		}
	}

	enforced := user.MFARequired || realmRequired || flowRequired
	if enforced && !totpReady(user) {
		status.Notes = append(status.Notes, "MFA is enforced for this account but no TOTP factor is usable; the next login will be sent to enrollment.")
	}
	if status.EffectiveTrigger != mfaTriggerNone && status.EffectiveTrigger != mfaTriggerTOTP && status.EffectiveTrigger != mfaTriggerFlow {
		status.Notes = append(status.Notes, fmt.Sprintf("The effective trigger is %s but the /mfa page only verifies TOTP; this account cannot complete the second factor until it is reset or TOTP is enrolled.", status.EffectiveTrigger))
	}
	if user.IsTwoFactorEnabled && user.TwoFactorSecret == "" {
		status.Notes = append(status.Notes, "The 2FA flag is set but no TOTP secret exists; the code prompt can never succeed.")
	}
	if len(user.WebAuthnDevices) > 0 {
		status.Notes = append(status.Notes, "WebAuthn devices are registered but passkey login is not implemented; devices do not satisfy the second factor.")
	}
	if totpReady(user) && len(user.TwoFactorRecoveryCodes) == 0 {
		status.Notes = append(status.Notes, "TOTP is enabled but no recovery codes remain; generate a new set before the user loses their authenticator.")
	}
	return status
}

// GetMFAStatus returns the full second-factor diagnosis for a user.
func (s *TwoFactorServer) GetMFAStatus(ctx context.Context, req *connect.Request[ssov1.GetMFAStatusRequest]) (*connect.Response[ssov1.GetMFAStatusResponse], error) {
	token, err := resolveAuthenticatedToken(ctx)
	if err != nil {
		return nil, err
	}
	// Check permission before touching the repository so a non-admin cannot
	// probe which identifiers exist.
	if req.Msg.GetUserId() != token.UserID && !rbac.HasPermission(token.Roles, rbac.Perm2FAManageOthers) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied to read MFA status for another user"))
	}
	user, err := s.resolveMFAUser(ctx, req.Msg.GetUserId())
	if err != nil {
		return nil, err
	}
	if user.ID != token.UserID && !rbac.HasPermission(token.Roles, rbac.Perm2FAManageOthers) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied to read MFA status for another user"))
	}
	return connect.NewResponse(&ssov1.GetMFAStatusResponse{Status: s.buildMFAStatus(ctx, user)}), nil
}

// ResetUserMFA clears every second-factor credential for a user. This is the
// recovery path for accounts whose configured factor cannot be satisfied.
func (s *TwoFactorServer) ResetUserMFA(ctx context.Context, req *connect.Request[ssov1.ResetUserMFARequest]) (*connect.Response[ssov1.ResetUserMFAResponse], error) {
	admin, err := requireMFAAdmin(ctx)
	if err != nil {
		return nil, err
	}
	user, err := s.resolveMFAUser(ctx, req.Msg.GetUserId())
	if err != nil {
		return nil, err
	}

	previous := s.buildMFAStatus(ctx, user)

	user.IsTwoFactorEnabled = false
	user.TwoFactorMethod = "NONE"
	user.TwoFactorSecret = ""
	user.TwoFactorRecoveryCodes = nil
	user.EmailMFAEnabled = false
	user.PushMFAEnabled = false
	user.PushMFADeviceTokens = nil
	user.PushMFAChallenges = nil
	user.MfaMethods = nil
	user.UpdatedAt = time.Now()

	removedPasskeys := false
	if req.Msg.GetRemovePasskeys() && len(user.WebAuthnDevices) > 0 {
		user.WebAuthnDevices = nil
		removedPasskeys = true
	}

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		audit.Log("TwoFactorService", "ResetUserMFA", admin.UserID, user.ID, "Failed to reset MFA", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to reset MFA: %w", err))
	}

	audit.Log("TwoFactorService", "ResetUserMFA", admin.UserID, user.ID, fmt.Sprintf("MFA reset (previous trigger %s, passkeys removed: %t)", previous.GetEffectiveTrigger(), removedPasskeys), true, nil)

	return connect.NewResponse(&ssov1.ResetUserMFAResponse{
		Previous:        previous,
		RemovedPasskeys: removedPasskeys,
	}), nil
}

// SetUserMFARequired sets or clears the per-user enforcement flag.
func (s *TwoFactorServer) SetUserMFARequired(ctx context.Context, req *connect.Request[ssov1.SetUserMFARequiredRequest]) (*connect.Response[emptypb.Empty], error) {
	admin, err := requireMFAAdmin(ctx)
	if err != nil {
		return nil, err
	}
	user, err := s.resolveMFAUser(ctx, req.Msg.GetUserId())
	if err != nil {
		return nil, err
	}

	user.MFARequired = req.Msg.GetRequired()
	user.UpdatedAt = time.Now()
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		audit.Log("TwoFactorService", "SetUserMFARequired", admin.UserID, user.ID, "Failed to update MFA requirement", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update MFA requirement: %w", err))
	}

	audit.Log("TwoFactorService", "SetUserMFARequired", admin.UserID, user.ID, fmt.Sprintf("MFA required set to %t", user.MFARequired), true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// GetMFAPolicy returns the realm-wide MFA enforcement policy.
func (s *TwoFactorServer) GetMFAPolicy(ctx context.Context, _ *connect.Request[ssov1.GetMFAPolicyRequest]) (*connect.Response[ssov1.GetMFAPolicyResponse], error) {
	if _, err := resolveAuthenticatedToken(ctx); err != nil {
		return nil, err
	}
	if s.realmSettingsRepo == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("realm settings are not configured"))
	}
	settings, err := s.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to read realm settings: %w", err))
	}
	return connect.NewResponse(&ssov1.GetMFAPolicyResponse{RequireMfa: settings.RequireMFA}), nil
}

// SetMFAPolicy updates the realm-wide MFA enforcement policy.
func (s *TwoFactorServer) SetMFAPolicy(ctx context.Context, req *connect.Request[ssov1.SetMFAPolicyRequest]) (*connect.Response[emptypb.Empty], error) {
	admin, err := requireMFAAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.realmSettingsRepo == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("realm settings are not configured"))
	}
	settings, err := s.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to read realm settings: %w", err))
	}
	settings.RequireMFA = req.Msg.GetRequireMfa()
	settings.UpdatedAt = time.Now()
	if err := s.realmSettingsRepo.UpdateRealmSettings(ctx, settings); err != nil {
		audit.Log("TwoFactorService", "SetMFAPolicy", admin.UserID, settings.Realm, "Failed to update realm MFA policy", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update realm MFA policy: %w", err))
	}

	audit.Log("TwoFactorService", "SetMFAPolicy", admin.UserID, settings.Realm, fmt.Sprintf("Realm require_mfa set to %t", settings.RequireMFA), true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// mfaEnforcedFor reports whether a user must complete a second factor,
// combining the per-user flag and the realm policy.
