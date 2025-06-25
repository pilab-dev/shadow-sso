package services

import (
	"context"
	"errors"
	"fmt"
	"strings" // For Verify2FA token check
	"time"    // Needed for GenerateTokenPair TTL and session expiry

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp" // For TOTP validation
	"github.com/pilab-dev/shadow-sso/middleware"         // For GetAuthenticatedTokenFromContext
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb" // For mapping time to proto
)

// AuthServer implements the ssov1connect.AuthServiceHandler interface.
type AuthServer struct {
	ssov1connect.UnimplementedAuthServiceHandler // Embed for forward compatibility
	userRepo                                     domain.UserRepository
	sessionRepo                                  domain.SessionRepository
	tokenService                                 *TokenService
	passwordHasher                               PasswordHasher
}

// NewAuthServer creates a new AuthServer.
func NewAuthServer(
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	tokenService *TokenService,
	passwordHasher PasswordHasher,
) *AuthServer {
	return &AuthServer{
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		tokenService:   tokenService,
		passwordHasher: passwordHasher,
	}
}

func mapDomainStatusToProto(ds domain.UserStatus) ssov1.UserStatus {
	switch ds {
	case domain.UserStatusActive:
		return ssov1.UserStatus_USER_STATUS_ACTIVE
	case domain.UserStatusLocked:
		return ssov1.UserStatus_USER_STATUS_LOCKED
	case domain.UserStatusPending:
		return ssov1.UserStatus_USER_STATUS_PENDING_ACTIVATION
	default:
		return ssov1.UserStatus_USER_STATUS_UNSPECIFIED
	}
}

// Login handles the first step of user authentication (password check).
// If 2FA is enabled, it returns a response indicating that 2FA is required.
// Otherwise, it completes the login and returns tokens.
func (s *AuthServer) Login(ctx context.Context, req *connect.Request[ssov1.LoginRequest]) (*connect.Response[ssov1.LoginResponse], error) {
	log.Debug().Str("email", req.Msg.Email).Msg("Login attempt")

	user, err := s.userRepo.GetUserByEmail(ctx, req.Msg.Email)
	if err != nil {
		log.Warn().Err(err).Str("email", req.Msg.Email).Msg("Login: User not found")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid email or password"))
	}
	if user.Status == domain.UserStatusLocked {
		log.Warn().Str("userID", user.ID).Msg("Login: Account locked")
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("account is locked"))
	}
	if user.Status == domain.UserStatusPending {
		log.Warn().Str("userID", user.ID).Msg("Login: Account pending activation")
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("account pending activation"))
	}

	if !s.passwordHasher.Verify(user.PasswordHash, req.Msg.Password) {
		log.Warn().Str("userID", user.ID).Msg("Login: Incorrect password")
		// TODO: Increment failed login attempts for user in userRepo.UpdateUser
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid email or password"))
	}

	// --- 2FA Check ---
	if user.IsTwoFactorEnabled && user.TwoFactorMethod == "TOTP" {
		log.Info().Str("userID", user.ID).Msg("Login: 2FA (TOTP) is enabled, step-up required.")
		// The TwoFactorSessionToken should be a secure, short-lived token (e.g., a JWT or opaque token stored server-side).
		// For this implementation, we use a simple placeholder. This is NOT production-ready.
		// A robust implementation would involve s.tokenService generating a special short-lived token.
		tfaSessionToken := "placeholder_2fa_session_token_for_" + user.ID
		return connect.NewResponse(&ssov1.LoginResponse{
			TwoFactorRequired:     true,
			TwoFactorSessionToken: tfaSessionToken,
			// UserInfo is not sent yet, only after full 2FA.
		}), nil
	}
	// --- End 2FA Check ---

	// If 2FA is not enabled, proceed to generate final tokens and session
	return s.completeLogin(ctx, user)
}

// completeLogin is a helper to finalize login after all checks (password, and 2FA if applicable) pass.
func (s *AuthServer) completeLogin(ctx context.Context, user *domain.User) (*connect.Response[ssov1.LoginResponse], error) {
	// Define clientID, scope, and tokenTTL for the application initiating the login.
	// These might come from client authentication if the client itself is an OAuth client.
	// For now, hardcode for a primary user login flow (e.g., web app, CLI).
	clientID := "sso-default-client"               // Example client ID
	scope := "openid profile email offline_access" // Standard OIDC scopes + offline for refresh token
	tokenTTL := 1 * time.Hour                      // Example access token TTL

	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientID, user.ID, scope, tokenTTL)
	if err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("completeLogin: Failed to generate token pair")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("could not generate tokens: %w", err))
	}

	// Create and store session
	session := &domain.Session{
		UserID:       user.ID,
		TokenID:      "", // TODO: Extract JTI from access token (tokenPair.AccessToken) to use as session.TokenID
		RefreshToken: tokenPair.RefreshToken,
		// TODO: Populate IPAddress, UserAgent from ctx/request if available and desired
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // Example: Long session expiry, e.g., 30 days
		IsRevoked: false,
	}
	if err := s.sessionRepo.StoreSession(ctx, session); err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("completeLogin: Failed to store session")
		// Decide if this should be a fatal error for login. For now, log and continue.
	}

	// Update LastLoginAt for user
	now := time.Now()
	user.LastLoginAt = &now
	user.FailedLoginAttempts = 0 // Reset on successful login
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		log.Warn().Err(err).Str("userID", user.ID).Msg("completeLogin: Failed to update user LastLoginAt")
		// Non-fatal
	}

	userInfoProto := &ssov1.User{
		Id:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Status:    mapDomainStatusToProto(user.Status),
		Roles:     user.Roles,
	}
	if !user.CreatedAt.IsZero() {
		userInfoProto.CreatedAt = timestamppb.New(user.CreatedAt)
	}
	if !user.UpdatedAt.IsZero() {
		userInfoProto.UpdatedAt = timestamppb.New(user.UpdatedAt)
	}
	if user.LastLoginAt != nil && !user.LastLoginAt.IsZero() {
		userInfoProto.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}

	return connect.NewResponse(&ssov1.LoginResponse{
		AccessToken:           tokenPair.AccessToken,
		TokenType:             tokenPair.TokenType,
		ExpiresIn:             int32(tokenPair.ExpiresIn),
		RefreshToken:          tokenPair.RefreshToken,
		IdToken:               tokenPair.IDToken,
		UserInfo:              userInfoProto,
		TwoFactorRequired:     false, // Final response, 2FA already passed or not needed
		TwoFactorSessionToken: "",    // Not needed in final response
	}), nil
}

// Verify2FA verifies the 2FA code (TOTP or recovery) and completes the login.
func (s *AuthServer) Verify2FA(ctx context.Context, req *connect.Request[ssov1.Verify2FARequest]) (*connect.Response[ssov1.LoginResponse], error) {
	log.Debug().Str("userID", req.Msg.UserId).Msg("Verify2FA attempt")

	// SECURITY CRITICAL: Validate req.Msg.TwoFactorSessionToken robustly.
	// The placeholder implementation below is NOT secure for production.
	// It should involve validating a short-lived, server-generated token (e.g., JWT or opaque token).
	expectedTFASessionTokenPrefix := "placeholder_2fa_session_token_for_"
	if !strings.HasPrefix(req.Msg.TwoFactorSessionToken, expectedTFASessionTokenPrefix) ||
		req.Msg.TwoFactorSessionToken != expectedTFASessionTokenPrefix+req.Msg.UserId {
		log.Warn().Str("userID", req.Msg.UserId).Str("receivedToken", req.Msg.TwoFactorSessionToken).Msg("Verify2FA: Invalid or missing two_factor_session_token")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired 2FA session"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		log.Warn().Err(err).Str("userID", req.Msg.UserId).Msg("Verify2FA: User not found")
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found: %w", err))
	}

	if !user.IsTwoFactorEnabled || user.TwoFactorMethod != "TOTP" || user.TwoFactorSecret == "" {
		log.Warn().Str("userID", user.ID).Msg("Verify2FA: 2FA not enabled or setup correctly for user")
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("2FA not configured for this user, or setup incomplete"))
	}

	// Validate TOTP code
	validTOTP, errValidate := totp.ValidateTOTPCode(user.TwoFactorSecret, req.Msg.TotpCode)
	if errValidate != nil {
		log.Error().Err(errValidate).Str("userID", user.ID).Msg("Verify2FA: Error during TOTP code validation function call")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error during TOTP validation: %w", errValidate))
	}

	if validTOTP {
		log.Info().Str("userID", user.ID).Msg("Verify2FA: TOTP code valid.")
		return s.completeLogin(ctx, user)
	}

	// If TOTP is not valid, try recovery code
	validRecovery, usedRecoveryIndex := totp.VerifyRecoveryCode(user.TwoFactorRecoveryCodes, req.Msg.TotpCode)
	if validRecovery {
		log.Info().Str("userID", user.ID).Int("recoveryIndex", usedRecoveryIndex).Msg("Verify2FA: Recovery code valid and used.")
		// Invalidate used recovery code
		user.TwoFactorRecoveryCodes = append(user.TwoFactorRecoveryCodes[:usedRecoveryIndex], user.TwoFactorRecoveryCodes[usedRecoveryIndex+1:]...)
		if errUpdate := s.userRepo.UpdateUser(ctx, user); errUpdate != nil {
			log.Error().Err(errUpdate).Str("userID", user.ID).Msg("Verify2FA: Failed to update user after using recovery code")
			// Decide if this failure should prevent login. For now, it proceeds with login but logs the error.
		}
		return s.completeLogin(ctx, user)
	}

	log.Warn().Str("userID", user.ID).Msg("Verify2FA: Invalid TOTP or recovery code provided.")
	// TODO: Implement failed 2FA attempt tracking and potential user lockout/alert.
	return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid 2FA code"))
}

// Logout method (existing, ensure it's compatible with any context changes if needed)
func (s *AuthServer) Logout(ctx context.Context, req *connect.Request[ssov1.LogoutRequest]) (*connect.Response[emptypb.Empty], error) {
	authedToken, ok := middleware.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated for logout"))
	}

	// Assuming token.ID from context is the JTI, which is stored as TokenID in domain.Session
	session, err := s.sessionRepo.GetSessionByTokenID(ctx, authedToken.ID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") { // Check for domain/repo specific "not found"
			log.Warn().Str("jti", authedToken.ID).Msg("Logout: No active session found for token JTI, perhaps already logged out or session expired.")
			// If no session, maybe token is already effectively invalid. Can still try to revoke from denylist.
		} else {
			log.Error().Err(err).Str("jti", authedToken.ID).Msg("Logout: Error retrieving session by JTI")
			// Fall through to try token revocation anyway
		}
	}

	if session != nil {
		session.IsRevoked = true
		session.ExpiresAt = time.Now() // Expire immediately
		if errUpdate := s.sessionRepo.UpdateSession(ctx, session); errUpdate != nil {
			log.Error().Err(errUpdate).Str("sessionID", session.ID).Msg("Logout: Failed to update session to revoked")
			// Non-fatal for logout, proceed to revoke token itself
		} else {
			log.Info().Str("sessionID", session.ID).Str("userID", session.UserID).Msg("Logout: Session marked as revoked")
		}
	}

	// Also attempt to revoke the token via TokenService (e.g., if it maintains a denylist)
	// TokenService.RevokeToken might expect the raw token value or JTI.
	// Current ssso.TokenRepository.RevokeToken expects tokenValue.
	// If authedToken.TokenValue is available, use it. Otherwise, JTI (authedToken.ID).
	// Let's assume the TokenService's RevokeToken is designed to handle JTI for this scenario.
	if errRevoke := s.tokenService.RevokeToken(ctx, authedToken.ID); errRevoke != nil {
		log.Error().Err(errRevoke).Str("jti", authedToken.ID).Msg("Logout: Failed to revoke token via TokenService (e.g., denylist)")
		// This might not be fatal if session is already marked.
	}

	return connect.NewResponse(&emptypb.Empty{}), nil
}

// ListUserSessions method (existing)
func (s *AuthServer) ListUserSessions(ctx context.Context, req *connect.Request[ssov1.ListUserSessionsRequest]) (*connect.Response[ssov1.ListUserSessionsResponse], error) {
	authedToken, ok := middleware.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	targetUserID := req.Msg.UserId
	if targetUserID == "" || targetUserID == "me" { // "me" is a common convention
		targetUserID = authedToken.UserID
	} else {
		// Check if authed user has permission to list sessions for another user (RBAC)
		// This requires rbac.HasPermission and knowing the required permission.
		// For now, assume if targetUserID is different, admin rights are needed.
		// This logic should ideally be in the RBAC interceptor or a helper.
		if targetUserID != authedToken.UserID && !rbac.HasPermission(authedToken.Roles, rbac.PermSessionsListOthers) {
			return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied to list sessions for user %s", targetUserID))
		}
	}

	// TODO: Populate domain.SessionFilter from request if ListUserSessionsRequest has filter fields
	dbSessions, err := s.sessionRepo.ListSessionsByUserID(ctx, targetUserID, domain.SessionFilter{})
	if err != nil {
		log.Error().Err(err).Str("targetUserID", targetUserID).Msg("ListUserSessions: Failed to list sessions")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("could not list sessions: %w", err))
	}

	protoSessions := make([]*ssov1.SessionInfo, 0, len(dbSessions))
	for _, ds := range dbSessions {
		protoSessions = append(protoSessions, &ssov1.SessionInfo{
			Id:        ds.ID,
			UserId:    ds.UserID,
			UserAgent: ds.UserAgent,
			IpAddress: ds.IPAddress,
			CreatedAt: timestamppb.New(ds.CreatedAt),
			ExpiresAt: timestamppb.New(ds.ExpiresAt),
			// IsCurrentSession: ds.TokenID == authedToken.ID, // Check if it's the session of the calling token
		})
	}
	return connect.NewResponse(&ssov1.ListUserSessionsResponse{Sessions: protoSessions}), nil
}

// ClearUserSessions method (existing)
func (s *AuthServer) ClearUserSessions(ctx context.Context, req *connect.Request[ssov1.ClearUserSessionsRequest]) (*connect.Response[emptypb.Empty], error) {
	authedToken, ok := middleware.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	targetUserID := req.Msg.UserId
	if targetUserID == "" || targetUserID == "me" {
		targetUserID = authedToken.UserID
	} else {
		if targetUserID != authedToken.UserID && !rbac.HasPermission(authedToken.Roles, rbac.PermSessionsClearOthers) {
			return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied to clear sessions for user %s", targetUserID))
		}
	}

	if len(req.Msg.SessionIds) > 0 { // Clear specific sessions
		for _, sessionID := range req.Msg.SessionIds {
			// Optional: First get session to ensure it belongs to targetUserID before deleting/revoking
			// For now, directly try to update/delete.
			session, errGet := s.sessionRepo.GetSessionByID(ctx, sessionID)
			if errGet == nil && session.UserID == targetUserID {
				session.IsRevoked = true
				session.ExpiresAt = time.Now()
				if errUpdate := s.sessionRepo.UpdateSession(ctx, session); errUpdate != nil {
					log.Error().Err(errUpdate).Str("sessionID", sessionID).Msg("ClearUserSessions: Failed to revoke specific session")
					// Continue to try others, or return partial error?
				}
			} else if errGet != nil {
				log.Warn().Err(errGet).Str("sessionID", sessionID).Msg("ClearUserSessions: Failed to get session to revoke or session does not belong to user.")
			}
		}
	} else { // Clear all sessions for the target user (or all but current if self and not specified)
		var exceptSessionID string
		if targetUserID == authedToken.UserID {
			// Default "clear all" for self often means "all except current"
			// If an explicit "clear all including current" is desired, a flag or different method might be used.
			// For now, let's assume this call clears all sessions for the target user *including* the current one if applicable.
			// To clear all *but* current, we'd pass authedToken.ID (JTI) to DeleteSessionsByUserID's except list.
			// The CLI `ssoctl session clear --all` implies this path.
			// `ssoctl session clear` (no flags for self) implies all *other*.
			// This logic needs to be very clear. Let's assume if SessionIds is empty, it's all for that user.
			// If service needs to protect current session, it has to get JTI from context token.
		}
		_, err := s.sessionRepo.DeleteSessionsByUserID(ctx, targetUserID, exceptSessionID) // If exceptSessionID is empty, all are deleted for user.
		if err != nil {
			log.Error().Err(err).Str("targetUserID", targetUserID).Msg("ClearUserSessions: Failed to delete sessions by user ID")
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("could not clear sessions: %w", err))
		}
	}

	return connect.NewResponse(&emptypb.Empty{}), nil
}

// Ensure AuthServer implements ssov1connect.AuthServiceHandler
var _ ssov1connect.AuthServiceHandler = (*AuthServer)(nil)
