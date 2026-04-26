package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	goerrors "errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp" // For TOTP validation
	"github.com/pilab-dev/shadow-sso/internal/metrics"
	// "github.com/pilab-dev/shadow-sso/middleware" // No longer needed here
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb" // For mapping time to proto
)

type twoFactorSessionEntry struct {
	UserID    string
	ExpiresAt time.Time
}

// FIXME: Use Redis TTL store instead of in-memory when multi-replica deployment is active (see helm values replicaCount: 2)
type twoFactorSessionStore struct {
	mu      sync.Mutex
	entries map[string]twoFactorSessionEntry
}

func newTwoFactorSessionStore() *twoFactorSessionStore {
	s := &twoFactorSessionStore{
		entries: make(map[string]twoFactorSessionEntry),
	}
	go s.cleanup()
	return s
}

func (s *twoFactorSessionStore) Set(token, userID string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[token] = twoFactorSessionEntry{
		UserID:    userID,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// GetAndDelete retrieves and atomically removes a token entry if valid.
func (s *twoFactorSessionStore) GetAndDelete(token string) (twoFactorSessionEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[token]
	if !ok {
		return twoFactorSessionEntry{}, false
	}
	delete(s.entries, token)
	return entry, time.Now().Before(entry.ExpiresAt)
}

func (s *twoFactorSessionStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, entry := range s.entries {
			if now.After(entry.ExpiresAt) {
				delete(s.entries, token)
			}
		}
		s.mu.Unlock()
	}
}

// AuthServer implements the ssov1connect.AuthServiceHandler interface.
type AuthServer struct {
	ssov1connect.UnimplementedAuthServiceHandler // Embed for forward compatibility
	userRepo                                     domain.UserRepository
	sessionRepo                                  domain.SessionRepository
	tokenService                                 domain.TokenServiceInterface
	passwordHasher                               domain.PasswordHasher
	flowStore                                    domain.FlowStore
	oauthService                                 domain.OAuthServiceInterface
	clientService                                client.ClientServiceInterface
	twoFactorSessions                            *twoFactorSessionStore
}

// NewAuthServer creates a new AuthServer.
func NewAuthServer(
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	tokenService domain.TokenServiceInterface,
	passwordHasher domain.PasswordHasher,
	flowStore domain.FlowStore,
	oauthService domain.OAuthServiceInterface,
	clientService client.ClientServiceInterface,
) *AuthServer {
	return &AuthServer{
		userRepo:        userRepo,
		sessionRepo:     sessionRepo,
		tokenService:    tokenService,
		passwordHasher:  passwordHasher,
		flowStore:       flowStore,
		oauthService:    oauthService,
		clientService:   clientService,
		twoFactorSessions: newTwoFactorSessionStore(),
	}
}

const twoFactorSessionTTL = 5 * time.Minute

func (s *AuthServer) generateSecure2FAToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure 2FA token: %w", err)
	}
	return hex.EncodeToString(b), nil
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
	var userID string // For audit logging, even if user object is not fetched

	user, err := s.userRepo.GetUserByEmail(ctx, req.Msg.Email)
	if err != nil {
		log.Warn().Err(err).Str("email", req.Msg.Email).Msg("Login: User not found")
		audit.Log("AuthService", "Login", req.Msg.Email, "", "User not found or DB error", false, err)
		if metrics.LoginFailureTotal != nil {
			metrics.LoginFailureTotal.Inc()
		}
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid email or password"))
	}
	userID = user.ID // User found, set userID for audit

	if user.Status == domain.UserStatusLocked {
		log.Warn().Str("userID", userID).Msg("Login: Account locked")
		audit.Log("AuthService", "Login", userID, userID, "Account locked", false, errors.New("account locked"))
		if metrics.LoginFailureTotal != nil {
			metrics.LoginFailureTotal.Inc()
		}
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("account is locked"))
	}
	if user.Status == domain.UserStatusPending {
		log.Warn().Str("userID", userID).Msg("Login: Account pending activation")
		audit.Log("AuthService", "Login", userID, userID, "Account pending activation", false, errors.New("account pending activation"))
		if metrics.LoginFailureTotal != nil {
			metrics.LoginFailureTotal.Inc()
		}
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("account pending activation"))
	}

	if err := s.passwordHasher.Verify(user.PasswordHash, req.Msg.Password); err != nil {
		log.Warn().Str("userID", userID).Msg("Login: Incorrect password")
		audit.Log("AuthService", "Login", userID, userID, "Incorrect password", false, err)
		if metrics.LoginFailureTotal != nil {
			metrics.LoginFailureTotal.Inc()
		}
		// TODO: Increment failed login attempts for user in userRepo.UpdateUser
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid email or password"))
	}

	// --- 2FA Check ---
	if user.IsTwoFactorEnabled && user.TwoFactorMethod == "TOTP" {
		log.Info().Str("userID", user.ID).Msg("Login: 2FA (TOTP) is enabled, step-up required.")
		tfaSessionToken, err := s.generateSecure2FAToken()
		if err != nil {
			log.Error().Err(err).Str("userID", user.ID).Msg("Login: Failed to generate 2FA session token")
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate 2FA session token: %w", err))
		}
		s.twoFactorSessions.Set(tfaSessionToken, user.ID, twoFactorSessionTTL)
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
		audit.Log("AuthService", "LoginComplete", user.ID, user.ID, "Failed to generate token pair", false, err)
		// Note: LoginFailureTotal was already incremented if password check failed.
		// If token generation is the failure point after successful password, it's an internal error, not a typical "login failure".
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

	if metrics.LoginSuccessTotal != nil {
		metrics.LoginSuccessTotal.Inc()
	}
	if metrics.ActiveSessionsGauge != nil {
		metrics.ActiveSessionsGauge.Inc()
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

	audit.Log("AuthService", "LoginComplete", user.ID, user.ID, "Login successful, tokens and session created", true, nil)
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

	entry, valid := s.twoFactorSessions.GetAndDelete(req.Msg.TwoFactorSessionToken)
	if !valid || entry.UserID != req.Msg.UserId {
		log.Warn().Str("userID", req.Msg.UserId).Msg("Verify2FA: Invalid or expired 2FA session token")
		audit.Log("AuthService", "Verify2FA", req.Msg.UserId, req.Msg.UserId, "Invalid or missing 2FA session token", false, errors.New("invalid or expired 2FA session"))
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired 2FA session"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.UserId)
	if err != nil {
		log.Warn().Err(err).Str("userID", req.Msg.UserId).Msg("Verify2FA: User not found")
		audit.Log("AuthService", "Verify2FA", req.Msg.UserId, req.Msg.UserId, "User not found for 2FA verification", false, err)
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("user not found: %w", err))
	}

	if !user.IsTwoFactorEnabled || user.TwoFactorMethod != "TOTP" || user.TwoFactorSecret == "" {
		log.Warn().Str("userID", user.ID).Msg("Verify2FA: 2FA not enabled or setup correctly for user")
		audit.Log("AuthService", "Verify2FA", user.ID, user.ID, "2FA not enabled or setup correctly", false, errors.New("2FA not configured or setup incomplete"))
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("2FA not configured for this user, or setup incomplete"))
	}

	// Validate TOTP code
	validTOTP, errValidate := totp.ValidateTOTPCode(user.TwoFactorSecret, req.Msg.TotpCode)
	if errValidate != nil {
		log.Error().Err(errValidate).Str("userID", user.ID).Msg("Verify2FA: Error during TOTP code validation function call")
		audit.Log("AuthService", "Verify2FA", user.ID, user.ID, "Error during TOTP validation function", false, errValidate)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error during TOTP validation: %w", errValidate))
	}

	if validTOTP {
		log.Info().Str("userID", user.ID).Msg("Verify2FA: TOTP code valid.")
		// completeLogin will log success/failure of token generation
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
			audit.Log("AuthService", "Verify2FA", user.ID, user.ID, "Failed to update user after using recovery code", false, errUpdate)
			// Decide if this failure should prevent login. For now, it proceeds with login but logs the error.
		}
		// completeLogin will log success/failure of token generation
		return s.completeLogin(ctx, user)
	}

	log.Warn().Str("userID", user.ID).Msg("Verify2FA: Invalid TOTP or recovery code provided.")
	audit.Log("AuthService", "Verify2FA", user.ID, user.ID, "Invalid TOTP or recovery code", false, errors.New("invalid 2FA code"))
	// TODO: Implement failed 2FA attempt tracking and potential user lockout/alert.
	if metrics.LoginFailureTotal != nil {
		metrics.LoginFailureTotal.Inc()
	}
	return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid 2FA code"))
}

// Logout method (existing, ensure it's compatible with any context changes if needed)
func (s *AuthServer) Logout(ctx context.Context, req *connect.Request[ssov1.LogoutRequest]) (*connect.Response[emptypb.Empty], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authedToken == nil {
		audit.Log("AuthService", "Logout", "anonymous", "", "User not authenticated for logout", false, errors.New("user not authenticated"))
		// Not incrementing LoginFailureTotal here as it's not a login attempt
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated for logout"))
	}
	actingUserID := authedToken.UserID
	tokenJTI := authedToken.ID

	// Assuming token.ID from context is the JTI, which is stored as TokenID in domain.Session
	session, err := s.sessionRepo.GetSessionByTokenID(ctx, tokenJTI)
	if err != nil {
		if strings.Contains(err.Error(), "not found") { // Check for domain/repo specific "not found"
			log.Warn().Str("jti", tokenJTI).Str("userID", actingUserID).Msg("Logout: No active session found for token JTI, perhaps already logged out or session expired.")
			// If no session, maybe token is already effectively invalid. Can still try to revoke from denylist.
		} else {
			log.Error().Err(err).Str("jti", tokenJTI).Str("userID", actingUserID).Msg("Logout: Error retrieving session by JTI")
			// Fall through to try token revocation anyway
		}
		// Audit log for session retrieval failure, but continue to attempt token revocation
		audit.Log("AuthService", "Logout", actingUserID, tokenJTI, "Failed to retrieve session by JTI or session not found", false, err)
	}

	if session != nil {
		session.IsRevoked = true
		session.ExpiresAt = time.Now() // Expire immediately
		if errUpdate := s.sessionRepo.UpdateSession(ctx, session); errUpdate != nil {
			log.Error().Err(errUpdate).Str("sessionID", session.ID).Str("userID", actingUserID).Msg("Logout: Failed to update session to revoked")
			audit.Log("AuthService", "Logout", actingUserID, session.ID, "Failed to mark session as revoked", false, errUpdate)
			// Non-fatal for logout, proceed to revoke token itself
		} else {
			log.Info().Str("sessionID", session.ID).Str("userID", actingUserID).Msg("Logout: Session marked as revoked")
			audit.Log("AuthService", "Logout", actingUserID, session.ID, "Session marked as revoked successfully", true, nil)
		}
	}

	// Also attempt to revoke the token via TokenService (e.g., if it maintains a denylist)
	if errRevoke := s.tokenService.RevokeToken(ctx, tokenJTI); errRevoke != nil {
		log.Error().Err(errRevoke).Str("jti", tokenJTI).Str("userID", actingUserID).Msg("Logout: Failed to revoke token via TokenService (e.g., denylist)")
		audit.Log("AuthService", "Logout", actingUserID, tokenJTI, "Failed to revoke token via TokenService", false, errRevoke)
		// This might not be fatal if session is already marked.
		// If session revoking also failed, this could be the primary failure point.
		if session == nil || (session != nil && err != nil) { // If session marking failed or session wasn't found
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to complete logout process"))
		}
	} else {
		audit.Log("AuthService", "Logout", actingUserID, tokenJTI, "Token revoked via TokenService successfully", true, nil)
	}

	if metrics.ActiveSessionsGauge != nil {
		metrics.ActiveSessionsGauge.Dec()
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// ListUserSessions method (existing)
func (s *AuthServer) ListUserSessions(ctx context.Context, req *connect.Request[ssov1.ListUserSessionsRequest]) (*connect.Response[ssov1.ListUserSessionsResponse], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
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
		// Check if this session's TokenID matches the calling token's JTI (ID)
		isCurrentSession := ds.TokenID == authedToken.ID
		protoSessions = append(protoSessions, &ssov1.SessionInfo{
			Id:               ds.ID,
			UserId:           ds.UserID,
			UserAgent:        ds.UserAgent,
			IpAddress:        ds.IPAddress,
			CreatedAt:        timestamppb.New(ds.CreatedAt),
			ExpiresAt:        timestamppb.New(ds.ExpiresAt),
			IsCurrentSession: isCurrentSession,
		})
	}
	return connect.NewResponse(&ssov1.ListUserSessionsResponse{Sessions: protoSessions}), nil
}

// ClearUserSessions method (existing)
func (s *AuthServer) ClearUserSessions(ctx context.Context, req *connect.Request[ssov1.ClearUserSessionsRequest]) (*connect.Response[emptypb.Empty], error) {
	authedToken, ok := domain.GetAuthenticatedTokenFromContext(ctx)
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

// GetConsentInfo retrieves consent information for an OAuth flow
func (s *AuthServer) GetConsentInfo(ctx context.Context, req *connect.Request[ssov1.GetConsentInfoRequest]) (*connect.Response[ssov1.GetConsentInfoResponse], error) {
	flowID := req.Msg.FlowId
	log.Info().Str("flowId", flowID).Msg("GetConsentInfo called")

	// Get flow state
	flowState, err := s.flowStore.GetFlow(ctx, flowID)
	client, err := s.clientService.GetClient(ctx, flowState.ClientID)
	if err != nil {
		log.Error().Err(err).Str("clientID", flowState.ClientID).Msg("Failed to get client for consent")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not retrieve client information"))
	}

	// Parse scopes and create consent data
	requestedScopes := strings.Split(flowState.Scope, " ")
	scopes := make([]*ssov1.ConsentScope, 0, len(requestedScopes))

	for _, scope := range requestedScopes {
		// Basic scope descriptions - in a real implementation, this could be configurable
		var description string
		var required bool

		switch scope {
		case "openid":
			description = "Allow this application to identify you"
			required = true
		case "profile":
			description = "Access your basic profile information (name, picture, etc.)"
			required = false
		case "email":
			description = "Access your email address"
			required = false
		default:
			description = fmt.Sprintf("Access to %s scope", scope)
			required = false
		}

		scopes = append(scopes, &ssov1.ConsentScope{
			Name:        scope,
			Description: description,
			Required:    required,
		})
	}

	response := &ssov1.GetConsentInfoResponse{
		ClientName:    client.Name,
		ClientLogoUri: client.LogoURI,
		Scopes:        scopes,
	}

	return connect.NewResponse(response), nil
}

// SubmitConsent handles user consent approval for OAuth scopes
func (s *AuthServer) SubmitConsent(ctx context.Context, req *connect.Request[ssov1.SubmitConsentRequest]) (*connect.Response[ssov1.SubmitConsentResponse], error) {
	flowID := req.Msg.FlowId
	acceptedScopes := req.Msg.AcceptedScopes
	rememberConsent := req.Msg.RememberConsent

	log.Info().
		Str("flowId", flowID).
		Strs("acceptedScopes", acceptedScopes).
		Bool("rememberConsent", rememberConsent).
		Msg("SubmitConsent called")

	// Get flow state
	flowState, err := s.flowStore.GetFlow(ctx, flowID)
	if err != nil {
		if goerrors.Is(err, domain.ErrFlowNotFound) || goerrors.Is(err, domain.ErrFlowExpired) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("consent flow not found or expired"))
		}
		log.Error().Err(err).Str("flowId", flowID).Msg("Error retrieving flow state for consent submission")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not retrieve flow details"))
	}

	// Validate that all required scopes are accepted
	requestedScopes := strings.Split(flowState.Scope, " ")
	requiredScopes := make([]string, 0)
	for _, scope := range requestedScopes {
		// Basic logic - openid is always required
		if scope == "openid" {
			requiredScopes = append(requiredScopes, scope)
		}
	}

	// Check if all required scopes are in accepted scopes
	for _, required := range requiredScopes {
		found := false
		for _, accepted := range acceptedScopes {
			if accepted == required {
				found = true
				break
			}
		}
		if !found {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("required scopes must be accepted"))
		}
	}

	// Filter scope to only include accepted scopes
	acceptedScopeString := strings.Join(acceptedScopes, " ")

	// Generate authorization code with accepted scopes
	authCode, err := s.oauthService.GenerateAuthCode(
		ctx,
		flowState.ClientID,
		flowState.UserID,
		flowState.RedirectURI,
		acceptedScopeString, // Use only accepted scopes
		flowState.CodeChallenge,
		flowState.CodeChallengeMethod,
		flowState.Nonce,
		flowState.UserAuthenticatedAt,
	)
	if err != nil {
		log.Error().Err(err).Str("flowId", flowID).Msg("Failed to generate authorization code after consent")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not complete authorization"))
	}

	// Delete the flow state as it's now been used
	_ = s.flowStore.DeleteFlow(ctx, flowID)

	// Build redirect URL back to the client application
	redirectURL := flowState.RedirectURI
	params := url.Values{}
	params.Set("code", authCode)
	if flowState.State != "" {
		params.Set("state", flowState.State)
	}

	if strings.Contains(redirectURL, "?") {
		redirectURL += "&" + params.Encode()
	} else {
		redirectURL += "?" + params.Encode()
	}

	log.Info().Str("flowId", flowID).Str("userID", flowState.UserID).Str("redirectURL", redirectURL).Msg("User consented, redirecting to client with auth code")

	response := &ssov1.SubmitConsentResponse{
		RedirectUrl: redirectURL,
	}

	return connect.NewResponse(response), nil
}

// DenyConsent handles user consent denial for OAuth scopes
func (s *AuthServer) DenyConsent(ctx context.Context, req *connect.Request[ssov1.DenyConsentRequest]) (*connect.Response[ssov1.DenyConsentResponse], error) {
	flowID := req.Msg.FlowId
	log.Info().Str("flowId", flowID).Msg("DenyConsent called")

	// Get flow state
	flowState, err := s.flowStore.GetFlow(ctx, flowID)
	if err != nil {
		if goerrors.Is(err, domain.ErrFlowNotFound) || goerrors.Is(err, domain.ErrFlowExpired) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("consent flow not found or expired"))
		}
		log.Error().Err(err).Str("flowId", flowID).Msg("Error retrieving flow state for consent denial")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not retrieve flow details"))
	}

	// Delete the flow state
	_ = s.flowStore.DeleteFlow(ctx, flowID)

	// Build error redirect URL back to the client application
	redirectURL := flowState.RedirectURI
	params := url.Values{}
	params.Set("error", "access_denied")
	params.Set("error_description", "User denied consent")
	if flowState.State != "" {
		params.Set("state", flowState.State)
	}

	if strings.Contains(redirectURL, "?") {
		redirectURL += "&" + params.Encode()
	} else {
		redirectURL += "?" + params.Encode()
	}

	log.Info().Str("flowId", flowID).Str("userID", flowState.UserID).Str("redirectURL", redirectURL).Msg("User denied consent, redirecting to client with error")

	response := &ssov1.DenyConsentResponse{
		RedirectUrl: redirectURL,
	}

	return connect.NewResponse(response), nil
}

// DISABLED: WebAuthn login requires go-webauthn/webauthn library for proper cryptographic challenge verification.
func (s *AuthServer) CompleteWebAuthnLogin(ctx context.Context, req *connect.Request[ssov1.VerifyWebAuthnAuthenticationRequest]) (*connect.Response[ssov1.VerifyWebAuthnAuthenticationResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("WebAuthn login is not yet implemented - requires go-webauthn/webauthn library integration"))
}

// Ensure AuthServer implements ssov1connect.AuthServiceHandler
var _ ssov1connect.AuthServiceHandler = (*AuthServer)(nil)
