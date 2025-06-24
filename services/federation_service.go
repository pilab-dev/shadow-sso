package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time" // Required for token generation and session

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/pilab-dev/shadow-sso/middleware" // For GetAuthenticatedTokenFromContext
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ContinuationTokenData stores the necessary information for pending federation actions.
type ContinuationTokenData struct {
	ExternalUser      *federation.ExternalUserInfo
	ProviderName      string
	ProviderID        string       // Resolved ProviderID from IdPConfig
	ExistingLocalUser *domain.User // Populated if a local user with matching email exists
	// Add extToken *oauth2.Token if needed for future calls by the provider
}

const (
	defaultContinuationTokenTTL = 5 * time.Minute
)

// FederationServer implements the ssov1connect.FederationServiceHandler interface.
type FederationServer struct {
	ssov1connect.UnimplementedFederationServiceHandler // Embed for forward compatibility

	fedService     *federation.Service
	userRepo       domain.UserRepository
	fedIDRepo      domain.UserFederatedIdentityRepository
	idpRepo        domain.IdPRepository // To resolve provider_id to provider_name for responses
	tokenService   *ssso.TokenService   // To issue local tokens
	sessionRepo    domain.SessionRepository
	passwordHasher PasswordHasher // For creating users if local password setup is part of flow

	continuationCache *ttlcache.Cache[string, *ContinuationTokenData]
}

// NewFederationServer creates a new FederationServer.
func NewFederationServer(
	fedService *federation.Service,
	userRepo domain.UserRepository,
	fedIDRepo domain.UserFederatedIdentityRepository,
	idpRepo domain.IdPRepository,
	tokenService *ssso.TokenService,
	sessionRepo domain.SessionRepository,
	passwordHasher PasswordHasher,
) *FederationServer {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, *ContinuationTokenData](defaultContinuationTokenTTL),
		ttlcache.WithDisableTouchOnHit[string, *ContinuationTokenData](), // Or enable if activity should extend TTL
	)
	go cache.Start() // Start the background goroutine for cleanup

	return &FederationServer{
		fedService:        fedService,
		userRepo:          userRepo,
		fedIDRepo:         fedIDRepo,
		idpRepo:           idpRepo,
		tokenService:      tokenService,
		sessionRepo:       sessionRepo,
		passwordHasher:    passwordHasher,
		continuationCache: cache,
	}
}

// Stop should be called on server shutdown to clean up the cache.
func (s *FederationServer) Stop() {
	s.continuationCache.Stop()
}

// InitiateFederatedLogin starts the federated login flow.
func (s *FederationServer) InitiateFederatedLogin(ctx context.Context, req *connect.Request[ssov1.InitiateFederatedLoginRequest]) (*connect.Response[ssov1.InitiateFederatedLoginResponse], error) {
	if req.Msg.ProviderName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("provider_name is required"))
	}

	state, err := s.fedService.GenerateAuthState()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate auth state for federation")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate auth state"))
	}

	authURL, err := s.fedService.GetAuthorizationURL(ctx, req.Msg.ProviderName, state)
	if err != nil {
		log.Error().Err(err).Str("provider", req.Msg.ProviderName).Msg("Failed to get authorization URL")
		if errors.Is(err, federation.ErrProviderNotFound) || errors.Is(err, federation.ErrProviderMisconfigured) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("provider '%s' not found or misconfigured", req.Msg.ProviderName))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get authorization URL: %v", err))
	}

	return connect.NewResponse(&ssov1.InitiateFederatedLoginResponse{
		AuthorizationUrl: authURL,
		State:            state, // Client (HTTP handler) should store this (e.g., in a secure, HttpOnly cookie)
	}), nil
}

// HandleFederatedCallback processes the callback from the IdP.
// This is a complex method due to various scenarios:
// 1. Existing local user, existing federated link -> Login.
// 2. Existing local user, no federated link for this provider -> Link and Login.
// 3. No local user matching federated info -> New user registration flow or direct creation.
// 4. Federated email matches existing local email (unlinked) -> Merge flow.
func (s *FederationServer) HandleFederatedCallback(ctx context.Context, req *connect.Request[ssov1.HandleFederatedCallbackRequest]) (*connect.Response[ssov1.HandleFederatedCallbackResponse], error) {
	// Note: State validation (comparing req.Msg.State with a stored state like from a cookie)
	// should ideally happen in the HTTP handler that receives the redirect from the IdP
	// *before* calling this gRPC method. If this RPC is to do it, the stored_state needs to be passed in.
	// For simplicity, assuming state validation already passed if this RPC is called without error.

	if req.Msg.ProviderName == "" || req.Msg.Code == "" || req.Msg.State == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("provider_name, code, and state are required"))
	}

	// The `sessionState` for CSRF check needs to be retrieved by the calling HTTP handler (e.g., from a cookie)
	// and passed to fedService.HandleCallback. Here, we assume it's done by the caller or we simplify.
	// Let's assume for now the HTTP handler did this: if req.Msg.State != storedCookieState { return error }
	// For this gRPC handler, we pass req.Msg.State as both queryState and sessionState to the internal service,
	// implying the caller of this gRPC method is responsible for the actual CSRF check if one is needed beyond this.
	// A better way would be for this RPC to take `clientStateFromCookie` as a parameter.
	// For now, we pass req.Msg.State as the validated state.
	externalUser, _, err := s.fedService.HandleCallback(ctx, req.Msg.ProviderName, req.Msg.State, req.Msg.State, req.Msg.Code)
	if err != nil {
		log.Warn().Err(err).Str("provider", req.Msg.ProviderName).Msg("Federated callback processing failed")
		if errors.Is(err, federation.ErrInvalidAuthState) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		if errors.Is(err, federation.ErrExchangeCodeFailed) || errors.Is(err, federation.ErrFetchUserInfoFailed) {
			return nil, connect.NewError(connect.CodeUnavailable, err) // Or FailedPrecondition
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("callback handling failed: %v", err))
	}

	// --- Account Lookup / Linking / Creation Logic ---
	providerConfig, err := s.idpRepo.GetIdPByName(ctx, req.Msg.ProviderName)
	if err != nil || providerConfig == nil {
		log.Error().Err(err).Str("provider_name", req.Msg.ProviderName).Msg("Failed to retrieve provider config during callback")
		return nil, connect.NewError(connect.CodeInternal, errors.New("provider configuration error"))
	}
	providerID := providerConfig.ID

	// 1. Check if this federated identity is already linked to a local user
	fedIdentity, err := s.fedIDRepo.GetByProviderUserID(ctx, req.Msg.ProviderName, externalUser.ProviderUserID)
	if err == nil && fedIdentity != nil {
		// Found existing link. Log the user in.
		localUser, userErr := s.userRepo.GetUserByID(ctx, fedIdentity.UserID)
		if userErr != nil {
			log.Error().Err(userErr).Str("userID", fedIdentity.UserID).Msg("Failed to get local user for existing federated link")
			return nil, connect.NewError(connect.CodeInternal, errors.New("could not retrieve user profile"))
		}
		return s.completeLoginAndRespond(ctx, localUser, ssov1.HandleFederatedCallbackResponse_LOGIN_SUCCESSFUL, "Login successful.")
	} else if err != nil && !strings.Contains(err.Error(), "not found") { // True error, not just "not found"
		log.Error().Err(err).Msg("Error checking for existing federated identity")
		return nil, connect.NewError(connect.CodeInternal, errors.New("database error"))
	}

	// No existing link for this specific externalUser.ProviderUserID + providerName.

	// 2. Is a user currently logged in? (Account linking scenario for an already authenticated user)
	//    This requires the gRPC call to be authenticated.
	authToken, userIsLoggedIn := middleware.GetAuthenticatedTokenFromContext(ctx)
	if userIsLoggedIn && authToken != nil {
		// User is logged in, trying to link a new provider.
		// Check if this local user already has a link for this provider.
		_, err := s.fedIDRepo.GetByUserIDAndProvider(ctx, authToken.UserID, req.Msg.ProviderName)
		if err == nil { // Link already exists for this user and provider, but with a different external ID. This shouldn't happen.
			return connect.NewResponse(&ssov1.HandleFederatedCallbackResponse{
				Status:  ssov1.HandleFederatedCallbackResponse_STATUS_UNSPECIFIED, // Or a new status like CONFLICT
				Message: fmt.Sprintf("Your account is already linked with a %s account. Cannot link another.", req.Msg.ProviderName),
			}), nil
		}

		// Create the new link
		newLink := &domain.UserFederatedIdentity{
			UserID:           authToken.UserID,
			ProviderID:       providerID,
			ProviderUserID:   externalUser.ProviderUserID,
			ProviderEmail:    externalUser.Email,
			ProviderUsername: externalUser.Username,
			// Store tokens if needed (encrypt them!)
			// AccessToken: extToken.AccessToken, RefreshToken: extToken.RefreshToken, TokenExpiresAt: &extToken.Expiry
		}
		if err := s.fedIDRepo.Create(ctx, newLink); err != nil {
			log.Error().Err(err).Msg("Failed to link new federated identity to existing logged-in user")
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to link account"))
		}
		localUser, _ := s.userRepo.GetUserByID(ctx, authToken.UserID) // Should exist
		return s.completeLoginAndRespond(ctx, localUser, ssov1.HandleFederatedCallbackResponse_ACCOUNT_LINKED_LOGIN,
			fmt.Sprintf("Successfully linked your %s account.", req.Msg.ProviderName))
	}

	// User is NOT logged in. This is a fresh login/registration attempt via federation.

	// 3. Check if a local user exists with the email from the federated provider.
	if externalUser.Email != "" {
		existingLocalUser, err := s.userRepo.GetUserByEmail(ctx, externalUser.Email)
		if err == nil && existingLocalUser != nil {
			// Local user with this email exists. Is it already linked to *any* federated identity?
			// More importantly, is it linked to *this* provider? If so, flow 1 would catch it.
			// If it's linked to a *different* provider, that's fine.
			// If it's a PURE local account (no federated links for this provider), then we prompt to merge.

			// Check if this local user already has a link for *this specific provider*.
			// If they do, it implies the externalUser.ProviderUserID is different, which means
			// they used a *different Google account* that has the same email as this local user.
			// This is a conflict scenario.
			_, linkErr := s.fedIDRepo.GetByUserIDAndProvider(ctx, existingLocalUser.ID, req.Msg.ProviderName)
			if linkErr == nil {
				// This local user (existingLocalUser.ID) is ALREADY linked to this provider (req.Msg.ProviderName),
				// but the current externalUser.ProviderUserID is different.
				// This means the user is trying to log in with "Google Account B" which has email X,
				// but "Local User A" (with email X) is already linked to "Google Account A".
				// This is a conflict.
				return connect.NewResponse(&ssov1.HandleFederatedCallbackResponse{
					Status:        ssov1.HandleFederatedCallbackResponse_STATUS_UNSPECIFIED, // Or a new status like FEDERATION_CONFLICT
					Message:       fmt.Sprintf("The %s account you used (%s) is different from the one already linked to the local account with email %s.", req.Msg.ProviderName, externalUser.Email, existingLocalUser.Email),
					ProviderName:  req.Msg.ProviderName,
					ProviderEmail: externalUser.Email,
				}), nil
			}

			// Generate a continuation token for merge flow
			continuationToken := uuid.NewString()
			s.continuationCache.Set(continuationToken, &ContinuationTokenData{
				ExternalUser:      externalUser,
				ProviderName:      req.Msg.ProviderName,
				ProviderID:        providerID,
				ExistingLocalUser: existingLocalUser,
			}, defaultContinuationTokenTTL) // Use default TTL from cache setup

			return connect.NewResponse(&ssov1.HandleFederatedCallbackResponse{
				Status:            ssov1.HandleFederatedCallbackResponse_MERGE_REQUIRED_EMAIL_EXISTS,
				Message:           fmt.Sprintf("An account with email %s already exists. Would you like to link your %s identity to it?", externalUser.Email, req.Msg.ProviderName),
				ProviderUserId:    externalUser.ProviderUserID, // Corrected field name from proto def
				ProviderEmail:     externalUser.Email,
				ProviderName:      req.Msg.ProviderName,
				ContinuationToken: continuationToken,
			}), nil
		}
	}

	// 4. No local user found by federated ID or email. This is a new user registration via federation.
	// For now, we'll indicate that registration is required.
	// A full implementation might auto-create the user here.
	newUser := &domain.User{
		Email:     externalUser.Email, // Must be unique
		FirstName: externalUser.FirstName,
		LastName:  externalUser.LastName,
		Status:    domain.UserStatusActive, // Auto-activate federated users
		// PasswordHash can be empty or a random unguessable value as they won't use password login initially.
		// If PasswordHash is empty, they can never login via password unless they set one.
		PasswordHash: "", // Or generate a secure random hash: s.passwordHasher.Hash(uuid.NewString())
	}
	if err := s.userRepo.CreateUser(ctx, newUser); err != nil {
		// Handle email collision if, by chance, email was created between check and now
		if strings.Contains(err.Error(), "already exists") { // Or mongo.IsDuplicateKeyError(err)
			// This is rare but possible. Treat as merge scenario or ask user to try again.
			// For simplicity, error out here. A more robust flow would re-query and offer merge.
			log.Warn().Err(err).Str("email", newUser.Email).Msg("Failed to create new federated user due to email collision")
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("email associated with this provider is already in use by another local account"))
		}
		log.Error().Err(err).Msg("Failed to create new user during federated callback")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create user account"))
	}

	// Now link the new local user to the federated identity
	newLink := &domain.UserFederatedIdentity{
		UserID:           newUser.ID,
		ProviderID:       providerID,
		ProviderUserID:   externalUser.ProviderUserID,
		ProviderEmail:    externalUser.Email,
		ProviderUsername: externalUser.Username,
	}
	if err := s.fedIDRepo.Create(ctx, newLink); err != nil {
		log.Error().Err(err).Str("userID", newUser.ID).Msg("Failed to link federated identity to newly created user")
		// Potentially rollback user creation or mark user for cleanup. For now, error out.
		// This would leave an orphaned user if not handled.
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to link account after user creation"))
	}

	log.Info().Str("userID", newUser.ID).Str("email", newUser.Email).Str("provider", req.Msg.ProviderName).Msg("New user created and linked via federation.")
	return s.completeLoginAndRespond(ctx, newUser, ssov1.HandleFederatedCallbackResponse_LOGIN_SUCCESSFUL, "Account created and login successful.")

	// Placeholder for NEW_USER_REGISTRATION_REQUIRED if not auto-creating
	// continuationToken := uuid.NewString()
	// TODO: Store externalUser info and providerName with continuationToken for registration completion step
	// return connect.NewResponse(&ssov1.HandleFederatedCallbackResponse{
	// 	Status: ssov1.HandleFederatedCallbackResponse_NEW_USER_REGISTRATION_REQUIRED,
	// 	Message: "No existing account. Please complete registration.",
	// 	ProviderUserId: externalUser.ProviderUserID,
	// 	ProviderEmail: externalUser.Email,
	// 	ProviderName: req.Msg.ProviderName,
	// 	ContinuationToken: continuationToken,
	// }), nil
}

// completeLoginAndRespond is a helper to finalize session and token generation.
func (s *FederationServer) completeLoginAndRespond(ctx context.Context, user *domain.User, status ssov1.HandleFederatedCallbackResponse_Status, message string) (*connect.Response[ssov1.HandleFederatedCallbackResponse], error) {
	// TODO: Get client_id and scope from somewhere appropriate for this login session.
	// This might be a default client_id for the SSO system itself.
	clientID := "sso-default-client" // Example
	scope := "openid profile email offline_access"

	tokenPair, err := s.tokenService.GenerateTokenPair(ctx, clientID, user.ID, scope, 1*time.Hour)
	if err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("Failed to generate token pair in federated login")
		return nil, connect.NewError(connect.CodeInternal, errors.New("token generation failed"))
	}

	// Create and store session
	session := &domain.Session{
		UserID: user.ID,
		// TokenID should be JTI of access token if available
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour), // Long session for refresh token
	}
	if err := s.sessionRepo.StoreSession(ctx, session); err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("Failed to store session in federated login")
		// Non-fatal for login response itself, but an issue.
	}

	// Update LastLoginAt for user
	now := time.Now()
	user.LastLoginAt = &now
	user.FailedLoginAttempts = 0
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		log.Warn().Err(err).Str("userID", user.ID).Msg("Failed to update user LastLoginAt in federated login")
	}

	protoUser := &ssov1.User{
		Id:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Status:    mapDomainStatusToProto(user.Status), // mapDomainStatusToProto needs to be accessible
		Roles:     user.Roles,
	}
	if !user.CreatedAt.IsZero() {
		protoUser.CreatedAt = timestamppb.New(user.CreatedAt)
	}
	if !user.UpdatedAt.IsZero() {
		protoUser.UpdatedAt = timestamppb.New(user.UpdatedAt)
	}
	if user.LastLoginAt != nil && !user.LastLoginAt.IsZero() {
		protoUser.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}

	return connect.NewResponse(&ssov1.HandleFederatedCallbackResponse{
		Status:       status,
		Message:      message,
		AccessToken:  tokenPair.AccessToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    int32(tokenPair.ExpiresIn),
		RefreshToken: tokenPair.RefreshToken,
		UserInfo:     protoUser,
		IdToken:      tokenPair.IDToken,
	}), nil
}

// ListUserFederatedIdentities lists linked federated identities for the authenticated user.
func (s *FederationServer) ListUserFederatedIdentities(ctx context.Context, req *connect.Request[ssov1.ListUserFederatedIdentitiesRequest]) (*connect.Response[ssov1.ListUserFederatedIdentitiesResponse], error) {
	authToken, ok := middleware.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	identities, err := s.fedIDRepo.ListByUserID(ctx, authToken.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", authToken.UserID).Msg("Failed to list federated identities")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not retrieve linked accounts"))
	}

	respIdentities := make([]*ssov1.FederatedIdentityInfo, 0, len(identities))
	for _, ident := range identities {
		providerConfig, err := s.idpRepo.GetIdPByID(ctx, ident.ProviderID)
		providerName := ident.ProviderID // Fallback to ID if name not found
		if err == nil && providerConfig != nil {
			providerName = providerConfig.Name
		}

		respIdentities = append(respIdentities, &ssov1.FederatedIdentityInfo{
			Id:               ident.ID,
			ProviderId:       ident.ProviderID,
			ProviderName:     providerName,
			ProviderUserId:   ident.ProviderUserID,
			ProviderEmail:    ident.ProviderEmail,
			ProviderUsername: ident.ProviderUsername,
			CreatedAt:        timestamppb.New(ident.CreatedAt),
		})
	}

	return connect.NewResponse(&ssov1.ListUserFederatedIdentitiesResponse{
		Identities: respIdentities,
	}), nil
}

// RemoveUserFederatedIdentity unlinks an external identity for the authenticated user.
func (s *FederationServer) RemoveUserFederatedIdentity(ctx context.Context, req *connect.Request[ssov1.RemoveUserFederatedIdentityRequest]) (*connect.Response[emptypb.Empty], error) {
	authToken, ok := middleware.GetAuthenticatedTokenFromContext(ctx)
	if !ok || authToken == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}

	if req.Msg.ProviderName == "" || req.Msg.ProviderUserIdToRemove == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("provider_name and provider_user_id_to_remove are required"))
	}

	// We need to find the specific link ID to delete, or use DeleteByUserIDAndProvider.
	// Using DeleteByUserIDAndProvider is simpler if we trust provider_name.
	// However, the proto has ProviderUserIdToRemove, implying we might need to list and find the internal ID first
	// if the client doesn't have it. Let's assume for now that the client knows ProviderName and the external ProviderUserID.

	// Alternative: if client sends the internal link ID (FederatedIdentityInfo.Id), then use fedIDRepo.Delete(ctx, linkId)

	// Find the link first to confirm it belongs to the user and to get its internal ID if needed.
	fedIdentity, err := s.fedIDRepo.GetByProviderUserID(ctx, req.Msg.ProviderName, req.Msg.ProviderUserIdToRemove)
	if err != nil || fedIdentity == nil {
		log.Warn().Err(err).Str("provider", req.Msg.ProviderName).Str("providerUserID", req.Msg.ProviderUserIdToRemove).Msg("Federated identity to remove not found")
		return nil, connect.NewError(connect.CodeNotFound, errors.New("federated identity link not found"))
	}

	// Ensure the found identity belongs to the currently authenticated user.
	if fedIdentity.UserID != authToken.UserID {
		log.Warn().Str("authedUserID", authToken.UserID).Str("linkUserID", fedIdentity.UserID).Msg("User attempting to remove a federated link not belonging to them")
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied to remove this federated identity"))
	}

	// At this point, we have confirmed the link exists and belongs to the user.
	// We can delete it by its internal ID (fedIdentity.ID) or by UserID+ProviderName.
	// Using fedIdentity.ID is more precise.
	err = s.fedIDRepo.Delete(ctx, fedIdentity.ID)
	if err != nil {
		log.Error().Err(err).Str("linkID", fedIdentity.ID).Msg("Failed to remove federated identity")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to remove linked account"))
	}

	log.Info().Str("userID", authToken.UserID).Str("provider", req.Msg.ProviderName).Msg("Federated identity removed")
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// PromptMergeFederatedAccount provides information for a user to decide on merging.
func (s *FederationServer) PromptMergeFederatedAccount(ctx context.Context, req *connect.Request[ssov1.PromptMergeFederatedAccountRequest]) (*connect.Response[ssov1.PromptMergeFederatedAccountResponse], error) {
	if req.Msg.ContinuationToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("continuation_token is required"))
	}

	cachedItem := s.continuationCache.Get(req.Msg.ContinuationToken)
	if cachedItem == nil || cachedItem.Value() == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("invalid or expired continuation_token"))
	}
	cachedInfo := cachedItem.Value()

	if cachedInfo.ExistingLocalUser == nil || cachedInfo.ExternalUser == nil {
		log.Warn().Str("token", req.Msg.ContinuationToken).Msg("Continuation token data is incomplete for merge prompt.")
		s.continuationCache.Delete(req.Msg.ContinuationToken) // Clean up invalid token
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("invalid continuation state for merge"))
	}

	return connect.NewResponse(&ssov1.PromptMergeFederatedAccountResponse{
		Message: fmt.Sprintf("An account with email %s already exists. Do you want to link your %s account (from %s) to it? Linking will allow you to sign in with %s.",
			cachedInfo.ExistingLocalUser.Email, cachedInfo.ExternalUser.Email, cachedInfo.ProviderName, cachedInfo.ProviderName),
		ExistingLocalUserEmail: cachedInfo.ExistingLocalUser.Email,
		ProviderName:           cachedInfo.ProviderName,
	}), nil
}

// ConfirmMergeFederatedAccount finalizes the linking of a federated identity to an existing local account.
// SIMPLIFICATION: This does not currently implement a separate email verification loop for the local existing account owner.
// It assumes consent from the user performing the federated login is sufficient for this iteration.
func (s *FederationServer) ConfirmMergeFederatedAccount(ctx context.Context, req *connect.Request[ssov1.ConfirmMergeFederatedAccountRequest]) (*connect.Response[ssov1.HandleFederatedCallbackResponse], error) {
	if req.Msg.ContinuationToken == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("continuation_token is required"))
	}

	cachedItem := s.continuationCache.Get(req.Msg.ContinuationToken)
	if cachedItem == nil || cachedItem.Value() == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("invalid or expired continuation_token"))
	}
	cachedInfo := cachedItem.Value()
	s.continuationCache.Delete(req.Msg.ContinuationToken) // Consume the token

	if cachedInfo.ExistingLocalUser == nil || cachedInfo.ExternalUser == nil || cachedInfo.ProviderID == "" {
		log.Error().Str("token", req.Msg.ContinuationToken).Msg("Continuation token data is incomplete for merge confirmation.")
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("invalid continuation state for merge"))
	}

	// Ensure the local user account still exists and is in a mergeable state.
	localUser, err := s.userRepo.GetUserByID(ctx, cachedInfo.ExistingLocalUser.ID)
	if err != nil || localUser == nil {
		log.Error().Err(err).Str("localUserID", cachedInfo.ExistingLocalUser.ID).Msg("Local user for merge not found or error retrieving.")
		return nil, connect.NewError(connect.CodeNotFound, errors.New("original local account not found"))
	}
	// Potentially check localUser.Status here if relevant.

	// Check if this local user is ALREADY linked to this specific provider with a DIFFERENT external ID.
	// This would be a conflict that should ideally be caught earlier, but double-check.
	existingLink, _ := s.fedIDRepo.GetByUserIDAndProvider(ctx, localUser.ID, cachedInfo.ProviderName)
	if existingLink != nil && existingLink.ProviderUserID != cachedInfo.ExternalUser.ProviderUserID {
		log.Warn().Str("localUserID", localUser.ID).Str("provider", cachedInfo.ProviderName).
			Str("existingExternalID", existingLink.ProviderUserID).Str("newExternalID", cachedInfo.ExternalUser.ProviderUserID).
			Msg("Merge conflict: Local user already linked to this provider with a different external ID.")
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("this local account is already linked to a different %s account", cachedInfo.ProviderName))
	}
	// If existingLink.ProviderUserID == cachedInfo.ExternalUser.ProviderUserID, it means it was already linked.
	if existingLink != nil && existingLink.ProviderUserID == cachedInfo.ExternalUser.ProviderUserID {
		log.Info().Str("userID", localUser.ID).Str("provider", cachedInfo.ProviderName).Msg("Account already merged/linked. Proceeding to login.")
		return s.completeLoginAndRespond(ctx, localUser, ssov1.HandleFederatedCallbackResponse_LOGIN_SUCCESSFUL, "Account already linked. Login successful.")
	}

	// Create the new federated identity link
	newLink := &domain.UserFederatedIdentity{
		UserID:           localUser.ID,
		ProviderID:       cachedInfo.ProviderID,
		ProviderUserID:   cachedInfo.ExternalUser.ProviderUserID,
		ProviderEmail:    cachedInfo.ExternalUser.Email,
		ProviderUsername: cachedInfo.ExternalUser.Username,
		// TODO: Store AccessToken, RefreshToken from cachedInfo.ExternalToken if needed (encrypted)
	}

	err = s.fedIDRepo.Create(ctx, newLink)
	if err != nil {
		// This might happen if, due to a race or previous error, the link was created by another request.
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "duplicate key") {
			log.Info().Str("userID", localUser.ID).Str("provider", cachedInfo.ProviderName).Msg("Federated link creation conflict, assuming already linked.")
			// Proceed to login as if already linked.
		} else {
			log.Error().Err(err).Str("userID", localUser.ID).Str("provider", cachedInfo.ProviderName).Msg("Failed to link federated identity during merge confirmation")
			return nil, connect.NewError(connect.CodeInternal, errors.New("failed to link account"))
		}
	}

	log.Info().Str("userID", localUser.ID).Str("provider", cachedInfo.ProviderName).Msg("Account merged successfully.")
	return s.completeLoginAndRespond(ctx, localUser, ssov1.HandleFederatedCallbackResponse_ACCOUNT_LINKED_LOGIN, "Accounts merged and login successful.")
}

// Ensure FederationServer implements ssov1connect.FederationServiceHandler
var _ ssov1connect.FederationServiceHandler = (*FederationServer)(nil)
