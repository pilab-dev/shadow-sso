package services

import (
	"context"
	// "time" // No longer directly needed by this file after removing TokenServiceAuth
	"github.com/pilab-dev/shadow-sso/ssso" // Import for ssso.TokenService

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/sso/v1/ssov1connect"
	"google.golang.org/protobuf/types/known/emptypb"
	// Add other necessary imports like session repository
)

// AuthServer implements the ssov1connect.AuthServiceHandler interface.
type AuthServer struct {
	ssov1connect.UnimplementedAuthServiceHandler // Embed for forward compatibility
	userRepo       domain.UserRepository
	sessionRepo    domain.SessionRepository // Added SessionRepository
	tokenService   *ssso.TokenService
	passwordHasher PasswordHasher
}

// NewAuthServer creates a new AuthServer.
func NewAuthServer(
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository, // Added SessionRepository
	tokenService *ssso.TokenService,
	passwordHasher PasswordHasher,
) *AuthServer {
	return &AuthServer{
		userRepo:       userRepo,
		sessionRepo:    sessionRepo, // Initialize SessionRepository
		tokenService:   tokenService,
		passwordHasher: passwordHasher,
	}
}

func (s *AuthServer) Login(ctx context.Context, req *connect.Request[ssov1.LoginRequest]) (*connect.Response[ssov1.LoginResponse], error) {
	// 1. Validate input (email, password)
	// 2. Fetch user by email from userRepo
	// 3. Compare password hash using passwordHasher
	// 4. If valid, create session (store in sessionRepo)
	// 5. Generate JWT using tokenService
	// 6. Return LoginResponse with token and user info
	return nil, connect.NewError(connect.CodeUnimplemented, "Login not implemented")
}

func (s *AuthServer) Logout(ctx context.Context, req *connect.Request[ssov1.LogoutRequest]) (*connect.Response[emptypb.Empty], error) {
	// 1. Get token from context (added by auth interceptor)
	// 2. Validate token (e.g., get JTI or session ID)
	// 3. Invalidate session in sessionRepo (e.g., mark as revoked or delete)
	// 4. Optionally add token JTI to a denylist cache
	return nil, connect.NewError(connect.CodeUnimplemented, "Logout not implemented")
}

func (s *AuthServer) ListUserSessions(ctx context.Context, req *connect.Request[ssov1.ListUserSessionsRequest]) (*connect.Response[ssov1.ListUserSessionsResponse], error) {
	// 1. Get authenticated user_id from context
	// 2. Check permissions: if req.UserId is different from authenticated user_id, ensure admin privileges
	// 3. Fetch sessions from sessionRepo for req.UserId
	// 4. Convert to ssov1.SessionInfo
	return nil, connect.NewError(connect.CodeUnimplemented, "ListUserSessions not implemented")
}

func (s *AuthServer) ClearUserSessions(ctx context.Context, req *connect.Request[ssov1.ClearUserSessionsRequest]) (*connect.Response[emptypb.Empty], error) {
	// 1. Get authenticated user_id from context
	// 2. Check permissions: if req.UserId is different from authenticated user_id, ensure admin privileges
	// 3. If req.SessionIds is empty, clear all sessions for req.UserId from sessionRepo
	// 4. Else, clear specified session_ids for req.UserId
	return nil, connect.NewError(connect.CodeUnimplemented, "ClearUserSessions not implemented")
}

// Ensure AuthServer implements ssov1connect.AuthServiceHandler
var _ ssov1connect.AuthServiceHandler = (*AuthServer)(nil)
