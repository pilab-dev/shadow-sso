package services

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	// "github.com/pilab-dev/shadow-sso/internal/metrics" // Unused for now as RegisterUser is not fully implemented
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"google.golang.org/protobuf/types/known/emptypb"
	// Add other necessary imports like user repository, password hasher
)

// UserServer implements the ssov1connect.UserServiceHandler interface.
type UserServer struct {
	ssov1connect.UnimplementedUserServiceHandler // Embed for forward compatibility
	userRepo                                     domain.UserRepository
	passwordHasher                               PasswordHasher
}

// NewUserServer creates a new UserServer.
func NewUserServer(userRepo domain.UserRepository, hasher PasswordHasher) *UserServer {
	return &UserServer{
		userRepo:       userRepo,
		passwordHasher: hasher,
	}
}

func (s *UserServer) RegisterUser(ctx context.Context, req *connect.Request[ssov1.RegisterUserRequest]) (*connect.Response[ssov1.RegisterUserResponse], error) {
	// Example: Get current user from context if available (for who performed the action)
	// actingUser := domain.UserFromContext(ctx) // Assuming you have a way to get this
	// actingUserID := ""
	// if actingUser != nil {
	// 	actingUserID = actingUser.ID
	// }

	// 1. Validate input (email, password, names)
	if req.Msg.GetEmail() == "" || req.Msg.GetPassword() == "" {
		err := errors.New("email and password are required")
		audit.Log("UserService", "RegisterUser", "", req.Msg.GetEmail(), "Validation failed", false, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// 2. Check if user already exists with userRepo.GetUserByEmail
	// existingUser, err := s.userRepo.GetUserByEmail(ctx, req.Msg.GetEmail())
	// if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
	// 	audit.Log("UserService", "RegisterUser", "", req.Msg.GetEmail(), "Failed to check existing user", false, err)
	// 	return nil, connect.NewError(connect.CodeInternal, err)
	// }
	// if existingUser != nil {
	// 	err = errors.New("user already exists")
	// 	audit.Log("UserService", "RegisterUser", "", req.Msg.GetEmail(), "User already exists", false, err)
	// 	return nil, connect.NewError(connect.CodeAlreadyExists, err)
	// }

	// 3. Hash password using passwordHasher
	// hashedPassword, err := s.passwordHasher.Hash(req.Msg.GetPassword())
	// if err != nil {
	// 	audit.Log("UserService", "RegisterUser", "", req.Msg.GetEmail(), "Failed to hash password", false, err)
	// 	return nil, connect.NewError(connect.CodeInternal, errors.New("failed to process password"))
	// }

	// 4. Create domain.User struct
	// newUser := &domain.User{
	// 	Email:        req.Msg.GetEmail(),
	// 	PasswordHash: hashedPassword,
	// 	FirstName:    req.Msg.GetFirstName(),
	// 	LastName:     req.Msg.GetLastName(),
	// 	Status:       domain.UserStatusPendingActivation, // Or UserStatusActive if auto-activated
	// }

	// 5. Save user with userRepo.CreateUser
	// createdUser, err := s.userRepo.CreateUser(ctx, newUser)
	// if err != nil {
	// 	audit.Log("UserService", "RegisterUser", "", req.Msg.GetEmail(), "Failed to create user in repository", false, err)
	// 	return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create user"))
	// }

	// audit.Log("UserService", "RegisterUser", "", createdUser.ID, "User registered successfully", true, nil)
	//  metrics.UserRegisteredTotal.Inc()

	// 6. Convert to ssov1.User and return in RegisterUserResponse
	// return connect.NewResponse(&ssov1.RegisterUserResponse{User: &ssov1.User{Id: createdUser.ID, Email: createdUser.Email /* ... other fields ... */}}), nil
	audit.Log("UserService", "RegisterUser", "", req.Msg.GetEmail(), "Method not implemented", false, errors.New("RegisterUser not implemented"))
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("RegisterUser not implemented"))
}

func (s *UserServer) ActivateUser(ctx context.Context, req *connect.Request[ssov1.ActivateUserRequest]) (*connect.Response[emptypb.Empty], error) {
	// 1. Fetch user by req.UserId from userRepo
	// 2. Update user status to domain.UserStatusActive
	// 3. Save user with userRepo.UpdateUser
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ActivateUser not implemented"))
}

func (s *UserServer) LockUser(ctx context.Context, req *connect.Request[ssov1.LockUserRequest]) (*connect.Response[emptypb.Empty], error) {
	// 1. Fetch user by req.UserId from userRepo
	// 2. Update user status to domain.UserStatusLocked
	// 3. Save user with userRepo.UpdateUser
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("LockUser not implemented"))
}

func (s *UserServer) ListUsers(ctx context.Context, req *connect.Request[ssov1.ListUsersRequest]) (*connect.Response[ssov1.ListUsersResponse], error) {
	// 1. Implement pagination and filtering based on req
	// 2. Fetch users from userRepo.ListUsers
	// 3. Convert to ssov1.User
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ListUsers not implemented"))
}

func (s *UserServer) GetUser(ctx context.Context, req *connect.Request[ssov1.GetUserRequest]) (*connect.Response[ssov1.GetUserResponse], error) {
	// Example: Get current user from context if available
	// actingUser := domain.UserFromContext(ctx) // Assuming you have a way to get this
	// actingUserID := ""
	// if actingUser != nil {
	// 	actingUserID = actingUser.ID
	// }

	targetUserID := req.Msg.GetUserId()
	if targetUserID == "" {
		err := errors.New("user_id is required")
		audit.Log("UserService", "GetUser", "", "", "Validation failed: missing user_id", false, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// 1. Fetch user by req.UserId from userRepo.GetUserByID or userRepo.GetUserByEmail
	// user, err := s.userRepo.GetUserByID(ctx, targetUserID) // Or GetUserByEmail if that's the identifier
	// if err != nil {
	// 	if errors.Is(err, domain.ErrUserNotFound) {
	// 		audit.Log("UserService", "GetUser", "", targetUserID, "User not found", false, err)
	// 		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	// 	}
	// 	audit.Log("UserService", "GetUser", "", targetUserID, "Failed to get user from repository", false, err)
	// 	return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get user"))
	// }

	// audit.Log("UserService", "GetUser", "", targetUserID, "User retrieved successfully", true, nil)

	// 2. Convert to ssov1.User
	// return connect.NewResponse(&ssov1.GetUserResponse{User: &ssov1.User{Id: user.ID, Email: user.Email /* ... other fields ... */}}), nil
	audit.Log("UserService", "GetUser", "", targetUserID, "Method not implemented", false, errors.New("GetUser not implemented"))
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetUser not implemented"))
}

func (s *UserServer) ChangePassword(ctx context.Context, req *connect.Request[ssov1.ChangePasswordRequest]) (*connect.Response[emptypb.Empty], error) {
	// 1. Get authenticated user_id from context
	// 2. If req.UserId is self:
	//    a. Fetch user, verify req.OldPassword against stored hash
	// 3. Else (admin changing password for another user):
	//    a. Check admin privileges
	// 4. Hash req.NewPassword
	// 5. Update password hash in userRepo
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ChangePassword not implemented"))
}

// Ensure UserServer implements ssov1connect.UserServiceHandler
var _ ssov1connect.UserServiceHandler = (*UserServer)(nil)
