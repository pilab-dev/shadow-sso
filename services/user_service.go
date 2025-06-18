package services

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/sso/v1/ssov1connect"
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
	// 1. Validate input (email, password, names)
	// 2. Check if user already exists with userRepo.GetUserByEmail
	// 3. Hash password using passwordHasher
	// 4. Create domain.User struct
	// 5. Save user with userRepo.CreateUser
	// 6. Convert to ssov1.User and return in RegisterUserResponse
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
	// 1. Fetch user by req.UserId from userRepo.GetUserByID or userRepo.GetUserByEmail
	// 2. Convert to ssov1.User
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
