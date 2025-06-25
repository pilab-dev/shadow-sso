package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/dto" // Added DTO import
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/tracing" // Import tracing package
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute" // For span attributes
	"go.opentelemetry.io/otel/codes"     // For span status codes
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Implementation of the new UserService ---
type UserService struct {
	userStore        UserStore
	userSessionStore UserSessionStore
	passwordHasher   PasswordHasher
}

// NewUserService creates a new UserServiceImpl.
func NewUserService(userRepo UserStore, hasher PasswordHasher) *UserService {
	return &UserService{
		userStore:      userRepo,
		passwordHasher: hasher,
	}
}

func (s *UserService) CreateUser(ctx context.Context, username, password string) (*User, error) {
	if strings.TrimSpace(password) == "" || strings.TrimSpace(username) == "" {
		return nil, errors.New("both username and password is required") // Basic validation
	}

	// Check if user already exists
	if _, err := s.userStore.GetUserByUsername(ctx, username); err == nil {
		return nil, fmt.Errorf("user with username '%s' already exists", username) // Consider custom error
	}

	hashedPassword, err := s.passwordHasher.Hash(password)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash password during user creation")
		return nil, errors.New("failed to process password")
	}

	user, err := s.userStore.CreateUser(ctx, username, hashedPassword)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create user in service")

		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (s *UserService) GetUserByID(ctx context.Context, userID string) (*dto.UserResponse, error) {
	// Start a custom span
	newCtx, span := tracing.Tracer.Start(ctx, "UserService.GetUserByID")
	defer span.End()

	span.SetAttributes(attribute.String("user.id", userID))

	domainUser, err := s.userStore.GetUserByID(newCtx, userID) // Pass newCtx
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		if strings.Contains(err.Error(), "not found") { // Crude error checking
			return nil, fmt.Errorf("user not found with ID %s: %w", userID, err)
		}

		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}

	span.SetAttributes(attribute.Bool("user.found", domainUser != nil))

	return domainUser, nil
}

func (s *UserService) GetUserByEmail(ctx context.Context, username string) (*User, error) {
	domainUser, err := s.userStore.GetUserByUsername(ctx, username)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("user not found with email %s: %w", username, err)
		}

		return nil, fmt.Errorf("failed to retrieve user by email: %w", err)
	}

	return domainUser, nil
}

func (s *UserService) ListUsers(ctx context.Context) ([]*dto.UserResponse, error) {
	// Placeholder: Real implementation would need pagination and filtering
	domainUsers, _, err := s.userStore.ListUsers(ctx, "", 0) // Assuming ListUsers takes limit, offset, filter, sort
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	return dto.FromDomainUsers(domainUsers), nil
}

func (s *UserService) UpdateUser(ctx context.Context, userID string, req *dto.UserUpdateRequest) (*dto.UserResponse, error) {
	existingUser, err := s.userStore.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found for update: %w", err)
	}

	// Apply updates from DTO
	if req.Email != nil {
		// Check if new email is already taken by another user
		if otherUser, errEmail := s.userStore.GetUserByEmail(ctx, *req.Email); errEmail == nil && otherUser.ID != userID {
			return nil, fmt.Errorf("email '%s' is already in use by another account", *req.Email)
		}
		existingUser.Email = *req.Email
	}
	if req.FirstName != nil {
		existingUser.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		existingUser.LastName = *req.LastName
	}
	if req.Status != nil {
		existingUser.Status = domain.UserStatus(*req.Status) // Add validation for status values
	}
	if req.Roles != nil {
		existingUser.Roles = *req.Roles
	}
	if req.Password != nil && *req.Password != "" {
		newPasswordHash, hashErr := s.passwordHasher.Hash(*req.Password)
		if hashErr != nil {
			log.Error().Err(hashErr).Msg("Failed to hash new password during update")
			return nil, errors.New("failed to process new password")
		}
		existingUser.PasswordHash = newPasswordHash
	}

	if err := s.userStore.UpdateUser(ctx, existingUser); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	return dto.FromDomainUser(existingUser), nil
}

func (s *UserService) ActivateUser(ctx context.Context, userID string) error {
	user, err := s.userStore.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	user.Status = domain.UserStatusActive
	return s.userStore.UpdateUser(ctx, user)
}

func (s *UserService) LockUser(ctx context.Context, userID string) error {
	user, err := s.userStore.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	user.Status = domain.UserStatusLocked
	return s.userStore.UpdateUser(ctx, user)
}

func (s *UserService) ChangePassword(ctx context.Context, userID string, oldPassword string, newPassword string) error {
	user, err := s.userStore.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	if !s.passwordHasher.Verify(user.PasswordHash, oldPassword) {
		return errors.New("old password does not match") // Consider custom error
	}
	newPasswordHash, hashErr := s.passwordHasher.Hash(newPassword)
	if hashErr != nil {
		return errors.New("failed to process new password")
	}
	user.PasswordHash = newPasswordHash
	return s.userStore.UpdateUser(ctx, user)
}

// --- UserServer (RPC Handler) ---
type UserServer struct {
	ssov1connect.UnimplementedUserServiceHandler
	service UserService
}

// NewUserServer creates a new UserServer RPC handler.
func NewUserServer(service UserService) *UserServer {
	return &UserServer{
		service: service,
	}
}

// Helper to convert domain.User (via dto.UserResponse) to ssov1.User
func dtoUserResponseToProto(userResp *dto.UserResponse) *ssov1.User {
	if userResp == nil {
		return nil
	}
	protoUser := &ssov1.User{
		Id:                 userResp.ID,
		Email:              userResp.Email,
		FirstName:          userResp.FirstName,
		LastName:           userResp.LastName,
		Roles:              userResp.Roles,
		IsTwoFactorEnabled: userResp.IsTwoFactorEnabled,
		TwoFactorMethod:    userResp.TwoFactorMethod,
		// FIXME: the user status type is different in domain
		Status: 0, // string(userResp.Status), // Assuming ssov1.User.Status is string
	}
	if !userResp.CreatedAt.IsZero() {
		protoUser.CreatedAt = timestamppb.New(userResp.CreatedAt)
	}
	if !userResp.UpdatedAt.IsZero() {
		protoUser.UpdatedAt = timestamppb.New(userResp.UpdatedAt)
	}
	if userResp.LastLoginAt != nil && !userResp.LastLoginAt.IsZero() {
		protoUser.LastLoginAt = timestamppb.New(*userResp.LastLoginAt)
	}
	return protoUser
}

func (s *UserServer) RegisterUser(ctx context.Context, req *connect.Request[ssov1.RegisterUserRequest]) (*connect.Response[ssov1.RegisterUserResponse], error) {
	dtoReq := &dto.UserCreateRequest{
		Email:     req.Msg.Email,
		Password:  req.Msg.Password,
		FirstName: req.Msg.FirstName,
		LastName:  req.Msg.LastName,
		Roles:     []string{},
	}
	dtoResp, err := s.service.CreateUser(ctx, dtoReq)
	if err != nil {
		// TODO: Map service errors to connect errors
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("registration failed: %w", err))
	}
	return connect.NewResponse(&ssov1.RegisterUserResponse{User: dtoUserResponseToProto(dtoResp)}), nil
}

func (s *UserServer) GetUser(ctx context.Context, req *connect.Request[ssov1.GetUserRequest]) (*connect.Response[ssov1.GetUserResponse], error) {
	var (
		dtoResp *dto.UserResponse
		err     error
	)
	if req.Msg.GetUserId() != "" {
		dtoResp, err = s.service.GetUserByID(ctx, req.Msg.GetUserId())
		if err != nil {
			// try it with email too
			dtoResp, err = s.service.GetUserByEmail(ctx, req.Msg.GetUserId())
		}
	} else {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("either user_id or email must be provided"))
	}

	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ssov1.GetUserResponse{User: dtoUserResponseToProto(dtoResp)}), nil
}

func (s *UserServer) ListUsers(ctx context.Context, req *connect.Request[ssov1.ListUsersRequest]) (*connect.Response[ssov1.ListUsersResponse], error) {
	// Pagination and filtering from req.Msg should be passed to s.service.ListUsers
	dtoResps, err := s.service.ListUsers(ctx /* pass params here */)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	protoUsers := make([]*ssov1.User, len(dtoResps))
	for i, dtoResp := range dtoResps {
		protoUsers[i] = dtoUserResponseToProto(dtoResp)
	}
	return connect.NewResponse(&ssov1.ListUsersResponse{Users: protoUsers /* Add NextPageToken if applicable */}), nil
}

func (s *UserServer) ActivateUser(ctx context.Context, req *connect.Request[ssov1.ActivateUserRequest]) (*connect.Response[emptypb.Empty], error) {
	if req.Msg.UserId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("user_id is required"))
	}
	err := s.service.ActivateUser(ctx, req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) LockUser(ctx context.Context, req *connect.Request[ssov1.LockUserRequest]) (*connect.Response[emptypb.Empty], error) {
	if req.Msg.UserId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("user_id is required"))
	}
	err := s.service.LockUser(ctx, req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) ChangePassword(ctx context.Context, req *connect.Request[ssov1.ChangePasswordRequest]) (*connect.Response[emptypb.Empty], error) {
	// This RPC implies the user is changing their own password.
	// UserID should be extracted from authenticated context, not from request for self-change.
	// For admin changing password, a different RPC/check is needed.
	// For now, assume req.UserId is the target user, and auth checks happen upstream or are missing.
	if req.Msg.UserId == "" { // Should be from context for self, or explicit for admin
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("user_id is required"))
	}
	if req.Msg.NewPassword == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("new_password is required"))
	}

	// This simplified ChangePassword in service doesn't distinguish self-service vs admin.
	// A real implementation would need that distinction.
	err := s.service.ChangePassword(ctx, req.Msg.UserId, req.Msg.OldPassword, req.Msg.NewPassword)
	if err != nil {
		// TODO: Map specific errors (like "old password does not match") to appropriate connect codes
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// // UpdateUser RPC (Placeholder, not fully implemented in this pass, depends on ssov1.UpdateUserRequest fields)
// func (s *UserServer) UpdateUser(ctx context.Context, req *connect.Request[ssov1.UpdateUserRequest]) (*connect.Response[ssov1.UpdateUserResponse], error) {
// 	if req.Msg.GetId() == "" {
// 		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("user id is required for update"))
// 	}

// 	dtoUpdateReq := &dto.UserUpdateRequest{}
// 	// Simplified mapping from ssov1.UpdateUserRequest to dto.UserUpdateRequest
// 	// Assumes ssov1.UpdateUserRequest has fields like Email, FirstName, LastName, Roles, Status
// 	// Proper mapping requires checking for presence of fields if using proto3 optionals or field masks.

// 	// Example:
// 	// if req.Msg.GetEmail() != "" { // Or check FieldMask
// 	//	email := req.Msg.GetEmail()
// 	//	dtoUpdateReq.Email = &email
// 	// }
// 	// ... map other fields ...
// 	// For now, this part is conceptual as ssov1.UpdateUserRequest is not fully known.
// 	// Let's assume it has some fields for demonstration if we were to implement it.
// 	// if req.Msg.FirstName != "" { dtoUpdateReq.FirstName = &req.Msg.FirstName }
// 	// if req.Msg.LastName != "" { dtoUpdateReq.LastName = &req.Msg.LastName }

// 	if req.Msg.GetUpdateMask() != nil { // Example if using FieldMask
// 		for _, path := range req.Msg.GetUpdateMask().GetPaths() {
// 			switch path {
// 			case "email":
// 				email := req.Msg.GetUser().GetEmail() // Assuming updated fields are in a User sub-message
// 				dtoUpdateReq.Email = &email
// 			case "first_name":
// 				fname := req.Msg.GetUser().GetFirstName()
// 				dtoUpdateReq.FirstName = &fname
// 			case "last_name":
// 				lname := req.Msg.GetUser().GetLastName()
// 				dtoUpdateReq.LastName = &lname
// 			case "roles":
// 				roles := req.Msg.GetUser().GetRoles()
// 				dtoUpdateReq.Roles = &roles
// 			case "status":
// 				status := req.Msg.GetUser().GetStatus()
// 				dtoUpdateReq.Status = &status
// 				// Add more cases for other updatable fields
// 			}
// 		}
// 	} else {
// 		// If no field mask, this implies a full update or specific fields are set.
// 		// This part is highly dependent on the design of ssov1.UpdateUserRequest.
// 		// For this refactor, we'll assume it's not fully implemented yet.
// 		log.Warn().Msg("UpdateUser RPC called but mapping from ssov1.UpdateUserRequest to DTO is partial/conceptual.")
// 		// Fallback to a Get and return if no actual update fields are mapped.
// 		// This is just to make it compile and show structure.
// 		dtoResp, err := s.service.GetUserByID(ctx, req.Msg.GetId())
// 		if err != nil { /* handle error */
// 		}
// 		return connect.NewResponse(&ssov1.UpdateUserResponse{User: dtoUserResponseToProto(dtoResp)}),
// 			connect.NewError(connect.CodeUnimplemented, errors.New("UpdateUser mapping from proto to DTO not fully implemented"))
// 	}

// 	dtoResp, err := s.service.UpdateUser(ctx, req.Msg.GetId(), dtoUpdateReq)
// 	if err != nil {
// 		return nil, connect.NewError(connect.CodeInternal, err)
// 	}
// 	return connect.NewResponse(&ssov1.UpdateUserResponse{User: dtoUserResponseToProto(dtoResp)}), nil
// }

// Ensure UserServer implements ssov1connect.UserServiceHandler
var _ ssov1connect.UserServiceHandler = (*UserServer)(nil)
