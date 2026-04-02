package services

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	passwordHasher                               domain.PasswordHasher
	phoneVerificationService                     *domain.PhoneVerificationService
}

// mapUserStatusToProto maps domain.UserStatus to ssov1.UserStatus
func mapUserStatusToProto(ds domain.UserStatus) ssov1.UserStatus {
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

// NewUserServer creates a new UserServer.
func NewUserServer(userRepo domain.UserRepository, hasher domain.PasswordHasher, phoneVerificationService *domain.PhoneVerificationService) *UserServer {
	return &UserServer{
		userRepo:                 userRepo,
		passwordHasher:           hasher,
		phoneVerificationService: phoneVerificationService,
	}
}

// RegisterUser registers a new user with the provided details.
func (s *UserServer) RegisterUser(ctx context.Context, req *connect.Request[ssov1.RegisterUserRequest]) (*connect.Response[ssov1.RegisterUserResponse], error) {
	// Get acting user from context (could be a service account acting on behalf of a user)
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		audit.Log("UserService", "RegisterUser", "", req.Msg.GetEmail(), "Authentication required", false, err)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	// 1. Validate input (email, password, names)
	if req.Msg.GetEmail() == "" || req.Msg.GetPassword() == "" {
		err := errors.New("email and password are required")
		audit.Log("UserService", "RegisterUser", actingUserID, req.Msg.GetEmail(), "Validation failed", false, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// 2. Check if user already exists with userRepo.GetUserByEmail
	existingUser, err := s.userRepo.GetUserByEmail(ctx, req.Msg.GetEmail())
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		audit.Log("UserService", "RegisterUser", actingUserID, req.Msg.GetEmail(), "Failed to check existing user", false, err)
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if existingUser != nil {
		err = errors.New("user already exists")
		audit.Log("UserService", "RegisterUser", actingUserID, req.Msg.GetEmail(), "User already exists", false, err)
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	}

	// 3. Hash password using passwordHasher
	hashedPassword, err := s.passwordHasher.Hash(req.Msg.GetPassword())
	if err != nil {
		audit.Log("UserService", "RegisterUser", actingUserID, req.Msg.GetEmail(), "Failed to hash password", false, err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to process password"))
	}

	// 4. Create domain.User struct
	newUser := &domain.User{
		Email:        req.Msg.GetEmail(),
		PasswordHash: hashedPassword,
		FirstName:    req.Msg.GetFirstName(),
		LastName:     req.Msg.GetLastName(),
		Status:       domain.UserStatusPending, // Require activation
		Roles:        []string{"user"},         // Default role
	}

	// 5. Save user with userRepo.CreateUser
	err = s.userRepo.CreateUser(ctx, newUser)
	if err != nil {
		audit.Log("UserService", "RegisterUser", actingUserID, req.Msg.GetEmail(), "Failed to create user in repository", false, err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create user"))
	}

	audit.Log("UserService", "RegisterUser", actingUserID, newUser.ID, "User registered successfully", true, nil)

	// 6. Convert to ssov1.User and return in RegisterUserResponse
	userProto := &ssov1.User{
		Id:        newUser.ID,
		Email:     newUser.Email,
		FirstName: newUser.FirstName,
		LastName:  newUser.LastName,
		Status:    mapUserStatusToProto(newUser.Status),
		Roles:     newUser.Roles,
	}

	return connect.NewResponse(&ssov1.RegisterUserResponse{User: userProto}), nil
}

// ActivateUser activates a user account.
func (s *UserServer) ActivateUser(ctx context.Context, req *connect.Request[ssov1.ActivateUserRequest]) (*connect.Response[emptypb.Empty], error) {
	// Get acting user from context
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		audit.Log("UserService", "ActivateUser", "", req.Msg.GetUserId(), "Authentication required", false, err)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	userID := req.Msg.GetUserId()
	if userID == "" {
		err := errors.New("user_id is required")
		audit.Log("UserService", "ActivateUser", actingUserID, "", "Validation failed: missing user_id", false, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// 1. Fetch user by req.UserId from userRepo
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			audit.Log("UserService", "ActivateUser", actingUserID, userID, "User not found", false, err)
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		audit.Log("UserService", "ActivateUser", actingUserID, userID, "Failed to get user", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	// 2. Check if user is already active
	if user.Status == domain.UserStatusActive {
		err := errors.New("user is already active")
		audit.Log("UserService", "ActivateUser", actingUserID, userID, "User already active", false, err)
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	// 3. Update user status to domain.UserStatusActive
	user.Status = domain.UserStatusActive
	user.UpdatedAt = time.Now()

	// 4. Save user with userRepo.UpdateUser
	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		audit.Log("UserService", "ActivateUser", actingUserID, userID, "Failed to update user", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user: %w", err))
	}

	audit.Log("UserService", "ActivateUser", actingUserID, userID, "User activated successfully", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// LockUser locks a user account.
func (s *UserServer) LockUser(ctx context.Context, req *connect.Request[ssov1.LockUserRequest]) (*connect.Response[emptypb.Empty], error) {
	// Get acting user from context
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		audit.Log("UserService", "LockUser", "", req.Msg.GetUserId(), "Authentication required", false, err)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	userID := req.Msg.GetUserId()
	if userID == "" {
		err := errors.New("user_id is required")
		audit.Log("UserService", "LockUser", actingUserID, "", "Validation failed: missing user_id", false, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// 1. Fetch user by req.UserId from userRepo
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			audit.Log("UserService", "LockUser", actingUserID, userID, "User not found", false, err)
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		audit.Log("UserService", "LockUser", actingUserID, userID, "Failed to get user", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	// 2. Check if user is already locked
	if user.Status == domain.UserStatusLocked {
		err := errors.New("user is already locked")
		audit.Log("UserService", "LockUser", actingUserID, userID, "User already locked", false, err)
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}

	// 3. Update user status to domain.UserStatusLocked
	user.Status = domain.UserStatusLocked
	user.UpdatedAt = time.Now()

	// 4. Save user with userRepo.UpdateUser
	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		audit.Log("UserService", "LockUser", actingUserID, userID, "Failed to update user", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user: %w", err))
	}

	audit.Log("UserService", "LockUser", actingUserID, userID, "User locked successfully", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// ListUsers lists users with pagination.
func (s *UserServer) ListUsers(ctx context.Context, req *connect.Request[ssov1.ListUsersRequest]) (*connect.Response[ssov1.ListUsersResponse], error) {
	// Get acting user from context
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		audit.Log("UserService", "ListUsers", "", "", "Authentication required", false, err)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	// 1. Get pagination parameters
	pageSize := int(req.Msg.GetPageSize())
	if pageSize <= 0 {
		pageSize = 50 // Default page size
	}
	if pageSize > 100 {
		pageSize = 100 // Max page size
	}

	pageToken := req.Msg.GetPageToken()

	// 2. Fetch users from userRepo.ListUsers
	users, nextPageToken, err := s.userRepo.ListUsers(ctx, pageToken, pageSize)
	if err != nil {
		audit.Log("UserService", "ListUsers", actingUserID, "", "Failed to list users", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list users: %w", err))
	}

	// 3. Convert to ssov1.User
	userProtos := make([]*ssov1.User, len(users))
	for i, user := range users {
		userProtos[i] = &ssov1.User{
			Id:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Status:    mapUserStatusToProto(user.Status),
			Roles:     user.Roles,
		}
	}

	audit.Log("UserService", "ListUsers", actingUserID, "", fmt.Sprintf("Listed %d users successfully", len(users)), true, nil)
	return connect.NewResponse(&ssov1.ListUsersResponse{
		Users:         userProtos,
		NextPageToken: nextPageToken,
	}), nil
}

// GetUser retrieves a user by ID.
func (s *UserServer) GetUser(ctx context.Context, req *connect.Request[ssov1.GetUserRequest]) (*connect.Response[ssov1.GetUserResponse], error) {
	// Get acting user from context
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		audit.Log("UserService", "GetUser", "", req.Msg.GetUserId(), "Authentication required", false, err)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	targetUserID := req.Msg.GetUserId()
	if targetUserID == "" {
		err := errors.New("user_id is required")
		audit.Log("UserService", "GetUser", actingUserID, "", "Validation failed: missing user_id", false, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// 1. Fetch user by req.UserId from userRepo.GetUserByID
	user, err := s.userRepo.GetUserByID(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			audit.Log("UserService", "GetUser", actingUserID, targetUserID, "User not found", false, err)
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		audit.Log("UserService", "GetUser", actingUserID, targetUserID, "Failed to get user from repository", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	audit.Log("UserService", "GetUser", actingUserID, targetUserID, "User retrieved successfully", true, nil)

	// 2. Convert to ssov1.User
	userProto := &ssov1.User{
		Id:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Status:    mapDomainStatusToProto(user.Status),
		Roles:     user.Roles,
	}

	return connect.NewResponse(&ssov1.GetUserResponse{User: userProto}), nil
}

// ChangePassword changes a user's password.
func (s *UserServer) ChangePassword(ctx context.Context, req *connect.Request[ssov1.ChangePasswordRequest]) (*connect.Response[emptypb.Empty], error) {
	// Get acting user from context
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		audit.Log("UserService", "ChangePassword", "", req.Msg.GetUserId(), "Authentication required", false, err)
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	targetUserID := req.Msg.GetUserId()
	if targetUserID == "" {
		err := errors.New("user_id is required")
		audit.Log("UserService", "ChangePassword", actingUserID, "", "Validation failed: missing user_id", false, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if req.Msg.GetNewPassword() == "" {
		err := errors.New("new_password is required")
		audit.Log("UserService", "ChangePassword", actingUserID, targetUserID, "Validation failed: missing new_password", false, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// 1. Fetch target user
	user, err := s.userRepo.GetUserByID(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			audit.Log("UserService", "ChangePassword", actingUserID, targetUserID, "User not found", false, err)
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		audit.Log("UserService", "ChangePassword", actingUserID, targetUserID, "Failed to get user", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	// 2. Check if user is self-changing password or admin changing
	isSelfChange := actingUserID == targetUserID

	if isSelfChange {
		// Self-change: verify old password
		if req.Msg.GetOldPassword() == "" {
			err := errors.New("old_password is required for self password change")
			audit.Log("UserService", "ChangePassword", actingUserID, targetUserID, "Validation failed: missing old_password for self-change", false, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}

		if err := s.passwordHasher.Verify(user.PasswordHash, req.Msg.GetOldPassword()); err != nil {
			audit.Log("UserService", "ChangePassword", actingUserID, targetUserID, "Incorrect old password", false, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("incorrect old password"))
		}
	} else {
		// Admin changing password: TODO - check admin privileges
		// For now, allow any authenticated user to change others' passwords
		// In production, you'd check if actingUserID has admin role
		audit.Log("UserService", "ChangePassword", actingUserID, targetUserID, "Admin password change", true, nil)
	}

	// 3. Hash new password
	hashedPassword, err := s.passwordHasher.Hash(req.Msg.GetNewPassword())
	if err != nil {
		audit.Log("UserService", "ChangePassword", actingUserID, targetUserID, "Failed to hash new password", false, err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to process new password"))
	}

	// 4. Update password hash and timestamp
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()

	// 5. Save user
	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		audit.Log("UserService", "ChangePassword", actingUserID, targetUserID, "Failed to update user password", false, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update password: %w", err))
	}

	audit.Log("UserService", "ChangePassword", actingUserID, targetUserID, "Password changed successfully", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// SendPhoneVerificationOtp sends a verification OTP to the user's phone number
func (s *UserServer) SendPhoneVerificationOtp(ctx context.Context, req *connect.Request[ssov1.SendPhoneVerificationOtpRequest]) (*connect.Response[ssov1.SendPhoneVerificationOtpResponse], error) {
	userID := req.Msg.GetUserId()
	if userID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("user_id is required"))
	}

	// Get user to check current state
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	if user.PhoneNumber == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("user has no phone number"))
	}

	if user.IsPhoneNumberVerified {
		return connect.NewResponse(&ssov1.SendPhoneVerificationOtpResponse{
			Success: true,
			Message: "Phone number is already verified",
		}), nil
	}

	// Use domain service to handle the business logic
	err = s.phoneVerificationService.SendVerificationOTP(ctx, userID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to send verification OTP: %w", err))
	}

	audit.Log("UserService", "SendPhoneVerificationOtp", "", userID, "OTP sent successfully", true, nil)

	return connect.NewResponse(&ssov1.SendPhoneVerificationOtpResponse{
		Success: true,
		Message: fmt.Sprintf("Verification OTP sent to %s", user.PhoneNumber),
	}), nil
}

// VerifyPhoneNumber verifies the user's phone number using the provided OTP
func (s *UserServer) VerifyPhoneNumber(ctx context.Context, req *connect.Request[ssov1.VerifyPhoneNumberRequest]) (*connect.Response[ssov1.VerifyPhoneNumberResponse], error) {
	userID := req.Msg.GetUserId()
	otp := req.Msg.GetOtp()

	if userID == "" || otp == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("user_id and otp are required"))
	}

	// Use domain service to handle the business logic
	err := s.phoneVerificationService.VerifyPhoneNumber(ctx, userID, otp)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserHasNoPhoneNumber):
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		case errors.Is(err, domain.ErrNoOTPFound), errors.Is(err, domain.ErrOTPExpired):
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		case errors.Is(err, domain.ErrInvalidOTP):
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		default:
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to verify phone number: %w", err))
		}
	}

	audit.Log("UserService", "VerifyPhoneNumber", "", userID, "Phone number verified successfully", true, nil)

	return connect.NewResponse(&ssov1.VerifyPhoneNumberResponse{
		Success: true,
		Message: "Phone number verified successfully",
	}), nil
}

// Ensure UserServer implements ssov1connect.UserServiceHandler
var _ ssov1connect.UserServiceHandler = (*UserServer)(nil)
