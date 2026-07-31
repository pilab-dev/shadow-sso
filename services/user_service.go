package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp"

	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// generateSecureOTP generates a cryptographically secure OTP of the given length.
func generateSecureOTP(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// Fallback to zero-filled OTP on catastrophic rand failure (should never happen)
		return "000000"
	}
	// Map each byte to a digit 0-9
	for i := range b {
		b[i] = byte('0' + (int(b[i]) % 10))
	}
	return string(b)
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
		Roles:        []string{rbac.RoleUser},  // Default role
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
		tokenInfo, ok := domain.GetAuthenticatedTokenFromContext(ctx)
		if !ok || !rbac.HasPermission(tokenInfo.Roles, rbac.PermUsersChangePasswordAll) {
			return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied to change password for another user"))
		}
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

func (s *UserServer) UpdateUser(ctx context.Context, req *connect.Request[ssov1.UpdateUserRequest]) (*connect.Response[ssov1.UpdateUserResponse], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	if req.Msg.GetEmail() != "" {
		user.Email = req.Msg.GetEmail()
	}
	if req.Msg.GetFirstName() != "" {
		user.FirstName = req.Msg.GetFirstName()
	}
	if req.Msg.GetLastName() != "" {
		user.LastName = req.Msg.GetLastName()
	}
	if req.Msg.Roles != nil {
		user.Roles = req.Msg.Roles
	}
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user: %w", err))
	}

	audit.Log("UserService", "UpdateUser", actingUserID, user.ID, "User updated successfully", true, nil)

	return connect.NewResponse(&ssov1.UpdateUserResponse{
		User: userToProto(user),
	}), nil
}

func (s *UserServer) DeleteUser(ctx context.Context, req *connect.Request[ssov1.DeleteUserRequest]) (*connect.Response[emptypb.Empty], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	if err := s.userRepo.DeleteUser(ctx, req.Msg.GetUserId()); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to delete user: %w", err))
	}

	audit.Log("UserService", "DeleteUser", actingUserID, req.Msg.GetUserId(), "User deleted successfully", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) AddMfaMethod(ctx context.Context, req *connect.Request[ssov1.AddMfaMethodRequest]) (*connect.Response[ssov1.AddMfaMethodResponse], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	method := req.Msg.GetMethod()
	if method == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("method is required"))
	}

	mfaMethod := domain.MfaMethod{
		ID:        uuid.NewString(),
		Type:      mfaMethodTypeFromProto(method.GetType()),
		Secret:    method.GetSecret(),
		Verified:  method.GetVerified(),
		CreatedAt: time.Now(),
		Name:      method.GetName(),
	}

	user.MfaMethods = append(user.MfaMethods, mfaMethod)
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to add MFA method: %w", err))
	}

	audit.Log("UserService", "AddMfaMethod", actingUserID, user.ID, "MFA method added", true, nil)

	return connect.NewResponse(&ssov1.AddMfaMethodResponse{
		Method: mfaMethodToProto(&mfaMethod),
	}), nil
}

func (s *UserServer) GetMfaMethod(ctx context.Context, req *connect.Request[ssov1.GetMfaMethodRequest]) (*connect.Response[ssov1.GetMfaMethodResponse], error) {
	_, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	for _, m := range user.MfaMethods {
		if m.ID == req.Msg.GetMethodId() {
			return connect.NewResponse(&ssov1.GetMfaMethodResponse{Method: mfaMethodToProto(&m)}), nil
		}
	}

	return nil, connect.NewError(connect.CodeNotFound, errors.New("MFA method not found"))
}

func (s *UserServer) ListMfaMethods(ctx context.Context, req *connect.Request[ssov1.ListMfaMethodsRequest]) (*connect.Response[ssov1.ListMfaMethodsResponse], error) {
	_, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	methods, err := s.userRepo.ListMfaMethods(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list MFA methods: %w", err))
	}

	protoMethods := make([]*ssov1.MfaMethod, len(methods))
	for i, m := range methods {
		protoMethods[i] = mfaMethodToProto(&m)
	}

	return connect.NewResponse(&ssov1.ListMfaMethodsResponse{Methods: protoMethods}), nil
}

func (s *UserServer) VerifyMfaMethod(ctx context.Context, req *connect.Request[ssov1.VerifyMfaMethodRequest]) (*connect.Response[emptypb.Empty], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	if err := s.userRepo.VerifyMfaMethod(ctx, req.Msg.GetUserId(), req.Msg.GetMethodId()); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to verify MFA method: %w", err))
	}

	audit.Log("UserService", "VerifyMfaMethod", actingUserID, req.Msg.GetUserId(), "MFA method verified", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) RemoveMfaMethod(ctx context.Context, req *connect.Request[ssov1.RemoveMfaMethodRequest]) (*connect.Response[emptypb.Empty], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	if err := s.userRepo.RemoveMfaMethod(ctx, req.Msg.GetUserId(), req.Msg.GetMethodId()); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to remove MFA method: %w", err))
	}

	audit.Log("UserService", "RemoveMfaMethod", actingUserID, req.Msg.GetUserId(), "MFA method removed", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) AddWebAuthnDevice(ctx context.Context, req *connect.Request[ssov1.AddWebAuthnDeviceRequest]) (*connect.Response[ssov1.AddWebAuthnDeviceResponse], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	device := req.Msg.GetDevice()
	if device == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device is required"))
	}

	webAuthnDevice := domain.WebAuthnDevice{
		ID:           uuid.NewString(),
		Name:         device.GetName(),
		CredentialID: device.GetCredentialId(),
		PublicKey:    device.GetPublicKey(),
		Counter:      device.GetCounter(),
		CreatedAt:    time.Now(),
		Transports:   device.GetTransports(),
	}

	user.WebAuthnDevices = append(user.WebAuthnDevices, webAuthnDevice)
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to add WebAuthn device: %w", err))
	}

	audit.Log("UserService", "AddWebAuthnDevice", actingUserID, user.ID, "WebAuthn device added", true, nil)

	return connect.NewResponse(&ssov1.AddWebAuthnDeviceResponse{
		Device: webAuthnDeviceToProto(&webAuthnDevice),
	}), nil
}

func (s *UserServer) GetWebAuthnDevice(ctx context.Context, req *connect.Request[ssov1.GetWebAuthnDeviceRequest]) (*connect.Response[ssov1.GetWebAuthnDeviceResponse], error) {
	_, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	device, err := s.userRepo.GetWebAuthnDevice(ctx, req.Msg.GetUserId(), req.Msg.GetDeviceId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeNotFound, errors.New("WebAuthn device not found"))
	}

	return connect.NewResponse(&ssov1.GetWebAuthnDeviceResponse{Device: webAuthnDeviceToProto(device)}), nil
}

func (s *UserServer) ListWebAuthnDevices(ctx context.Context, req *connect.Request[ssov1.ListWebAuthnDevicesRequest]) (*connect.Response[ssov1.ListWebAuthnDevicesResponse], error) {
	_, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	devices, err := s.userRepo.ListWebAuthnDevices(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list WebAuthn devices: %w", err))
	}

	protoDevices := make([]*ssov1.WebAuthnDevice, len(devices))
	for i, d := range devices {
		protoDevices[i] = webAuthnDeviceToProto(&d)
	}

	return connect.NewResponse(&ssov1.ListWebAuthnDevicesResponse{Devices: protoDevices}), nil
}

func (s *UserServer) UpdateWebAuthnDeviceCounter(ctx context.Context, req *connect.Request[ssov1.UpdateWebAuthnDeviceCounterRequest]) (*connect.Response[emptypb.Empty], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	if err := s.userRepo.UpdateWebAuthnDeviceCounter(ctx, req.Msg.GetUserId(), req.Msg.GetDeviceId(), req.Msg.GetNewCounter()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update device counter: %w", err))
	}

	audit.Log("UserService", "UpdateWebAuthnDeviceCounter", actingUserID, req.Msg.GetUserId(), "WebAuthn device counter updated", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) RemoveWebAuthnDevice(ctx context.Context, req *connect.Request[ssov1.RemoveWebAuthnDeviceRequest]) (*connect.Response[emptypb.Empty], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	if err := s.userRepo.RemoveWebAuthnDevice(ctx, req.Msg.GetUserId(), req.Msg.GetDeviceId()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to remove WebAuthn device: %w", err))
	}

	audit.Log("UserService", "RemoveWebAuthnDevice", actingUserID, req.Msg.GetUserId(), "WebAuthn device removed", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) IncrementFailedLoginAttempts(ctx context.Context, req *connect.Request[ssov1.IncrementFailedLoginAttemptsRequest]) (*connect.Response[ssov1.IncrementFailedLoginAttemptsResponse], error) {
	currentAttempts, err := s.userRepo.IncrementFailedLoginAttempts(ctx, req.Msg.GetUserId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to increment failed login attempts: %w", err))
	}

	return connect.NewResponse(&ssov1.IncrementFailedLoginAttemptsResponse{
		CurrentAttempts: currentAttempts,
	}), nil
}

func (s *UserServer) ResetFailedLoginAttempts(ctx context.Context, req *connect.Request[ssov1.ResetFailedLoginAttemptsRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.ResetFailedLoginAttempts(ctx, req.Msg.GetUserId()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to reset failed login attempts: %w", err))
	}

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) SetEmailAsVerified(ctx context.Context, req *connect.Request[ssov1.SetEmailAsVerifiedRequest]) (*connect.Response[emptypb.Empty], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	user.IsEmailVerified = true
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user: %w", err))
	}

	audit.Log("UserService", "SetEmailAsVerified", actingUserID, user.ID, "Email verified", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) StoreEmailVerificationToken(ctx context.Context, req *connect.Request[ssov1.StoreEmailVerificationTokenRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.StoreEmailVerificationToken(ctx, req.Msg.GetUserId(), req.Msg.GetToken(), req.Msg.GetExpiresAt().AsTime()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store email verification token: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) ClearEmailVerificationToken(ctx context.Context, req *connect.Request[ssov1.ClearEmailVerificationTokenRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.ClearEmailVerificationToken(ctx, req.Msg.GetUserId()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to clear email verification token: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) GetUserByEmailVerificationToken(ctx context.Context, req *connect.Request[ssov1.GetUserByEmailVerificationTokenRequest]) (*connect.Response[ssov1.GetUserByEmailVerificationTokenResponse], error) {
	user, err := s.userRepo.GetUserByEmailVerificationToken(ctx, req.Msg.GetToken())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	return connect.NewResponse(&ssov1.GetUserByEmailVerificationTokenResponse{
		User: userToProto(user),
	}), nil
}

func (s *UserServer) StorePasswordResetToken(ctx context.Context, req *connect.Request[ssov1.StorePasswordResetTokenRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.StorePasswordResetToken(ctx, req.Msg.GetUserId(), req.Msg.GetToken(), req.Msg.GetExpiresAt().AsTime()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store password reset token: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) GetUserByPasswordResetToken(ctx context.Context, req *connect.Request[ssov1.GetUserByPasswordResetTokenRequest]) (*connect.Response[ssov1.GetUserByPasswordResetTokenResponse], error) {
	user, err := s.userRepo.GetUserByPasswordResetToken(ctx, req.Msg.GetToken())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	return connect.NewResponse(&ssov1.GetUserByPasswordResetTokenResponse{
		User: userToProto(user),
	}), nil
}

func (s *UserServer) ClearPasswordResetToken(ctx context.Context, req *connect.Request[ssov1.ClearPasswordResetTokenRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.ClearPasswordResetToken(ctx, req.Msg.GetUserId()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to clear password reset token: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) UpdateUserPassword(ctx context.Context, req *connect.Request[ssov1.UpdateUserPasswordRequest]) (*connect.Response[emptypb.Empty], error) {
	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	user.PasswordHash = req.Msg.GetNewPasswordHash()
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user password: %w", err))
	}

	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) StoreLoginOtp(ctx context.Context, req *connect.Request[ssov1.StoreLoginOtpRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.StoreLoginOtp(ctx, req.Msg.GetUserId(), req.Msg.GetOtp(), req.Msg.GetMethodType().String(), req.Msg.GetExpiresAt().AsTime()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store login OTP: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) ClearLoginOtp(ctx context.Context, req *connect.Request[ssov1.ClearLoginOtpRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.ClearLoginOtp(ctx, req.Msg.GetUserId()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to clear login OTP: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) SetPhoneNumber(ctx context.Context, req *connect.Request[ssov1.SetPhoneNumberRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.SetPhoneNumber(ctx, req.Msg.GetUserId(), req.Msg.GetPhoneNumber()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to set phone number: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) StorePhoneVerificationOtp(ctx context.Context, req *connect.Request[ssov1.StorePhoneVerificationOtpRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.StorePhoneVerificationOtp(ctx, req.Msg.GetUserId(), req.Msg.GetOtp(), req.Msg.GetExpiresAt().AsTime()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store phone verification OTP: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) ClearPhoneVerificationOtp(ctx context.Context, req *connect.Request[ssov1.ClearPhoneVerificationOtpRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.userRepo.ClearPhoneVerificationOtp(ctx, req.Msg.GetUserId()); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to clear phone verification OTP: %w", err))
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) SendEmailVerification(ctx context.Context, req *connect.Request[ssov1.SendEmailVerificationRequest]) (*connect.Response[emptypb.Empty], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	token := uuid.NewString()
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := s.userRepo.StoreEmailVerificationToken(ctx, user.ID, token, expiresAt); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store verification token: %w", err))
	}

	audit.Log("UserService", "SendEmailVerification", actingUserID, user.ID, "Email verification sent", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *UserServer) VerifyEmail(ctx context.Context, req *connect.Request[ssov1.VerifyEmailRequest]) (*connect.Response[ssov1.VerifyEmailResponse], error) {
	user, err := s.userRepo.GetUserByEmailVerificationToken(ctx, req.Msg.GetToken())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("invalid verification token"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to verify email: %w", err))
	}

	if user.EmailVerificationTokenExpiresAt != nil && time.Now().After(*user.EmailVerificationTokenExpiresAt) {
		return connect.NewResponse(&ssov1.VerifyEmailResponse{
			Success: false,
			Error:   "verification token expired",
		}), nil
	}

	user.IsEmailVerified = true
	user.EmailVerificationToken = ""
	user.EmailVerificationTokenExpiresAt = nil
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user: %w", err))
	}

	return connect.NewResponse(&ssov1.VerifyEmailResponse{
		Success: true,
		Message: "Email verified successfully",
	}), nil
}

func (s *UserServer) RequestPasswordReset(ctx context.Context, req *connect.Request[ssov1.RequestPasswordResetRequest]) (*connect.Response[ssov1.RequestPasswordResetResponse], error) {
	user, err := s.userRepo.GetUserByEmail(ctx, req.Msg.GetEmail())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return connect.NewResponse(&ssov1.RequestPasswordResetResponse{
				Success: true,
				Message: "If an account exists with this email, a password reset link has been sent.",
			}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	token := uuid.NewString()
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := s.userRepo.StorePasswordResetToken(ctx, user.ID, token, expiresAt); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store reset token: %w", err))
	}

	return connect.NewResponse(&ssov1.RequestPasswordResetResponse{
		Success: true,
		Message: "If an account exists with this email, a password reset link has been sent.",
	}), nil
}

func (s *UserServer) ResetPassword(ctx context.Context, req *connect.Request[ssov1.ResetPasswordRequest]) (*connect.Response[ssov1.ResetPasswordResponse], error) {
	user, err := s.userRepo.GetUserByPasswordResetToken(ctx, req.Msg.GetToken())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return connect.NewResponse(&ssov1.ResetPasswordResponse{
				Success: false,
				Error:   "invalid or expired reset token",
			}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to reset password: %w", err))
	}

	if user.PasswordResetTokenExpiresAt != nil && time.Now().After(*user.PasswordResetTokenExpiresAt) {
		return connect.NewResponse(&ssov1.ResetPasswordResponse{
			Success: false,
			Error:   "reset token expired",
		}), nil
	}

	hashedPassword, err := s.passwordHasher.Hash(req.Msg.GetNewPassword())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to process password"))
	}

	user.PasswordHash = hashedPassword
	user.PasswordResetToken = ""
	user.PasswordResetTokenExpiresAt = nil
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user: %w", err))
	}

	return connect.NewResponse(&ssov1.ResetPasswordResponse{
		Success: true,
		Message: "Password reset successfully",
	}), nil
}

func (s *UserServer) SendSmsOtp(ctx context.Context, req *connect.Request[ssov1.SendSmsOtpRequest]) (*connect.Response[ssov1.SendSmsOtpResponse], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	if user.PhoneNumber == "" {
		return connect.NewResponse(&ssov1.SendSmsOtpResponse{
			Success: false,
			Error:   "user has no phone number",
		}), nil
	}

	otp := generateSecureOTP(6)
	expiresAt := time.Now().Add(5 * time.Minute)

	if err := s.userRepo.StoreLoginOtp(ctx, user.ID, otp, ssov1.MfaMethodType_MFA_METHOD_TYPE_SMS.String(), expiresAt); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store OTP: %w", err))
	}

	audit.Log("UserService", "SendSmsOtp", actingUserID, user.ID, "SMS OTP sent", true, nil)

	return connect.NewResponse(&ssov1.SendSmsOtpResponse{
		Success: true,
		Message: "SMS OTP sent successfully",
	}), nil
}

func (s *UserServer) SendEmailOtp(ctx context.Context, req *connect.Request[ssov1.SendEmailOtpRequest]) (*connect.Response[ssov1.SendEmailOtpResponse], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	otp := generateSecureOTP(6)
	expiresAt := time.Now().Add(5 * time.Minute)

	if err := s.userRepo.StoreLoginOtp(ctx, user.ID, otp, ssov1.MfaMethodType_MFA_METHOD_TYPE_EMAIL.String(), expiresAt); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store OTP: %w", err))
	}

	audit.Log("UserService", "SendEmailOtp", actingUserID, user.ID, "Email OTP sent", true, nil)

	return connect.NewResponse(&ssov1.SendEmailOtpResponse{
		Success: true,
		Message: "Email OTP sent successfully",
	}), nil
}

func (s *UserServer) VerifyLoginOtp(ctx context.Context, req *connect.Request[ssov1.VerifyLoginOtpRequest]) (*connect.Response[ssov1.VerifyLoginOtpResponse], error) {
	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	if user.LoginOtp == "" {
		return connect.NewResponse(&ssov1.VerifyLoginOtpResponse{
			Success: false,
			Error:   "no OTP found",
		}), nil
	}

	if user.LoginOtpExpiresAt != nil && time.Now().After(*user.LoginOtpExpiresAt) {
		return connect.NewResponse(&ssov1.VerifyLoginOtpResponse{
			Success: false,
			Error:   "OTP expired",
		}), nil
	}

	if user.LoginOtp != req.Msg.GetOtp() {
		return connect.NewResponse(&ssov1.VerifyLoginOtpResponse{
			Success: false,
			Error:   "invalid OTP",
		}), nil
	}

	user.LoginOtp = ""
	user.LoginOtpExpiresAt = nil
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user: %w", err))
	}

	return connect.NewResponse(&ssov1.VerifyLoginOtpResponse{
		Success: true,
	}), nil
}

func (s *UserServer) SetupTotp(ctx context.Context, req *connect.Request[ssov1.SetupTotpRequest]) (*connect.Response[ssov1.SetupTotpResponse], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	if user.IsTwoFactorEnabled {
		return connect.NewResponse(&ssov1.SetupTotpResponse{
			Success: false,
			Error:   "2FA is already enabled",
		}), nil
	}

	otpKey, otpAuthURI, err := totp.GenerateTOTPSecret("ShadowSSO", user.Email)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate TOTP secret: %w", err))
	}

	methodID := uuid.NewString()
	user.TwoFactorSecret = otpKey.Secret()
	user.TwoFactorMethod = "TOTP"
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user: %w", err))
	}

	audit.Log("UserService", "SetupTotp", actingUserID, user.ID, "TOTP setup initiated", true, nil)

	return connect.NewResponse(&ssov1.SetupTotpResponse{
		Success:   true,
		QrCodeUri: otpAuthURI,
		MethodId:  methodID,
	}), nil
}

func (s *UserServer) VerifyTotpSetup(ctx context.Context, req *connect.Request[ssov1.VerifyTotpSetupRequest]) (*connect.Response[ssov1.VerifyTotpSetupResponse], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	valid, err := totp.ValidateTOTPCode(user.TwoFactorSecret, req.Msg.GetToken())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to validate TOTP: %w", err))
	}

	if !valid {
		return connect.NewResponse(&ssov1.VerifyTotpSetupResponse{
			Verified: false,
			Error:    "invalid TOTP code",
		}), nil
	}

	user.IsTwoFactorEnabled = true
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to update user: %w", err))
	}

	audit.Log("UserService", "VerifyTotpSetup", actingUserID, user.ID, "TOTP setup verified", true, nil)

	return connect.NewResponse(&ssov1.VerifyTotpSetupResponse{
		Verified: true,
	}), nil
}

func (s *UserServer) SetupWebAuthnRegistration(ctx context.Context, req *connect.Request[ssov1.SetupWebAuthnRegistrationRequest]) (*connect.Response[ssov1.SetupWebAuthnRegistrationResponse], error) {
	_, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	challenge := uuid.NewString()

	return connect.NewResponse(&ssov1.SetupWebAuthnRegistrationResponse{
		Challenge: challenge,
		Options: &ssov1.PublicKeyCredentialCreationOptions{
			Challenge:       challenge,
			RpId:            "sso.pilab.hu",
			RpName:          "ShadowSSO",
			UserId:          user.ID,
			UserName:        user.Email,
			UserDisplayName: fmt.Sprintf("%s %s", user.FirstName, user.LastName),
		},
	}), nil
}

func (s *UserServer) VerifyWebAuthnRegistration(ctx context.Context, req *connect.Request[ssov1.VerifyWebAuthnRegistrationRequest]) (*connect.Response[ssov1.VerifyWebAuthnRegistrationResponse], error) {
	actingUserID, err := domain.GetAuthenticatedUserIDFromContext(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}

	user, err := s.userRepo.GetUserByID(ctx, req.Msg.GetUserId())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	device := domain.WebAuthnDevice{
		ID:           uuid.NewString(),
		Name:         req.Msg.GetDeviceName(),
		CredentialID: req.Msg.GetRegistrationResponse().GetId(),
		PublicKey:    req.Msg.GetRegistrationResponse().GetResponse().GetAuthenticatorAttestationResponse().GetAttestationObject(),
		Counter:      0,
		CreatedAt:    time.Now(),
	}

	user.WebAuthnDevices = append(user.WebAuthnDevices, device)
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to register WebAuthn device: %w", err))
	}

	audit.Log("UserService", "VerifyWebAuthnRegistration", actingUserID, user.ID, "WebAuthn device registered", true, nil)

	return connect.NewResponse(&ssov1.VerifyWebAuthnRegistrationResponse{
		Verified: true,
	}), nil
}

func (s *UserServer) SetupWebAuthnAuthentication(ctx context.Context, req *connect.Request[ssov1.SetupWebAuthnAuthenticationRequest]) (*connect.Response[ssov1.SetupWebAuthnAuthenticationResponse], error) {
	user, err := s.userRepo.GetUserByEmail(ctx, req.Msg.GetEmail())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get user: %w", err))
	}

	challenge := uuid.NewString()

	allowCredentials := make([]*ssov1.PublicKeyCredentialDescriptor, len(user.WebAuthnDevices))
	for i, d := range user.WebAuthnDevices {
		allowCredentials[i] = &ssov1.PublicKeyCredentialDescriptor{
			Type:       "public-key",
			Id:         d.CredentialID,
			Transports: d.Transports,
		}
	}

	return connect.NewResponse(&ssov1.SetupWebAuthnAuthenticationResponse{
		Challenge: challenge,
		Options: &ssov1.PublicKeyCredentialRequestOptions{
			Challenge:        challenge,
			Timeout:          60000,
			RpId:             "sso.pilab.hu",
			AllowCredentials: allowCredentials,
			UserVerification: "preferred",
		},
	}), nil
}

func (s *UserServer) VerifyWebAuthnAuthentication(ctx context.Context, req *connect.Request[ssov1.VerifyWebAuthnAuthenticationRequest]) (*connect.Response[ssov1.VerifyWebAuthnAuthenticationResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("use AuthService.CompleteWebAuthnLogin instead"))
}

func mfaMethodTypeFromProto(t ssov1.MfaMethodType) domain.MfaMethodType {
	switch t {
	case ssov1.MfaMethodType_MFA_METHOD_TYPE_TOTP:
		return domain.MfaMethodTypeTOTP
	case ssov1.MfaMethodType_MFA_METHOD_TYPE_SMS:
		return domain.MfaMethodTypeSMS
	case ssov1.MfaMethodType_MFA_METHOD_TYPE_EMAIL:
		return domain.MfaMethodTypeEmail
	case ssov1.MfaMethodType_MFA_METHOD_TYPE_WEBAUTHN:
		return domain.MfaMethodTypeWebAuthn
	default:
		return domain.MfaMethodTypeNone
	}
}

func mfaMethodTypeToProto(t domain.MfaMethodType) ssov1.MfaMethodType {
	switch t {
	case domain.MfaMethodTypeTOTP:
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_TOTP
	case domain.MfaMethodTypeSMS:
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_SMS
	case domain.MfaMethodTypeEmail:
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_EMAIL
	case domain.MfaMethodTypeWebAuthn:
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_WEBAUTHN
	default:
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_UNSPECIFIED
	}
}

func mfaMethodToProto(m *domain.MfaMethod) *ssov1.MfaMethod {
	if m == nil {
		return nil
	}
	pb := &ssov1.MfaMethod{
		Id:       m.ID,
		Type:     mfaMethodTypeToProto(m.Type),
		Secret:   m.Secret,
		Verified: m.Verified,
		Name:     m.Name,
	}
	if !m.CreatedAt.IsZero() {
		pb.CreatedAt = timestamppb.New(m.CreatedAt)
	}
	return pb
}

func webAuthnDeviceToProto(d *domain.WebAuthnDevice) *ssov1.WebAuthnDevice {
	if d == nil {
		return nil
	}
	pb := &ssov1.WebAuthnDevice{
		Id:           d.ID,
		Name:         d.Name,
		CredentialId: d.CredentialID,
		PublicKey:    d.PublicKey,
		Counter:      d.Counter,
		Transports:   d.Transports,
	}
	if !d.CreatedAt.IsZero() {
		pb.CreatedAt = timestamppb.New(d.CreatedAt)
	}
	return pb
}

func userToProto(user *domain.User) *ssov1.User {
	if user == nil {
		return nil
	}
	pb := &ssov1.User{
		Id:                    user.ID,
		Email:                 user.Email,
		Status:                mapUserStatusToProto(user.Status),
		FirstName:             user.FirstName,
		LastName:              user.LastName,
		Roles:                 user.Roles,
		FailedLoginAttempts:   int32(user.FailedLoginAttempts),
		IsEmailVerified:       user.IsEmailVerified,
		IsPhoneNumberVerified: user.IsPhoneNumberVerified,
		PhoneNumber:           user.PhoneNumber,
		LoginOtp:              user.LoginOtp,
		LoginOtpMethodType:    user.LoginOtpMethodType,
	}

	if !user.CreatedAt.IsZero() {
		pb.CreatedAt = timestamppb.New(user.CreatedAt)
	}
	if !user.UpdatedAt.IsZero() {
		pb.UpdatedAt = timestamppb.New(user.UpdatedAt)
	}
	if user.LastLoginAt != nil && !user.LastLoginAt.IsZero() {
		pb.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}
	if user.LastFailedLoginTime != nil && !user.LastFailedLoginTime.IsZero() {
		pb.LastFailedLoginTime = timestamppb.New(*user.LastFailedLoginTime)
	}
	if user.LoginOtpExpiresAt != nil && !user.LoginOtpExpiresAt.IsZero() {
		pb.LoginOtpExpiresAt = timestamppb.New(*user.LoginOtpExpiresAt)
	}
	if user.EmailVerificationTokenExpiresAt != nil && !user.EmailVerificationTokenExpiresAt.IsZero() {
		pb.EmailVerificationTokenExpiresAt = timestamppb.New(*user.EmailVerificationTokenExpiresAt)
	}
	if user.PasswordResetTokenExpiresAt != nil && !user.PasswordResetTokenExpiresAt.IsZero() {
		pb.PasswordResetTokenExpiresAt = timestamppb.New(*user.PasswordResetTokenExpiresAt)
	}
	if user.PhoneVerificationOtpExpiresAt != nil && !user.PhoneVerificationOtpExpiresAt.IsZero() {
		pb.PhoneVerificationOtpExpiresAt = timestamppb.New(*user.PhoneVerificationOtpExpiresAt)
	}

	pb.MfaMethods = make([]*ssov1.MfaMethod, len(user.MfaMethods))
	for i, m := range user.MfaMethods {
		pb.MfaMethods[i] = mfaMethodToProto(&m)
	}

	pb.WebAuthnDevices = make([]*ssov1.WebAuthnDevice, len(user.WebAuthnDevices))
	for i, d := range user.WebAuthnDevices {
		pb.WebAuthnDevices[i] = webAuthnDeviceToProto(&d)
	}

	return pb
}
