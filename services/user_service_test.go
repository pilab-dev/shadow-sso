package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Mock Implementations ---

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	// If CreateUser needs to set the ID on the user arg:
	if userArg, ok := args.Get(1).(*domain.User); ok {
		if userArg.ID == "" { // Simulate ID generation if repo does it
			userArg.ID = "mock-generated-id"
		}
	}
	return args.Error(0)
}
func (m *MockUserRepository) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}
func (m *MockUserRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockUserRepository) DeleteUser(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockUserRepository) ListUsers(ctx context.Context, pageToken string, pageSize int) ([]*domain.User, string, error) {
	args := m.Called(ctx, pageToken, pageSize)
	if args.Get(0) == nil {
		return nil, args.String(1), args.Error(2)
	}
	return args.Get(0).([]*domain.User), args.String(1), args.Error(2)
}

type MockPasswordHasher struct {
	mock.Mock
}

func (m *MockPasswordHasher) Hash(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordHasher) Verify(hashedPassword, password string) error {
	args := m.Called(hashedPassword, password)
	return args.Error(0)
}

// --- UserServer Tests ---

func TestUserServer_RegisterUser(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockHasher := new(MockPasswordHasher)

	userServer := NewUserServer(mockUserRepo, mockHasher)
	ctx := context.Background()

	registerReqPayload := &ssov1.RegisterUserRequest{
		Email:     "newuser@example.com",
		Password:  "password123",
		FirstName: "Test",
		LastName:  "User",
	}
	hashedPassword := "hashed_password123"

	// Reset mocks before each sub-test if they are reused across sub-tests with different behaviors.
    // Or, define them inside each t.Run scope. For now, they are defined once per top-level test.

	t.Run("Successful Registration", func(t *testing.T) {
		// Fresh mocks for this sub-test to avoid interference
		mockUserRepoSub := new(MockUserRepository)
		mockHasherSub := new(MockPasswordHasher)
		userServerSub := NewUserServer(mockUserRepoSub, mockHasherSub)


		mockUserRepoSub.On("GetUserByEmail", ctx, registerReqPayload.Email).Return(nil, errors.New("not found")).Once()
		mockHasherSub.On("Hash", registerReqPayload.Password).Return(hashedPassword, nil).Once()
		mockUserRepoSub.On("CreateUser", ctx, mock.AnythingOfType("*domain.User")).Run(func(args mock.Arguments) {
			userArg := args.Get(1).(*domain.User)
			assert.Equal(t, registerReqPayload.Email, userArg.Email)
			assert.Equal(t, hashedPassword, userArg.PasswordHash)
			assert.Equal(t, registerReqPayload.FirstName, userArg.FirstName)
			assert.Equal(t, domain.UserStatusActive, userArg.Status) // Default status
			// Simulate ID being set by CreateUser mock if necessary for assertions
			if userArg.ID == "" { userArg.ID = "newly-created-id"}
		}).Return(nil).Once()

		req := connect.NewRequest(registerReqPayload)
		resp, err := userServerSub.RegisterUser(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Msg)
		require.NotNil(t, resp.Msg.User)
		assert.Equal(t, registerReqPayload.Email, resp.Msg.User.Email)
		assert.Equal(t, ssov1.UserStatus_USER_STATUS_ACTIVE, resp.Msg.User.Status)
		assert.NotEmpty(t, resp.Msg.User.Id) // Check if ID is populated in response

		mockUserRepoSub.AssertExpectations(t)
		mockHasherSub.AssertExpectations(t)
	})

	t.Run("Registration_UserAlreadyExists", func(t *testing.T) {
		mockUserRepoSub := new(MockUserRepository)
		mockHasherSub := new(MockPasswordHasher) // Not called
		userServerSub := NewUserServer(mockUserRepoSub, mockHasherSub)

		existingUser := &domain.User{ID: "id1", Email: registerReqPayload.Email}
		mockUserRepoSub.On("GetUserByEmail", ctx, registerReqPayload.Email).Return(existingUser, nil).Once()

		req := connect.NewRequest(registerReqPayload)
		resp, err := userServerSub.RegisterUser(ctx, req)

		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok, "Error should be a connect.Error")
		assert.Equal(t, connect.CodeAlreadyExists, connectErr.Code())
		assert.Nil(t, resp)

		mockUserRepoSub.AssertExpectations(t)
		mockHasherSub.AssertNotCalled(t, "Hash", mock.Anything)
		mockUserRepoSub.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})

	t.Run("Registration_PasswordHashFails", func(t *testing.T) {
		mockUserRepoSub := new(MockUserRepository)
		mockHasherSub := new(MockPasswordHasher)
		userServerSub := NewUserServer(mockUserRepoSub, mockHasherSub)

		mockUserRepoSub.On("GetUserByEmail", ctx, registerReqPayload.Email).Return(nil, errors.New("not found")).Once()
		mockHasherSub.On("Hash", registerReqPayload.Password).Return("", errors.New("hash failed")).Once()

		req := connect.NewRequest(registerReqPayload)
		resp, err := userServerSub.RegisterUser(ctx, req)

		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		assert.Nil(t, resp)

		mockUserRepoSub.AssertExpectations(t)
		mockHasherSub.AssertExpectations(t)
		mockUserRepoSub.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})
}

func TestUserServer_GetUser(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockHasher := new(MockPasswordHasher) // Not used by GetUser
	userServer := NewUserServer(mockUserRepo, mockHasher)
	ctx := context.Background()

	userID := "user123"
	userEmail := "getuser@example.com"
	now := time.Now()
	dbUser := &domain.User{
		ID: userID, Email: userEmail, FirstName: "Get", LastName: "Me",
		Status: domain.UserStatusActive, CreatedAt: now, UpdatedAt: now,
	}

	t.Run("Successful GetUser by ID", func(t *testing.T) {
		// Assuming UserServer.GetUser primarily tries GetUserByID
		// or has logic to determine if input is ID or Email.
		// The current service skeleton for GetUser is:
		// user, err := s.userRepo.GetUserByID(ctx, req.Msg.UserId)
		// So, this test path is valid.
		mockUserRepo.On("GetUserByID", ctx, userID).Return(dbUser, nil).Once()

		req := connect.NewRequest(&ssov1.GetUserRequest{UserId: userID})
		resp, err := userServer.GetUser(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Msg)
		require.NotNil(t, resp.Msg.User)
		assert.Equal(t, userID, resp.Msg.User.Id)
		assert.Equal(t, userEmail, resp.Msg.User.Email)
		assert.Equal(t, ssov1.UserStatus_USER_STATUS_ACTIVE, resp.Msg.User.Status)
		assert.Equal(t, timestamppb.New(now).Seconds, resp.Msg.User.CreatedAt.Seconds) // Compare seconds for timestamppb
		assert.Equal(t, timestamppb.New(now).Nanos, resp.Msg.User.CreatedAt.Nanos)


		mockUserRepo.AssertExpectations(t)
	})

    // To test GetUser by Email, the UserServer.GetUser RPC handler would need to be updated
    // to attempt GetUserByEmail if GetUserByID fails or if the input string looks like an email.
    // Or, a separate GetUserByEmail RPC method would be clearer.
    // For now, we assume GetUser primarily uses GetUserByID based on the current service skeleton.

	t.Run("GetUser_NotFound", func(t *testing.T) {
		notFoundID := "notfoundID"
		// Assuming GetUser tries GetUserByID
		mockUserRepo.On("GetUserByID", ctx, notFoundID).Return(nil, errors.New("user not found")).Once()
		// If GetUser also tried GetUserByEmail on ID not found:
		// mockUserRepo.On("GetUserByEmail", ctx, notFoundID).Return(nil, errors.New("user not found")).Once()


		req := connect.NewRequest(&ssov1.GetUserRequest{UserId: notFoundID})
		resp, err := userServer.GetUser(ctx, req)

		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		assert.Nil(t, resp)
		mockUserRepo.AssertExpectations(t)
	})

	// TODO: Add tests for ActivateUser, LockUser, ListUsers, ChangePassword
}

func TestUserServer_ActivateUser(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockHasher := new(MockPasswordHasher) // Not used by ActivateUser
	userServer := NewUserServer(mockUserRepo, mockHasher)
	ctx := context.Background()
	userID := "user-to-activate"

	// Reset mocks for this test function suite
	defer func() {
		mockUserRepo.ExpectedCalls = nil
		mockUserRepo.Calls = nil
		mockHasher.ExpectedCalls = nil
		mockHasher.Calls = nil
	}()


	t.Run("Successful Activation", func(t *testing.T) {
		// Fresh mocks for sub-test clarity if needed, or ensure calls are specific enough
		mockUserRepo.On("GetUserByID", ctx, userID).Return(&domain.User{ID: userID, Status: domain.UserStatusPending}, nil).Once()
		mockUserRepo.On("UpdateUser", ctx, mock.MatchedBy(func(user *domain.User) bool {
			return user.ID == userID && user.Status == domain.UserStatusActive
		})).Return(nil).Once()

		req := connect.NewRequest(&ssov1.ActivateUserRequest{UserId: userID})
		_, err := userServer.ActivateUser(ctx, req)

		require.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Activation_UserNotFound", func(t *testing.T) {
		mockUserRepo.On("GetUserByID", ctx, userID).Return(nil, errors.New("not found")).Once()

		req := connect.NewRequest(&ssov1.ActivateUserRequest{UserId: userID})
		_, err := userServer.ActivateUser(ctx, req)

		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		mockUserRepo.AssertExpectations(t)
		mockUserRepo.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})

	t.Run("Activation_UpdateFails", func(t *testing.T) {
		mockUserRepo.On("GetUserByID", ctx, userID).Return(&domain.User{ID: userID, Status: domain.UserStatusPending}, nil).Once()
		mockUserRepo.On("UpdateUser", ctx, mock.AnythingOfType("*domain.User")).Return(errors.New("update failed")).Once()

		req := connect.NewRequest(&ssov1.ActivateUserRequest{UserId: userID})
		_, err := userServer.ActivateUser(ctx, req)

		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockUserRepo.AssertExpectations(t)
	})
}

func TestUserServer_LockUser(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	userServer := NewUserServer(mockUserRepo, nil) // Hasher not used
	ctx := context.Background()
	userID := "user-to-lock"

	defer func() { // Reset mocks
		mockUserRepo.ExpectedCalls = nil
		mockUserRepo.Calls = nil
	}()

	t.Run("Successful Lock", func(t *testing.T) {
		mockUserRepo.On("GetUserByID", ctx, userID).Return(&domain.User{ID: userID, Status: domain.UserStatusActive}, nil).Once()
		mockUserRepo.On("UpdateUser", ctx, mock.MatchedBy(func(user *domain.User) bool {
			return user.ID == userID && user.Status == domain.UserStatusLocked
		})).Return(nil).Once()

		req := connect.NewRequest(&ssov1.LockUserRequest{UserId: userID})
		_, err := userServer.LockUser(ctx, req)

		require.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("Lock_UserNotFound", func(t *testing.T) {
		mockUserRepo.On("GetUserByID", ctx, userID).Return(nil, errors.New("not found")).Once()
		req := connect.NewRequest(&ssov1.LockUserRequest{UserId: userID})
		_, err := userServer.LockUser(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error); require.True(t, ok)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		mockUserRepo.AssertExpectations(t)
		mockUserRepo.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})

	t.Run("Lock_UpdateFails", func(t *testing.T) {
		mockUserRepo.On("GetUserByID", ctx, userID).Return(&domain.User{ID: userID, Status: domain.UserStatusActive}, nil).Once()
		mockUserRepo.On("UpdateUser", ctx, mock.AnythingOfType("*domain.User")).Return(errors.New("update failed")).Once()
		req := connect.NewRequest(&ssov1.LockUserRequest{UserId: userID})
		_, err := userServer.LockUser(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error); require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockUserRepo.AssertExpectations(t)
	})
}

func TestUserServer_ListUsers(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	userServer := NewUserServer(mockUserRepo, nil) // Hasher not used
	ctx := context.Background()

	now := time.Now()
	dbUsers := []*domain.User{
		{ID: "user1", Email: "user1@example.com", Status: domain.UserStatusActive, CreatedAt: now, UpdatedAt: now},
		{ID: "user2", Email: "user2@example.com", Status: domain.UserStatusLocked, CreatedAt: now, UpdatedAt: now},
	}
	nextPageToken := "nextpagetoken"

	defer func() { mockUserRepo.ExpectedCalls = nil; mockUserRepo.Calls = nil }()


	t.Run("Successful ListUsers", func(t *testing.T) {
		mockUserRepo.On("ListUsers", ctx, "", int32(10)).Return(dbUsers, nextPageToken, nil).Once()

		req := connect.NewRequest(&ssov1.ListUsersRequest{PageSize: 10, PageToken: ""})
		resp, err := userServer.ListUsers(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Len(t, resp.Msg.Users, 2)
		assert.Equal(t, nextPageToken, resp.Msg.NextPageToken)
		assert.Equal(t, dbUsers[0].Email, resp.Msg.Users[0].Email)
		assert.Equal(t, ssov1.UserStatus_USER_STATUS_LOCKED, resp.Msg.Users[1].Status) // Check enum mapping

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("ListUsers_RepoFails", func(t *testing.T) {
		mockUserRepo.On("ListUsers", ctx, "", int32(10)).Return(nil, "", errors.New("repo error")).Once()

		req := connect.NewRequest(&ssov1.ListUsersRequest{PageSize: 10, PageToken: ""})
		resp, err := userServer.ListUsers(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		mockUserRepo.AssertExpectations(t)
	})
}

func TestUserServer_ChangePassword(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockHasher := new(MockPasswordHasher)
	userServer := NewUserServer(mockUserRepo, mockHasher)
	ctx := context.Background()

	userID := "user-pass-change"
	oldPassword := "oldPassword123"
	newPassword := "newPassword456"
	hashedOldPassword := "hashed_oldPassword123"
	hashedNewPassword := "hashed_newPassword456"

	defer func() { // Reset mocks
		mockUserRepo.ExpectedCalls = nil; mockUserRepo.Calls = nil
		mockHasher.ExpectedCalls = nil; mockHasher.Calls = nil
	}()


	// Admin changing password for a user
	t.Run("Admin Changes Password Successfully", func(t *testing.T) {
		userToUpdate := &domain.User{ID: userID, Email: "user@example.com", PasswordHash: hashedOldPassword}

		mockUserRepo.On("GetUserByID", ctx, userID).Return(userToUpdate, nil).Once()
		mockHasher.On("Hash", newPassword).Return(hashedNewPassword, nil).Once()
		mockUserRepo.On("UpdateUser", ctx, mock.MatchedBy(func(user *domain.User) bool {
			return user.ID == userID && user.PasswordHash == hashedNewPassword
		})).Return(nil).Once()

		req := connect.NewRequest(&ssov1.ChangePasswordRequest{
			UserId: userID, NewPassword: newPassword, // OldPassword not provided by admin
		})
		_, err := userServer.ChangePassword(ctx, req)
		require.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	// User changes own password
	t.Run("User Changes Own Password Successfully", func(t *testing.T) {
		// This test assumes UserServer.ChangePassword can identify the caller is changing their own password
		// (e.g. by comparing req.Msg.UserId to an authenticated user ID from context, or if OldPassword is provided)
		// The service skeleton had comments about this logic.
		userToUpdate := &domain.User{ID: userID, Email: "self@example.com", PasswordHash: hashedOldPassword}

		mockUserRepo.On("GetUserByID", ctx, userID).Return(userToUpdate, nil).Once()
		mockHasher.On("Verify", hashedOldPassword, oldPassword).Return(nil).Once() // Old password matches
		mockHasher.On("Hash", newPassword).Return(hashedNewPassword, nil).Once()
		mockUserRepo.On("UpdateUser", ctx, mock.MatchedBy(func(user *domain.User) bool {
			return user.ID == userID && user.PasswordHash == hashedNewPassword
		})).Return(nil).Once()

		req := connect.NewRequest(&ssov1.ChangePasswordRequest{
			UserId: userID, OldPassword: oldPassword, NewPassword: newPassword,
		})
		_, err := userServer.ChangePassword(ctx, req)
		require.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("User Changes Own Password - Old Password Mismatch", func(t *testing.T) {
		userToUpdate := &domain.User{ID: userID, Email: "self@example.com", PasswordHash: hashedOldPassword}
		mockUserRepo.On("GetUserByID", ctx, userID).Return(userToUpdate, nil).Once()
		mockHasher.On("Verify", hashedOldPassword, "wrongOldPassword").Return(errors.New("password mismatch")).Once()

		req := connect.NewRequest(&ssov1.ChangePasswordRequest{
			UserId: userID, OldPassword: "wrongOldPassword", NewPassword: newPassword,
		})
		_, err := userServer.ChangePassword(ctx, req)

		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeUnauthenticated, connectErr.Code()) // Or PermissionDenied or InvalidArgument
		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		mockUserRepo.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})
}
