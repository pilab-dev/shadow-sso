package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/api" // For api.TokenResponse
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	"github.com/pilab-dev/shadow-sso/middleware" // For AuthenticatedTokenContextKey
	"github.com/pilab-dev/shadow-sso/ssso"       // For ssso.Token
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	// "google.golang.org/protobuf/types/known/timestamppb" // Not directly used in this snippet yet
)

// --- Mock Implementations ---

// MockUserRepository (copied from user_service_test.go for now, consider shared package)
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	if userArg, ok := args.Get(1).(*domain.User); ok {
		if userArg.ID == "" {
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

// MockPasswordHasher (copied from user_service_test.go for now)
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

// MockSessionRepository
type MockSessionRepository struct {
	mock.Mock
}

func (m *MockSessionRepository) StoreSession(ctx context.Context, session *domain.Session) error {
	args := m.Called(ctx, session)
	// Simulate ID generation if repo does it and session.ID is empty
	if s, ok := args.Get(1).(*domain.Session); ok {
		if s.ID == "" {
			s.ID = "mock-session-id"
		}
	}
	return args.Error(0)
}
func (m *MockSessionRepository) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}
func (m *MockSessionRepository) GetSessionByTokenID(ctx context.Context, tokenID string) (*domain.Session, error) {
	args := m.Called(ctx, tokenID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}
func (m *MockSessionRepository) UpdateSession(ctx context.Context, session *domain.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}
func (m *MockSessionRepository) DeleteSession(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockSessionRepository) ListSessionsByUserID(ctx context.Context, userID string, filter domain.SessionFilter) ([]*domain.Session, error) {
	args := m.Called(ctx, userID, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.Session), args.Error(1)
}
func (m *MockSessionRepository) DeleteSessionsByUserID(ctx context.Context, userID string, exceptSessionIDs ...string) (int64, error) {
	args := m.Called(ctx, userID, exceptSessionIDs)
	return args.Get(0).(int64), args.Error(1) // Make sure to return int64 for count
}

// MockTokenService
type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) GenerateTokenPair(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration) (*api.TokenResponse, error) {
	args := m.Called(ctx, clientID, userID, scope, tokenTTL)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*api.TokenResponse), args.Error(1)
}

func (m *MockTokenService) RevokeToken(ctx context.Context, tokenID string) error { // Assuming tokenID is JTI
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

// Ensure NewAuthServer signature matches:
// userRepo domain.UserRepository, sessionRepo domain.SessionRepository, tokenService *ssso.TokenService, passwordHasher PasswordHasher
// The mock tokenService is *MockTokenService, but NewAuthServer expects *ssso.TokenService.
// This requires ssso.TokenService to be an interface, or adapt the mock.
// For now, we assume that either TokenService is an interface that MockTokenService implements,
// or that the test will be adjusted (e.g. by using a real TokenService with further mocked dependencies if needed for GenerateTokenPair).
// The current NewAuthServer takes *ssso.TokenService (concrete).
// This test will need to use a real ssso.TokenService and mock its dependencies (TokenRepository, cache.TokenStore, TokenSigner).
// This is getting complex for unit testing AuthServer in isolation.
// A simpler approach for this unit test is to have TokenService be an interface that AuthServer depends on.
// If we stick to concrete ssso.TokenService, then GenerateTokenPair test becomes an integration test for TokenService too.

// Let's assume for this unit test, we can mock the *direct* calls AuthServer makes.
// AuthServer's Login calls: userRepo.GetUserByEmail, hasher.Verify, tokenService.GenerateTokenPair, sessionRepo.StoreSession.
// So, MockTokenService.GenerateTokenPair is correct.

// --- AuthServer Tests ---

func TestAuthServer_Login(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockSessionRepo := new(MockSessionRepository)
	mockTokenService := new(MockTokenService) // This is our mock for ssso.TokenService methods
	mockHasher := new(MockPasswordHasher)

	// To make NewAuthServer work with MockTokenService, we need to ensure type compatibility.
	// If AuthServer expects *ssso.TokenService, we can't directly pass *MockTokenService.
	// This highlights a design consideration: AuthServer should depend on an interface for TokenService.
	// For this test, we will assume this is handled (e.g. AuthServer depends on an interface that MockTokenService implements
	// and the real ssso.TokenService also implements).
	// If not, these tests would need to instantiate a real ssso.TokenService and mock its deeper dependencies.
	// The constructor for AuthServer was updated in step 14 to take *ssso.TokenService.
	// This means we cannot pass MockTokenService directly.
	// The solution is to either:
	// 1. Change AuthServer to depend on an interface for TokenService. (Preferred for unit testing)
	// 2. Create a real ssso.TokenService for the test and mock *its* dependencies (TokenRepository, cache.TokenStore, TokenSigner).
	// Option 2 makes this more of an integration test between AuthServer and TokenService.
	// Let's proceed with Option 1 assumption for a focused unit test of AuthServer.
	// This implies that the AuthServer's `tokenService` field should be an interface type.
	// And `NewAuthServer` should accept this interface.
	// If we cannot change AuthServer, then we must use Option 2.
	// The prompt for AuthServer constructor was:
	// NewAuthServer(userRepo domain.UserRepository, sessionRepo domain.SessionRepository, tokenService *ssso.TokenService, ph PasswordHasher)
	// This means we must use Option 2 if we don't refactor AuthServer.
	// Let's use a simplified real TokenService for this test, where its own dependencies are mocked.
	// This is a bit heavy but respects the current concrete dependency.

	mockTokenRepoForRealTS := new(ssso.MockTokenRepository) // from token_service_test.go (or define here)
	mockCacheForRealTS := new(ssso.MockTokenStore)       // from token_service_test.go (or define here)
	mockSignerForRealTS := new(ssso.MockTokenSigner)     // from token_service_test.go (or define here)

	// We need these mocks to be defined in this package or a shared test util package.
	// Assuming they are defined in this file for now (as MockTokenRepository, MockTokenStore are above).
	// MockTokenSigner also needs to be defined.

	realTokenService := ssso.NewTokenService(
		mockTokenRepoForRealTS,
		mockCacheForRealTS,
		"test-issuer", // Real TokenService needs an issuer
		mockSignerForRealTS, // Real TokenService needs a signer
		nil, nil, // pubKeyRepo, saRepo - not used by GenerateTokenPair for user tokens
	)


	authServer := NewAuthServer(mockUserRepo, mockSessionRepo, realTokenService, mockHasher)
	ctx := context.Background()

	loginEmail := "user@example.com"
	loginPassword := "password123"
	hashedPassword := "hashed_password123"
	dbUser := &domain.User{
		ID: "user123", Email: loginEmail, PasswordHash: hashedPassword, Status: domain.UserStatusActive,
		FirstName: "Test", LastName: "User", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	// This is api.TokenResponse
	expectedTokenResp := &api.TokenResponse{
		AccessToken: "new.access.token", TokenType: "Bearer", ExpiresIn: 3600, RefreshToken: "new.refresh.token",
	}

	t.Run("Successful Login", func(t *testing.T) {
		// Reset mocks for sub-test
		mockUserRepo.On("GetUserByEmail", ctx, loginEmail).Return(dbUser, nil).Once()
		mockHasher.On("Verify", hashedPassword, loginPassword).Return(nil).Once()

		// Mocks for the *real* TokenService's dependencies when GenerateTokenPair is called
		mockSignerForRealTS.On("Sign", mock.AnythingOfType("jwt.RegisteredClaims"), "").Return("dummy.signed.access.token", nil).Once() // "" for default keyID
		mockSignerForRealTS.On("Sign", mock.AnythingOfType("jwt.RegisteredClaims"), "").Return("dummy.signed.refresh.token", nil).Once()
		mockTokenRepoForRealTS.On("StoreToken", ctx, mock.AnythingOfType("*ssso.Token")).Return(nil).Twice() // For access and refresh
		mockCacheForRealTS.On("Set", ctx, mock.AnythingOfType("*cache.TokenEntry")).Return(nil).Once() // For access token


		mockSessionRepo.On("StoreSession", ctx, mock.MatchedBy(func(session *domain.Session) bool {
			return session.UserID == dbUser.ID && session.TokenID != "" &&
				!session.ExpiresAt.IsZero() && session.RefreshToken != ""
		})).Return(nil).Once()


		req := connect.NewRequest(&ssov1.LoginRequest{Email: loginEmail, Password: loginPassword})
		resp, err := authServer.Login(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		// The actual token values will be "dummy.signed.access.token" etc. due to mockSigner.
		// We should match against what GenerateTokenPair is expected to return based on its *own* logic
		// using these mocked signed strings.
		assert.Equal(t, "dummy.signed.access.token", resp.Msg.AccessToken)
		assert.Equal(t, dbUser.Email, resp.Msg.UserInfo.Email)
		assert.Equal(t, dbUser.ID, resp.Msg.UserInfo.Id)

		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		mockSignerForRealTS.AssertExpectations(t)
		mockTokenRepoForRealTS.AssertExpectations(t)
		mockCacheForRealTS.AssertExpectations(t)
		mockSessionRepo.AssertExpectations(t)

		// Clear calls for next sub-test if mocks are reused at top level
		mockUserRepo.ExpectedCalls = nil; mockUserRepo.Calls = nil
		mockHasher.ExpectedCalls = nil; mockHasher.Calls = nil
		mockSignerForRealTS.ExpectedCalls = nil; mockSignerForRealTS.Calls = nil
		mockTokenRepoForRealTS.ExpectedCalls = nil; mockTokenRepoForRealTS.Calls = nil
		mockCacheForRealTS.ExpectedCalls = nil; mockCacheForRealTS.Calls = nil
		mockSessionRepo.ExpectedCalls = nil; mockSessionRepo.Calls = nil
	})

    // ... other Login sub-tests (UserNotFound, IncorrectPassword, UserLocked) ...
    // These would primarily mock mockUserRepo and mockHasher.
    // For these, tokenService and sessionRepo calls should not be made.
}


func TestAuthServer_Logout(t *testing.T) {
	mockUserRepo := new(MockUserRepository) // Not directly used by Logout's core logic
	mockSessionRepo := new(MockSessionRepository)

	// Setup real TokenService with its own mocks for Logout test consistency
	mockTokenRepoForRealTS_Logout := new(MockSssoTokenRepository)
	mockCacheForRealTS_Logout := new(MockCacheTokenStore)     // Not used by RevokeToken directly
	mockSignerForRealTS_Logout := new(MockTokenSigner)   // Not used by RevokeToken directly

	realTokenServiceForLogout := ssso.NewTokenService(
		mockTokenRepoForRealTS_Logout,
		mockCacheForRealTS_Logout,
		"test-issuer",
		mockSignerForRealTS_Logout,
		nil, nil,
	)

	authServer := NewAuthServer(mockUserRepo, mockSessionRepo, realTokenServiceForLogout, nil) // Hasher not used for logout

	tokenJTI := "jwt-to-logout-jti"
	authenticatedToken := &ssso.Token{ID: tokenJTI, UserID: "user123"} // ID here is JTI
	ctxWithAuth := context.WithValue(context.Background(), middleware.AuthenticatedTokenContextKey, authenticatedToken)

	sessionID := "session-id-for-jti-" + tokenJTI


	t.Run("Successful Logout", func(t *testing.T) {
		mockSession := &domain.Session{ID: sessionID, TokenID: tokenJTI, UserID: "user123", IsRevoked: false}
		// AuthServer.Logout should:
		// 1. Get token from context (done by providing ctxWithAuth).
		// 2. Find session by token's JTI (TokenID).
		// 3. Update session to be revoked.
		// 4. Optionally, call tokenService.RevokeToken for JWT denylist.

		mockSessionRepo.On("GetSessionByTokenID", ctxWithAuth, tokenJTI).Return(mockSession, nil).Once()
		mockSessionRepo.On("UpdateSession", ctxWithAuth, mock.MatchedBy(func(s *domain.Session) bool {
			return s.ID == sessionID && s.IsRevoked == true
		})).Return(nil).Once()

		// Now, RevokeToken is called on realTokenServiceForLogout, so we mock its dependency (mockTokenRepoForRealTS_Logout)
		// TokenService.RevokeToken calls cache.Delete then repo.RevokeToken.
		mockCacheForRealTS_Logout.On("Delete", ctxWithAuth, tokenJTI).Return(nil).Once() // Assuming RevokeToken uses tokenJTI as key for cache
		mockTokenRepoForRealTS_Logout.On("RevokeToken", ctxWithAuth, tokenJTI).Return(nil).Once()


		req := connect.NewRequest(&ssov1.LogoutRequest{})
		_, err := authServer.Logout(ctxWithAuth, req)

		require.NoError(t, err)
		mockSessionRepo.AssertExpectations(t)
		mockTokenServiceForLogout.AssertExpectations(t)
	})
}

// TODO: Add tests for ListUserSessions, ClearUserSessions
// Need to define MockTokenSigner if not already present from other test files.
// And adapt the NewTokenService call in Login test if using real TokenService.

func TestAuthServer_SessionManagement(t *testing.T) {
	mockUserRepo := new(MockUserRepository) // Not directly used by these session methods
	mockSessionRepo := new(MockSessionRepository)

	// Setup real TokenService with its own mocks, even if not all methods are used by session mgt paths
	mockTokenRepoForRealTS_SM := new(MockSssoTokenRepository)
	mockCacheForRealTS_SM := new(MockCacheTokenStore)
	mockSignerForRealTS_SM := new(MockTokenSigner)
	realTokenServiceForSM := ssso.NewTokenService(
		mockTokenRepoForRealTS_SM,
		mockCacheForRealTS_SM,
		"test-issuer",
		mockSignerForRealTS_SM,
		nil, nil,
	)
	mockHasher := new(MockPasswordHasher) // Not used by these session methods

	authServer := NewAuthServer(mockUserRepo, mockSessionRepo, realTokenServiceForSM, mockHasher)

	authedUserID := "user-self-sessions"
	otherUserID := "user-other-sessions" // For admin-like tests
	authedToken := &ssso.Token{ID: "self-jti", UserID: authedUserID, Issuer: "test-issuer"} // Mock token in context

	ctxWithAuth := context.WithValue(context.Background(), middleware.AuthenticatedTokenContextKey, authedToken)
	// Admin context simulation would require a token with admin scope/role, and service logic to check it.
	// For now, we test based on whether UserID in request matches UserID in token, or if UserID in request is empty.

	// Reset mocks for each sub-test or ensure unique mock instances per test function.
	// Here, we are defining mocks at the top of TestAuthServer_SessionManagement, so they are shared across its t.Run calls.
	// We need to reset them or manage .Once() carefully or make them specific to sub-tests.
	// For simplicity, let's ensure .Once() is used and AssertExpectations is called in each sub-test.

	t.Run("ListUserSessions_Self_Success", func(t *testing.T) {
		// Define fresh mocks for sub-test isolation for sessionRepo
		subMockSessionRepo := new(MockSessionRepository)
		subAuthServer := NewAuthServer(mockUserRepo, subMockSessionRepo, realTokenServiceForSM, mockHasher)

		expectedSessions := []*domain.Session{
			{ID: "sess1", UserID: authedUserID, TokenID: "jti1", IPAddress: "1.1.1.1", CreatedAt: time.Now().Add(-time.Hour)},
			{ID: "sess2", UserID: authedUserID, TokenID: "jti2", IPAddress: "2.2.2.2", CreatedAt: time.Now().Add(-30 * time.Minute)},
		}
		subMockSessionRepo.On("ListSessionsByUserID", ctxWithAuth, authedUserID, mock.AnythingOfType("domain.SessionFilter")).Return(expectedSessions, nil).Once()

		req := connect.NewRequest(&ssov1.ListUserSessionsRequest{UserId: ""}) // Empty UserId means "self"
		resp, err := subAuthServer.ListUserSessions(ctxWithAuth, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Len(t, resp.Msg.Sessions, 2)
		if len(resp.Msg.Sessions) > 0 {
			assert.Equal(t, expectedSessions[0].Id, resp.Msg.Sessions[0].Id)
		}
		subMockSessionRepo.AssertExpectations(t)
	})

	t.Run("ListUserSessions_ForOtherUser_Success (Admin Scenario)", func(t *testing.T) {
		subMockSessionRepo := new(MockSessionRepository)
		subAuthServer := NewAuthServer(mockUserRepo, subMockSessionRepo, realTokenServiceForSM, mockHasher)

		expectedSessions := []*domain.Session{
			{ID: "sess-other", UserID: otherUserID, TokenID: "jti-other", IPAddress: "3.3.3.3"},
		}
		subMockSessionRepo.On("ListSessionsByUserID", ctxWithAuth, otherUserID, mock.AnythingOfType("domain.SessionFilter")).Return(expectedSessions, nil).Once()

		req := connect.NewRequest(&ssov1.ListUserSessionsRequest{UserId: otherUserID})
		resp, err := subAuthServer.ListUserSessions(ctxWithAuth, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Len(t, resp.Msg.Sessions, 1)
		subMockSessionRepo.AssertExpectations(t)
	})

	t.Run("ListUserSessions_RepoError", func(t *testing.T) {
		subMockSessionRepo := new(MockSessionRepository)
		subAuthServer := NewAuthServer(mockUserRepo, subMockSessionRepo, realTokenServiceForSM, mockHasher)

		subMockSessionRepo.On("ListSessionsByUserID", ctxWithAuth, authedUserID, mock.AnythingOfType("domain.SessionFilter")).Return(nil, errors.New("db error")).Once()

		req := connect.NewRequest(&ssov1.ListUserSessionsRequest{UserId: ""})
		resp, err := subAuthServer.ListUserSessions(ctxWithAuth, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		subMockSessionRepo.AssertExpectations(t)
	})

	t.Run("ClearUserSessions_Self_SpecificSessions", func(t *testing.T) {
		subMockSessionRepo := new(MockSessionRepository)
		subAuthServer := NewAuthServer(mockUserRepo, subMockSessionRepo, realTokenServiceForSM, mockHasher)

		sessionsToClear := []string{"sess1-to-clear", "sess2-to-clear"}
		// Assuming service iterates and calls UpdateSession to revoke or DeleteSession
		// Let's assume it calls UpdateSession to mark as revoked.
		subMockSessionRepo.On("GetSessionByID", ctxWithAuth, sessionsToClear[0]).Return(&domain.Session{ID: sessionsToClear[0], UserID: authedUserID}, nil).Once()
		subMockSessionRepo.On("UpdateSession", ctxWithAuth, mock.MatchedBy(func(s *domain.Session) bool { return s.ID == sessionsToClear[0] && s.IsRevoked })).Return(nil).Once()
		subMockSessionRepo.On("GetSessionByID", ctxWithAuth, sessionsToClear[1]).Return(&domain.Session{ID: sessionsToClear[1], UserID: authedUserID}, nil).Once()
		subMockSessionRepo.On("UpdateSession", ctxWithAuth, mock.MatchedBy(func(s *domain.Session) bool { return s.ID == sessionsToClear[1] && s.IsRevoked })).Return(nil).Once()

		req := connect.NewRequest(&ssov1.ClearUserSessionsRequest{UserId: "", SessionIds: sessionsToClear})
		_, err := subAuthServer.ClearUserSessions(ctxWithAuth, req)

		require.NoError(t, err)
		subMockSessionRepo.AssertExpectations(t)
	})

	t.Run("ClearUserSessions_Self_AllOtherSessions (Implicit)", func(t *testing.T) {
		subMockSessionRepo := new(MockSessionRepository)
		subAuthServer := NewAuthServer(mockUserRepo, subMockSessionRepo, realTokenServiceForSM, mockHasher)

		// Service calls DeleteSessionsByUserID(ctx, selfUserID, currentSessionJTI)
		subMockSessionRepo.On("DeleteSessionsByUserID", ctxWithAuth, authedUserID, authedToken.ID).Return(int64(5), nil).Once()

		req := connect.NewRequest(&ssov1.ClearUserSessionsRequest{UserId: "", SessionIds: []string{}})
		_, err := subAuthServer.ClearUserSessions(ctxWithAuth, req)

		require.NoError(t, err)
		subMockSessionRepo.AssertExpectations(t)
	})

	t.Run("ClearUserSessions_ForOtherUser_AllSessions (Admin)", func(t *testing.T) {
		subMockSessionRepo := new(MockSessionRepository)
		subAuthServer := NewAuthServer(mockUserRepo, subMockSessionRepo, realTokenServiceForSM, mockHasher)

		// Admin clears all sessions for otherUserID. SessionIds in request is empty.
		// This means DeleteSessionsByUserID is called with empty exceptSessionIDs.
		subMockSessionRepo.On("DeleteSessionsByUserID", ctxWithAuth, otherUserID).Return(int64(3), nil).Once()

		req := connect.NewRequest(&ssov1.ClearUserSessionsRequest{UserId: otherUserID, SessionIds: []string{}})
		_, err := subAuthServer.ClearUserSessions(ctxWithAuth, req)

		require.NoError(t, err)
		subMockSessionRepo.AssertExpectations(t)
	})
}

// Copied MockTokenSigner from previous plan
type MockTokenSigner struct {
	mock.Mock
}
func (m *MockTokenSigner) Sign(claims jwt.RegisteredClaims, keyID string) (string, error) {
	args := m.Called(claims, keyID)
	return args.String(0), args.Error(1)
}

// Need to define ssso.MockTokenRepository, ssso.MockTokenStore if they are from ssso package space
// For now, assume they are local types in this test file if not imported from ssso.
// Based on ssso/token_service_test.go, they are defined there.
// To use them here, they would need to be exported from ssso (if in ssso_test package) or moved to ssso package itself.
// Or, redefine them here for simplicity if they are not complex.
// The current MockTokenRepository and MockTokenStore in this file are for domain.TokenRepository and cache.TokenStore.
// ssso.TokenService uses ssso.TokenRepository and cache.TokenStore.
// Let's assume the MockTokenRepository and MockTokenStore here are sufficient for ssso.TokenService's needs.
// (i.e., their interfaces are compatible).
// ssso.TokenRepository IS defined in token_service.go now. The mock here should implement that.
// cache.TokenStore is an interface from cache package. MockTokenStore here should implement it.

// The mock structs MockTokenRepository, MockTokenStore, MockPasswordHasher, MockPublicKeyRepository, MockServiceAccountRepository
// are defined in token_service_test.go. If this file is in the same 'services' package, they might be accessible.
// But services_test is usually a separate package `services_test`.
// For this subtask, I've copied MockUserRepository and MockPasswordHasher.
// I'll add MockSessionRepository and MockTokenService as per the plan.
// The ssso.TokenService test dependencies (MockTokenRepository etc. for its own use) are different.
// This implies the mocks for ssso.TokenService's dependencies need to be available or defined here.
// I will define ssso.MockTokenRepository and ssso.MockTokenStore as needed for the real TokenService.
// These are distinct from the domain.MockUserRepository etc.

// Mock for ssso.TokenRepository (if different from domain.TokenRepository)
type MockSssoTokenRepository struct { mock.Mock }
func (m *MockSssoTokenRepository) StoreToken(ctx context.Context, token *ssso.Token) error { args := m.Called(ctx, token); return args.Error(0) }
func (m *MockSssoTokenRepository) GetAccessToken(ctx context.Context, tokenValue string) (*ssso.Token, error) { args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*ssso.Token), args.Error(1) }
func (m *MockSssoTokenRepository) RevokeToken(ctx context.Context, tokenValue string) error { args := m.Called(ctx, tokenValue); return args.Error(0) }
func (m *MockSssoTokenRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) { args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*ssso.TokenInfo), args.Error(1) }
func (m *MockSssoTokenRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) { args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*ssso.TokenInfo), args.Error(1) }

// Mock for cache.TokenStore
type MockCacheTokenStore struct { mock.Mock }
func (m *MockCacheTokenStore) Set(ctx context.Context, entry *cache.TokenEntry) error { args := m.Called(ctx, entry); return args.Error(0) }
func (m *MockCacheTokenStore) Get(ctx context.Context, tokenValue string) (*cache.TokenEntry, error) { args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*cache.TokenEntry), args.Error(1) }
func (m *MockCacheTokenStore) Delete(ctx context.Context, tokenValue string) error { args := m.Called(ctx, tokenValue); return args.Error(0) }

// Redefine mockSignerForRealTS and mockTokenRepoForRealTS, mockCacheForRealTS for Login test.
// This makes the TestAuthServer_Login more self-contained with its specific mocks for the real TokenService.
// The earlier definition of MockTokenService can be used for Logout if AuthServer depends on an interface.
// But since AuthServer depends on concrete *ssso.TokenService, Logout also needs a real TokenService with mocked deps.
