package ssso

import (
	"context"
	"crypto"
	cryptorand "crypto/rand" // aliased to avoid conflict with testing's rand
	"crypto/rsa"
	"testing"
	"time"
	goerrors "errors"

	"github.com/pilab-dev/shadow-sso/api" // Ensure this is present and uncommented
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/client"
	ssoerrors "github.com/pilab-dev/shadow-sso/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// --- Mock OAuthRepository (implements OAuthRepository, which embeds other repos) ---
type MockOAuthRepository struct {
	mock.Mock
}
// DeviceAuthorizationRepository methods
func (m *MockOAuthRepository) SaveDeviceAuth(ctx context.Context, auth *DeviceCode) error { args := m.Called(ctx, auth); return args.Error(0) }
func (m *MockOAuthRepository) GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	args := m.Called(ctx, deviceCode); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*DeviceCode), args.Error(1)
}
func (m *MockOAuthRepository) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	args := m.Called(ctx, userCode); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*DeviceCode), args.Error(1)
}
func (m *MockOAuthRepository) ApproveDeviceAuth(ctx context.Context, userCode string, userID string) (*DeviceCode, error) {
	args := m.Called(ctx, userCode, userID); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*DeviceCode), args.Error(1)
}
func (m *MockOAuthRepository) UpdateDeviceAuthStatus(ctx context.Context, deviceCode string, status DeviceCodeStatus) error {
	args := m.Called(ctx, deviceCode, status); return args.Error(0)
}
func (m *MockOAuthRepository) UpdateDeviceAuthLastPolledAt(ctx context.Context, deviceCode string) error {
	args := m.Called(ctx, deviceCode); return args.Error(0)
}
func (m *MockOAuthRepository) DeleteExpiredDeviceAuths(ctx context.Context) error { args := m.Called(ctx); return args.Error(0) }

// AuthorizationCodeRepository methods
func (m *MockOAuthRepository) SaveAuthCode(ctx context.Context, code *AuthCode) error { args := m.Called(ctx, code); return args.Error(0) }
func (m *MockOAuthRepository) GetAuthCode(ctx context.Context, code string) (*AuthCode, error) { args := m.Called(ctx, code); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*AuthCode), args.Error(1) }
func (m *MockOAuthRepository) MarkAuthCodeAsUsed(ctx context.Context, code string) error { args := m.Called(ctx, code); return args.Error(0) }
func (m *MockOAuthRepository) DeleteExpiredAuthCodes(ctx context.Context) error { args := m.Called(ctx); return args.Error(0) }

// PkceRepository methods
func (m *MockOAuthRepository) SaveCodeChallenge(ctx context.Context, code, challenge string) error { args := m.Called(ctx, code, challenge); return args.Error(0) }
func (m *MockOAuthRepository) GetCodeChallenge(ctx context.Context, code string) (string, error) { args := m.Called(ctx, code); return args.String(0), args.Error(1) }
func (m *MockOAuthRepository) DeleteCodeChallenge(ctx context.Context, code string) error { args := m.Called(ctx, code); return args.Error(0) }

// TokenRepository methods (added for TokenService dependency)
func (m *MockOAuthRepository) StoreToken(ctx context.Context, token *Token) error { args := m.Called(ctx, token); return args.Error(0) }
func (m *MockOAuthRepository) GetAccessToken(ctx context.Context, tokenValue string) (*Token, error) {
	args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*Token), args.Error(1)
}
func (m *MockOAuthRepository) GetRefreshToken(ctx context.Context, tokenValue string) (*Token, error) {
	args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*Token), args.Error(1)
}
func (m *MockOAuthRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error) {
	args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*TokenInfo), args.Error(1)
}
func (m *MockOAuthRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error) {
	args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*TokenInfo), args.Error(1)
}
func (m *MockOAuthRepository) RevokeToken(ctx context.Context, tokenValue string) error { args := m.Called(ctx, tokenValue); return args.Error(0) }
func (m *MockOAuthRepository) RevokeRefreshToken(ctx context.Context, tokenValue string) error { args := m.Called(ctx, tokenValue); return args.Error(0) }
func (m *MockOAuthRepository) RevokeAllUserTokens(ctx context.Context, userID string) error { args := m.Called(ctx, userID); return args.Error(0) }
func (m *MockOAuthRepository) RevokeAllClientTokens(ctx context.Context, clientID string) error { args := m.Called(ctx, clientID); return args.Error(0) }
func (m *MockOAuthRepository) DeleteExpiredTokens(ctx context.Context) error { args := m.Called(ctx); return args.Error(0) }
func (m *MockOAuthRepository) ValidateAccessToken(ctx context.Context, token string) (string, error) { args := m.Called(ctx, token); return args.String(0), args.Error(1) }
func (m *MockOAuthRepository) GetTokenInfo(ctx context.Context, tokenValue string) (*Token, error) {
	args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*Token), args.Error(1)
}

// io.Closer method
func (m *MockOAuthRepository) Close() error { args := m.Called(); return args.Error(0) }

// --- MockCacheTokenStore ---
type MockCacheTokenStore struct {
	mock.Mock
}
func (m *MockCacheTokenStore) Set(ctx context.Context, token *cache.TokenEntry) error { args := m.Called(ctx, token); return args.Error(0) }
func (m *MockCacheTokenStore) Get(ctx context.Context, token string) (*cache.TokenEntry, error) {
	args := m.Called(ctx, token); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*cache.TokenEntry), args.Error(1)
}
func (m *MockCacheTokenStore) Delete(ctx context.Context, token string) error { args := m.Called(ctx, token); return args.Error(0) }
func (m *MockCacheTokenStore) DeleteExpired(ctx context.Context) error { args := m.Called(ctx); return args.Error(0) }
func (m *MockCacheTokenStore) Clear(ctx context.Context) error { args := m.Called(ctx); return args.Error(0) }
func (m *MockCacheTokenStore) Count(ctx context.Context) int { args := m.Called(ctx); return args.Int(0) }


// --- Mock ClientStore ---
type MockClientStore struct { mock.Mock }
func (m *MockClientStore) CreateClient(ctx context.Context, cl *client.Client) error { args := m.Called(ctx, cl); return args.Error(0) }
func (m *MockClientStore) GetClient(ctx context.Context, clientID string) (*client.Client, error) {
	args := m.Called(ctx, clientID); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*client.Client), args.Error(1)
}
func (m *MockClientStore) UpdateClient(ctx context.Context, cl *client.Client) error { args := m.Called(ctx, cl); return args.Error(0) }
func (m *MockClientStore) DeleteClient(ctx context.Context, clientID string) error { args := m.Called(ctx, clientID); return args.Error(0) }
func (m *MockClientStore) ListClients(ctx context.Context, filter client.ClientFilter) ([]*client.Client, error) {
	args := m.Called(ctx, filter); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).([]*client.Client), args.Error(1)
}
func (m* MockClientStore) ValidateClient(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
	args := m.Called(ctx, clientID, clientSecret); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*client.Client), args.Error(1)
}
func (m* MockClientStore) ValidateRedirectURI(ctx context.Context, clientID, redirectURI string) error { args := m.Called(ctx, clientID, redirectURI); return args.Error(0) }
func (m* MockClientStore) ValidateGrantType(ctx context.Context, clientID, grantType string) error { args := m.Called(ctx, clientID, grantType); return args.Error(0) }
func (m* MockClientStore) ValidateScope(ctx context.Context, clientID string, scopes []string) error { args := m.Called(ctx, clientID, scopes); return args.Error(0) }
func (m* MockClientStore) RequiresPKCE(ctx context.Context, clientID string) (bool, error) { args := m.Called(ctx, clientID); return args.Bool(0), args.Error(1) }

// --- Mock UserStore ---
type MockUserStore struct { mock.Mock }
func (m *MockUserStore) CreateUser(ctx context.Context, username, password string) (*User, error) {
	args := m.Called(ctx, username, password); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*User), args.Error(1)
}
func (m *MockUserStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	args := m.Called(ctx, username); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*User), args.Error(1)
}
func (m *MockUserStore) GetUserByID(ctx context.Context, userID string) (*User, error) {
	args := m.Called(ctx, userID); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*User), args.Error(1)
}
func (m *MockUserStore) UpdateUser(ctx context.Context, user *User) error { args := m.Called(ctx, user); return args.Error(0) }
func (m *MockUserStore) DeleteUser(ctx context.Context, id string) error { args := m.Called(ctx, id); return args.Error(0) }
func (m *MockUserStore) FindUserByExternalProviderID(ctx context.Context, providerID string, externalID string) (*User, error) {
	args := m.Called(ctx, providerID, externalID); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*User), args.Error(1)
}
func (m *MockUserStore) CreateSession(ctx context.Context, userID string, session *UserSession) error { args := m.Called(ctx, userID, session); return args.Error(0) }
func (m *MockUserStore) GetUserSessions(ctx context.Context, userID string) ([]UserSession, error) {
	args := m.Called(ctx, userID); if args.Get(0) == nil { return ([]UserSession)(nil), args.Error(1) }; return args.Get(0).([]UserSession), args.Error(1)
}
func (m *MockUserStore) GetSessionByToken(ctx context.Context, token string) (*UserSession, error) {
	args := m.Called(ctx, token); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*UserSession), args.Error(1)
}
func (m *MockUserStore) UpdateSessionLastUsed(ctx context.Context, sessionID string) error { args := m.Called(ctx, sessionID); return args.Error(0) }
func (m *MockUserStore) RevokeSession(ctx context.Context, sessionID string) error { args := m.Called(ctx, sessionID); return args.Error(0) }
func (m *MockUserStore) DeleteExpiredSessions(ctx context.Context, userID string) error { args := m.Called(ctx, userID); return args.Error(0) }

func assertIsOAuthErrorCode(t *testing.T, err error, expectedCode string) {
	t.Helper()
	var oauthErr *ssoerrors.OAuth2Error
	if assert.True(t, goerrors.As(err, &oauthErr), "Error should be of type *ssoerrors.OAuth2Error. Got: %v", err) {
		assert.Equal(t, expectedCode, oauthErr.Code, "Error code does not match")
	}
}

var testSigner crypto.Signer
var testKeyID = "test-key-id-for-oauth-service-tests"

func init() {
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 512)
	if err != nil {
		panic("Failed to generate test RSA key: " + err.Error())
	}
	testSigner = privateKey
}


func TestOAuthService_InitiateDeviceAuthorization(t *testing.T) {
	mockRepo := new(MockOAuthRepository)
	mockClientStore := new(MockClientStore)
	mockUserStore := new(MockUserStore)
	mockCache := new(MockCacheTokenStore)

	testTokenSigner := NewTokenSigner()
	testTokenSigner.AddKeySigner("test-secret-for-oauth-service")

	realTokenService := NewTokenService(mockRepo, mockCache, "test-issuer", testTokenSigner)

	testService := &OAuthService{
		oauthRepo:    mockRepo,
		clientRepo:   mockClientStore,
		userRepo:     mockUserStore,
		issuer:       "test-issuer",
		tokenService: realTokenService,
	}

	testClient := &client.Client{ID: "test-client", AllowedGrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}}

	t.Run("success", func(t *testing.T) {
		localMockRepo := new(MockOAuthRepository)
		localMockClientStore := new(MockClientStore)
		testService.oauthRepo = localMockRepo
		testService.clientRepo = localMockClientStore
		if testService.tokenService != nil {
			testService.tokenService.repo = localMockRepo
		}


		localMockClientStore.On("GetClient", mock.Anything, "test-client").Return(testClient, nil).Once()
		localMockRepo.On("SaveDeviceAuth", mock.Anything, mock.MatchedBy(func(auth *DeviceCode) bool {
			return auth.ClientID == "test-client" && auth.Scope == "test-scope" && auth.DeviceCode != "" && auth.UserCode != ""
		})).Return(nil).Once()

		resp, err := testService.InitiateDeviceAuthorization(context.Background(), "test-client", "test-scope", "https://example.com")

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.DeviceCode)
		assert.NotEmpty(t, resp.UserCode)
		assert.Equal(t, int(deviceCodeLifetime.Seconds()), resp.ExpiresIn)
		assert.Equal(t, defaultPollInterval, resp.Interval)
		assert.Equal(t, "https://example.com/device", resp.VerificationURI)
		assert.Contains(t, resp.VerificationURIComplete, resp.UserCode)
		localMockRepo.AssertExpectations(t)
		localMockClientStore.AssertExpectations(t)
	})

	t.Run("client not found", func(t *testing.T) {
		localMockClientStore := new(MockClientStore)
		testService.clientRepo = localMockClientStore

		localMockClientStore.On("GetClient", mock.Anything, "unknown-client").Return(nil, ssoerrors.NewInvalidClient("client not found")).Once()

		_, err := testService.InitiateDeviceAuthorization(context.Background(), "unknown-client", "test-scope", "https://example.com")

		assert.Error(t, err)
		assertIsOAuthErrorCode(t, err, ssoerrors.InvalidClient)
		localMockClientStore.AssertExpectations(t)
	})
}

func TestOAuthService_VerifyUserCode(t *testing.T) {
	mockRepo := new(MockOAuthRepository)
	mockCache := new(MockCacheTokenStore)
	testTokenSigner := NewTokenSigner()
	testTokenSigner.AddKeySigner("test-secret")
	realTokenService := NewTokenService(mockRepo, mockCache, "test-issuer", testTokenSigner)

	service := &OAuthService{oauthRepo: mockRepo, issuer: "test-issuer", tokenService: realTokenService}

	userID := "user123"
	userCodeVal := "GOODCODE"

	validDeviceAuth := &DeviceCode{
		DeviceCode: "some-device-code", UserCode:   userCodeVal, ClientID:   "client-abc",
		Status:     DeviceCodeStatusPending, ExpiresAt:  time.Now().Add(5 * time.Minute),
	}

	t.Run("success", func(t *testing.T) {
		localMockRepo := new(MockOAuthRepository)
		service.oauthRepo = localMockRepo
		if service.tokenService != nil {
			service.tokenService.repo = localMockRepo
		}

		localMockRepo.On("GetDeviceAuthByUserCode", mock.Anything, userCodeVal).Return(validDeviceAuth, nil).Once()

		approvedDeviceAuth := *validDeviceAuth
		approvedDeviceAuth.Status = DeviceCodeStatusAuthorized
		approvedDeviceAuth.UserID = userID
		localMockRepo.On("ApproveDeviceAuth", mock.Anything, userCodeVal, userID).Return(&approvedDeviceAuth, nil).Once()

		approvedAuth, err := service.VerifyUserCode(context.Background(), userCodeVal, userID)

		assert.NoError(t, err)
		assert.NotNil(t, approvedAuth)
		assert.Equal(t, DeviceCodeStatusAuthorized, approvedAuth.Status)
		assert.Equal(t, userID, approvedAuth.UserID)
		localMockRepo.AssertExpectations(t)
	})

	t.Run("user code not found", func(t *testing.T) {
		localMockRepo := new(MockOAuthRepository)
		service.oauthRepo = localMockRepo
		if service.tokenService != nil {
			service.tokenService.repo = localMockRepo
		}

		localMockRepo.On("GetDeviceAuthByUserCode", mock.Anything, "BADCODE").Return(nil, ErrUserCodeNotFound).Once()

		_, err := service.VerifyUserCode(context.Background(), "BADCODE", userID)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUserCodeNotFound)
		localMockRepo.AssertExpectations(t)
	})

	t.Run("device already processed", func(t *testing.T) {
		localMockRepo := new(MockOAuthRepository)
		service.oauthRepo = localMockRepo
		if service.tokenService != nil {
			service.tokenService.repo = localMockRepo
		}

		alreadyAuthorizedAuth := *validDeviceAuth
		alreadyAuthorizedAuth.Status = DeviceCodeStatusAuthorized
		localMockRepo.On("GetDeviceAuthByUserCode", mock.Anything, userCodeVal).Return(&alreadyAuthorizedAuth, nil).Once()

		_, err := service.VerifyUserCode(context.Background(), userCodeVal, userID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrCannotApproveDeviceAuth)
		localMockRepo.AssertExpectations(t)
	})

	t.Run("device expired", func(t *testing.T) {
		localMockRepo := new(MockOAuthRepository)
		service.oauthRepo = localMockRepo
		if service.tokenService != nil {
			service.tokenService.repo = localMockRepo
		}

		expiredAuth := *validDeviceAuth
		expiredAuth.ExpiresAt = time.Now().Add(-5 * time.Minute)
		localMockRepo.On("GetDeviceAuthByUserCode", mock.Anything, userCodeVal).Return(&expiredAuth, nil).Once()
		localMockRepo.On("UpdateDeviceAuthStatus", mock.Anything, expiredAuth.DeviceCode, DeviceCodeStatusExpired).Return(nil).Once()

		_, err := service.VerifyUserCode(context.Background(), userCodeVal, userID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUserCodeNotFound)
		localMockRepo.AssertExpectations(t)
	})
}

func TestOAuthService_IssueTokenForDeviceFlow(t *testing.T) {
    mockRepo := new(MockOAuthRepository)
    mockUserStore := new(MockUserStore)
    mockCache := new(MockCacheTokenStore)

    testTokenSigner := NewTokenSigner()
	testTokenSigner.AddKeySigner("test-secret-for-device-flow")
    realTokenService := NewTokenService(mockRepo, mockCache, "test-issuer", testTokenSigner)

    service := &OAuthService{
        oauthRepo:    mockRepo,
        tokenService: realTokenService,
        issuer:       "test-issuer",
        clientRepo:   new(MockClientStore),
        userRepo:     mockUserStore,
    }

    clientID := "client-123"
    deviceCodeVal := "deviceXYZ"
    userID := "user-abc"
    scope := "read write"

    baseDeviceAuth := DeviceCode{
        DeviceCode: deviceCodeVal, UserCode: "USERCODE", ClientID: clientID, UserID: userID,
        Scope: scope, ExpiresAt:  time.Now().Add(10 * time.Minute), Interval: 5,
    }

    t.Run("success - authorized", func(t *testing.T) {
        localMockRepo := new(MockOAuthRepository)
		localMockCache := new(MockCacheTokenStore)
        service.oauthRepo = localMockRepo
		if service.tokenService != nil {
		service.tokenService.repo = localMockRepo
			service.tokenService.cache = localMockCache
		}


        authorizedAuth := baseDeviceAuth
        authorizedAuth.Status = DeviceCodeStatusAuthorized

        // This is where api.TokenResponse is used
        expectedTokenResp := &api.TokenResponse{AccessToken: "new-access-token", TokenType: "Bearer", ExpiresIn: 3600}

        localMockRepo.On("GetDeviceAuthByDeviceCode", mock.Anything, deviceCodeVal).Return(&authorizedAuth, nil).Once()

        localMockRepo.On("StoreToken", mock.Anything, mock.MatchedBy(func(token *Token) bool {
			return token.TokenType == "access_token" && token.ClientID == clientID && token.UserID == userID
		})).Return(nil).Run(func(args mock.Arguments) {
			tokenArg := args.Get(1).(*Token)
			expectedTokenResp.AccessToken = tokenArg.TokenValue
		}).Once()
        localMockRepo.On("StoreToken", mock.Anything, mock.MatchedBy(func(token *Token) bool {
			return token.TokenType == "refresh_token" && token.ClientID == clientID && token.UserID == userID
		})).Return(nil).Run(func(args mock.Arguments) {
			tokenArg := args.Get(1).(*Token)
			expectedTokenResp.RefreshToken = tokenArg.TokenValue
		}).Once()

		localMockCache.On("Set", mock.Anything, mock.MatchedBy(func(entry *cache.TokenEntry) bool {
			return entry.TokenType == "access_token" && entry.ClientID == clientID && entry.UserID == userID
		})).Return(nil).Once()

        localMockRepo.On("UpdateDeviceAuthStatus", mock.Anything, deviceCodeVal, DeviceCodeStatusRedeemed).Return(nil).Once()

        tokenResp, err := service.IssueTokenForDeviceFlow(context.Background(), deviceCodeVal, clientID)

        assert.NoError(t, err)
        assert.NotNil(t, tokenResp)
		assert.NotEmpty(t, tokenResp.AccessToken)
		assert.NotEmpty(t, tokenResp.RefreshToken)
		assert.Equal(t, "Bearer", tokenResp.TokenType)
		assert.Equal(t, expectedTokenResp.AccessToken, tokenResp.AccessToken)
		assert.Equal(t, expectedTokenResp.RefreshToken, tokenResp.RefreshToken)

        localMockRepo.AssertExpectations(t)
		localMockCache.AssertExpectations(t)
    })

    t.Run("pending authorization", func(t *testing.T) {
        localMockRepo := new(MockOAuthRepository)
        service.oauthRepo = localMockRepo
        if service.tokenService != nil { service.tokenService.repo = localMockRepo }

        pendingAuth := baseDeviceAuth
        pendingAuth.Status = DeviceCodeStatusPending

        localMockRepo.On("GetDeviceAuthByDeviceCode", mock.Anything, deviceCodeVal).Return(&pendingAuth, nil).Once()
        localMockRepo.On("UpdateDeviceAuthLastPolledAt", mock.Anything, deviceCodeVal).Return(nil).Once()

        _, err := service.IssueTokenForDeviceFlow(context.Background(), deviceCodeVal, clientID)

        assert.Error(t, err)
        assert.ErrorIs(t, err, ErrAuthorizationPending)
        localMockRepo.AssertExpectations(t)
    })

    t.Run("expired token status", func(t *testing.T) {
        localMockRepo := new(MockOAuthRepository)
        service.oauthRepo = localMockRepo
        if service.tokenService != nil { service.tokenService.repo = localMockRepo }

        expiredAuth := baseDeviceAuth
        expiredAuth.Status = DeviceCodeStatusExpired

        localMockRepo.On("GetDeviceAuthByDeviceCode", mock.Anything, deviceCodeVal).Return(&expiredAuth, nil).Once()

        _, err := service.IssueTokenForDeviceFlow(context.Background(), deviceCodeVal, clientID)

        assert.Error(t, err)
        assert.ErrorIs(t, err, ErrDeviceFlowTokenExpired)
        localMockRepo.AssertExpectations(t)
    })

    t.Run("client ID mismatch", func(t *testing.T) {
        localMockRepo := new(MockOAuthRepository)
        service.oauthRepo = localMockRepo
        if service.tokenService != nil { service.tokenService.repo = localMockRepo }

        authWithDifferentClient := baseDeviceAuth
        authWithDifferentClient.Status = DeviceCodeStatusAuthorized

        localMockRepo.On("GetDeviceAuthByDeviceCode", mock.Anything, deviceCodeVal).Return(&authWithDifferentClient, nil).Once()

        _, err := service.IssueTokenForDeviceFlow(context.Background(), deviceCodeVal, "mismatched-client-id")

        assert.Error(t, err)
		assertIsOAuthErrorCode(t, err, ssoerrors.InvalidClient)
        localMockRepo.AssertExpectations(t)
    })

     t.Run("device code not found", func(t *testing.T) {
        localMockRepo := new(MockOAuthRepository)
        service.oauthRepo = localMockRepo
        if service.tokenService != nil { service.tokenService.repo = localMockRepo }

        localMockRepo.On("GetDeviceAuthByDeviceCode", mock.Anything, "nonexistent-code").Return(nil, ErrDeviceCodeNotFound).Once()

        _, err := service.IssueTokenForDeviceFlow(context.Background(), "nonexistent-code", clientID)

        assert.Error(t, err)
        assert.ErrorIs(t, err, ErrDeviceFlowTokenExpired)
        localMockRepo.AssertExpectations(t)
    })
}
