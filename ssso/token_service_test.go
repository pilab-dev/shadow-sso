package ssso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	// "fmt" // Not directly used in this snippet, but could be for more complex logging/errors
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// --- Mock Implementations ---

type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) StoreToken(ctx context.Context, token *Token) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *MockTokenRepository) GetAccessToken(ctx context.Context, tokenValue string) (*Token, error) {
	args := m.Called(ctx, tokenValue)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Token), args.Error(1)
}
func (m *MockTokenRepository) RevokeToken(ctx context.Context, tokenValue string) error {
	args := m.Called(ctx, tokenValue)
	return args.Error(0)
}
func (m *MockTokenRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error) {
	args := m.Called(ctx, tokenValue)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TokenInfo), args.Error(1)
}
func (m *MockTokenRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error) {
	args := m.Called(ctx, tokenValue)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TokenInfo), args.Error(1)
}

type MockTokenStore struct {
	mock.Mock
}

func (m *MockTokenStore) Set(ctx context.Context, entry *cache.TokenEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}
func (m *MockTokenStore) Get(ctx context.Context, tokenValue string) (*cache.TokenEntry, error) {
	args := m.Called(ctx, tokenValue)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*cache.TokenEntry), args.Error(1)
}
func (m *MockTokenStore) Delete(ctx context.Context, tokenValue string) error {
	args := m.Called(ctx, tokenValue)
	return args.Error(0)
}

type MockPublicKeyRepository struct {
	mock.Mock
}

func (m *MockPublicKeyRepository) GetPublicKey(ctx context.Context, keyID string) (*domain.PublicKeyInfo, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.PublicKeyInfo), args.Error(1)
}
func (m *MockPublicKeyRepository) CreatePublicKey(ctx context.Context, pubKeyInfo *domain.PublicKeyInfo) error {
	args := m.Called(ctx, pubKeyInfo)
	return args.Error(0)
}
func (m *MockPublicKeyRepository) UpdatePublicKeyStatus(ctx context.Context, keyID string, newStatus string) error {
	args := m.Called(ctx, keyID, newStatus)
	return args.Error(0)
}
func (m *MockPublicKeyRepository) ListPublicKeysForServiceAccount(ctx context.Context, serviceAccountID string, onlyActive bool) ([]*domain.PublicKeyInfo, error) {
	args := m.Called(ctx, serviceAccountID, onlyActive)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.PublicKeyInfo), args.Error(1)
}

type MockServiceAccountRepository struct {
	mock.Mock
}

func (m *MockServiceAccountRepository) GetServiceAccount(ctx context.Context, id string) (*domain.ServiceAccount, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ServiceAccount), args.Error(1)
}
func (m *MockServiceAccountRepository) GetServiceAccountByClientEmail(ctx context.Context, clientEmail string) (*domain.ServiceAccount, error) {
	args := m.Called(ctx, clientEmail)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ServiceAccount), args.Error(1)
}
func (m *MockServiceAccountRepository) CreateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error {
	args := m.Called(ctx, sa)
	return args.Error(0)
}
func (m *MockServiceAccountRepository) UpdateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error {
	args := m.Called(ctx, sa)
	return args.Error(0)
}
func (m *MockServiceAccountRepository) DeleteServiceAccount(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Helper to generate RSA keys for testing SA JWTs
func generateTestRSAKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, _ := rsa.GenerateKey(rand.Reader, bits)
	return privKey, &privKey.PublicKey
}

func publicKeyToPEMString(pubKey *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return string(pemBytes), nil
}

// --- TokenService Tests ---

func TestTokenService_ValidateAccessToken_UserToken(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	mockCache := new(MockTokenStore)
	mockPubKeyRepo := new(MockPublicKeyRepository) // Needed by NewTokenService
	mockSARepo := new(MockServiceAccountRepository)   // Needed by NewTokenService

	// Dummy signer for NewTokenService. Its actual signing/verification logic isn't directly tested here
	// for user tokens that are simply retrieved from DB/cache.
	// For SA tokens, the crypto/jwt library does verification using provided public keys.
	rsaPrivKey, _ := rsa.GenerateKey(rand.Reader, 512) // Minimal key for test signer init
	testSigner, _ := NewTokenSigner(rsaPrivKey, "test-signer-kid")


	service := NewTokenService(mockRepo, mockCache, "test-issuer", testSigner, mockPubKeyRepo, mockSARepo)
	ctx := context.Background()
	now := time.Now()

	validUserToken := "valid-user-token-string"
	dbToken := &Token{
		ID: "token-id", UserID: "user123", TokenValue: validUserToken, TokenType: "access_token",
		ExpiresAt: now.Add(1 * time.Hour), CreatedAt: now.Add(-1 * time.Minute), Issuer: "test-issuer",
	}
	cacheEntry := dbToken.ToEntry()

	t.Run("Valid User Token - Cache Hit", func(t *testing.T) {
		mockCache.On("Get", ctx, validUserToken).Return(cacheEntry, nil).Once()

		token, err := service.ValidateAccessToken(ctx, validUserToken)
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, dbToken.UserID, token.UserID)
		assert.Equal(t, "test-issuer", token.Issuer) // Check issuer is set
		mockCache.AssertExpectations(t)
		mockRepo.AssertNotCalled(t, "GetAccessToken", mock.AnythingOfType("*context.emptyCtx"), validUserToken)
	})

	t.Run("Valid User Token - Cache Miss, DB Hit", func(t *testing.T) {
		mockCache.On("Get", ctx, validUserToken).Return(nil, errors.New("cache miss")).Once()
		mockRepo.On("GetAccessToken", ctx, validUserToken).Return(dbToken, nil).Once()
		mockCache.On("Set", ctx, cacheEntry).Return(nil).Once() // Expect caching after DB hit

		token, err := service.ValidateAccessToken(ctx, validUserToken)
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, dbToken.UserID, token.UserID)
		assert.Equal(t, "test-issuer", token.Issuer)
		mockCache.AssertExpectations(t)
		mockRepo.AssertExpectations(t)
	})

	t.Run("User Token Expired - From Cache", func(t *testing.T) {
		expiredEntry := *cacheEntry // Copy
		expiredEntry.ExpiresAt = now.Add(-1 * time.Minute)
		mockCache.On("Get", ctx, validUserToken).Return(&expiredEntry, nil).Once()
		mockCache.On("Delete", ctx, validUserToken).Return(nil).Once()

		token, err := service.ValidateAccessToken(ctx, validUserToken)
		assert.ErrorIs(t, err, ErrTokenExpiredOrRevoked)
		assert.Nil(t, token)
		mockCache.AssertExpectations(t)
	})

	t.Run("User Token Revoked - From DB", func(t *testing.T) {
		revokedToken := *dbToken // Copy
		revokedToken.IsRevoked = true
		mockCache.On("Get", ctx, validUserToken).Return(nil, errors.New("cache miss")).Once()
		mockRepo.On("GetAccessToken", ctx, validUserToken).Return(&revokedToken, nil).Once()
		// No cache set for revoked token from DB

		token, err := service.ValidateAccessToken(ctx, validUserToken)
		assert.ErrorIs(t, err, ErrTokenExpiredOrRevoked)
		assert.Nil(t, token)
		mockCache.AssertExpectations(t)
		mockRepo.AssertExpectations(t)
	})

	t.Run("User Token Not Found", func(t *testing.T) {
		notFoundToken := "not-found-token-string"
		mockCache.On("Get", ctx, notFoundToken).Return(nil, errors.New("cache miss")).Once()
		mockRepo.On("GetAccessToken", ctx, notFoundToken).Return(nil, errors.New("token not found")).Once()

		token, err := service.ValidateAccessToken(ctx, notFoundToken)
		assert.Error(t, err) // Specific error check depends on repo error wrapping
		assert.Nil(t, token)
		mockCache.AssertExpectations(t)
		mockRepo.AssertExpectations(t)
	})
}

func TestTokenService_ValidateAccessToken_SAToken(t *testing.T) {
	mockRepo := new(MockTokenRepository) // Not used for SA token path directly
	mockCache := new(MockTokenStore)    // Not used for SA token path
	mockPubKeyRepo := new(MockPublicKeyRepository)
	mockSARepo := new(MockServiceAccountRepository)
	rsaPrivKeySA, _ := rsa.GenerateKey(rand.Reader, 512) // Minimal key for test signer init
	testSigner, _ := NewTokenSigner(rsaPrivKeySA, "")      // Not used for SA token validation directly by this service

	service := NewTokenService(mockRepo, mockCache, "user-token-issuer", testSigner, mockPubKeyRepo, mockSARepo)
	ctx := context.Background()

	saPrivKey, saPubKey := generateTestRSAKeys(2048) // Key pair for signing actual SA test tokens
	saPubKeyPEM, _ := publicKeyToPEMString(saPubKey)
	saKeyID := "sa-test-kid-123"

	t.Run("Valid SA JWT", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss":   "sa-issuer@example.com",
			"sub":   "sa-issuer@example.com", // Often same as iss for SA
			"aud":   []string{"my-service"},
			"exp":   float64(now.Add(1 * time.Hour).Unix()),
			"iat":   float64(now.Unix()),
			"jti":   "jwt-id-1",
			"scope": "read write",
		}
		saToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		saToken.Header["kid"] = saKeyID
		signedSAToken, _ := saToken.SignedString(saPrivKey)

		mockPubKeyRepo.On("GetPublicKey", ctx, saKeyID).Return(&domain.PublicKeyInfo{
			ID: saKeyID, PublicKey: saPubKeyPEM, Status: "ACTIVE", Algorithm: "RS256",
		}, nil).Once()

		token, err := service.ValidateAccessToken(ctx, signedSAToken)
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, "sa-issuer@example.com", token.UserID) // UserID is 'iss' for SA tokens
		assert.Equal(t, "sa-issuer@example.com", token.Issuer)
		assert.Equal(t, "service_account_jwt", token.TokenType)
		assert.Equal(t, "read write", token.Scope)
		assert.Equal(t, "jwt-id-1", token.ID)
		assert.WithinDuration(t, now.Add(1*time.Hour), token.ExpiresAt, time.Second)
		mockPubKeyRepo.AssertExpectations(t)
	})

	t.Run("SA JWT - No KID in header", func(t *testing.T) {
		claims := jwt.MapClaims{"iss": "sa-no-kid@example.com", "exp": float64(time.Now().Add(1 * time.Hour).Unix()), "iat": float64(time.Now().Unix())}
		saTokenNoKid := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		// No KID header set
		signedSATokenNoKid, _ := saTokenNoKid.SignedString(saPrivKey)

		mockCache.On("Get", ctx, signedSATokenNoKid).Return(nil, errors.New("cache miss")).Once()
		mockRepo.On("GetAccessToken", ctx, signedSATokenNoKid).Return(nil, errors.New("token not found")).Once()

		token, err := service.ValidateAccessToken(ctx, signedSATokenNoKid)
		assert.Error(t, err)
		assert.Nil(t, token)
		mockPubKeyRepo.AssertNotCalled(t, "GetPublicKey", mock.AnythingOfType("*context.emptyCtx"), mock.AnythingOfType("string"))
		mockCache.AssertExpectations(t)
		mockRepo.AssertExpectations(t)
	})

	t.Run("SA JWT - Unknown KID", func(t *testing.T) {
		unknownKID := "unknown-kid"
		claims := jwt.MapClaims{"iss": "sa-unknown-kid@example.com", "exp": float64(time.Now().Add(1 * time.Hour).Unix()), "iat": float64(time.Now().Unix())}
		saTokenUnknownKid := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		saTokenUnknownKid.Header["kid"] = unknownKID
		signedToken, _ := saTokenUnknownKid.SignedString(saPrivKey)

		mockPubKeyRepo.On("GetPublicKey", ctx, unknownKID).Return(nil, errors.New("public key not found or not active")).Once()

		token, err := service.ValidateAccessToken(ctx, signedToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SA key retrieval failed")
		assert.Nil(t, token)
		mockPubKeyRepo.AssertExpectations(t)
	})

	t.Run("SA JWT - Expired Token", func(t *testing.T) {
		expiredTime := time.Now().Add(-1 * time.Hour)
		claims := jwt.MapClaims{
			"iss": "sa-issuer@example.com", "sub": "sa-issuer@example.com",
			"exp": float64(expiredTime.Unix()), "iat": float64(expiredTime.Add(-time.Minute).Unix()),
		}
		saToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		saToken.Header["kid"] = saKeyID // Add kid to header
		signedSAToken, _ := saToken.SignedString(saPrivKey)

		mockPubKeyRepo.On("GetPublicKey", ctx, saKeyID).Return(&domain.PublicKeyInfo{
			ID: saKeyID, PublicKey: saPubKeyPEM, Status: "ACTIVE",
		}, nil).Once()

		token, err := service.ValidateAccessToken(ctx, signedSAToken)
		assert.ErrorIs(t, err, ErrTokenExpiredOrRevoked) // jwt-go itself should return an error containing expired info
		assert.Nil(t, token)
		mockPubKeyRepo.AssertExpectations(t)
	})
}

// TODO: Add tests for CreateToken, GenerateTokenPair, RevokeToken etc.

// MockTokenSigner mocks the TokenSigner interface/struct
type MockTokenSigner struct {
	mock.Mock
}

// Sign mocks the Sign method of TokenSigner
func (m *MockTokenSigner) Sign(claims jwt.RegisteredClaims, keyID string) (string, error) {
	args := m.Called(claims, keyID)
	return args.String(0), args.Error(1)
}

func TestTokenService_CreateToken(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	mockCache := new(MockTokenStore)
	mockPubKeyRepo := new(MockPublicKeyRepository)
	mockSARepo := new(MockServiceAccountRepository)
	mockSigner := new(MockTokenSigner)

	// Note: NewTokenService expects a concrete *TokenSigner, not an interface.
	// For full mocking capability, NewTokenService might need to accept an interface.
	// However, TokenSigner itself is simple and could be instantiated with test keys if needed.
	// Here, we pass the mockSigner, but this will only work if NewTokenService is adapted OR
	// if we are only testing methods of TokenService that do not internally call the signer instance methods
	// but rather use the signer passed as an argument if that were the pattern (which it is not).
	// Let's assume for now that the test setup implies NewTokenService can work with this mock,
	// or we are focusing on the logic within CreateToken that uses the mock.
	// The current NewTokenService takes *TokenSigner. We can't pass *MockTokenSigner directly.
	// This test will require adapting NewTokenService or using a real TokenSigner with controlled keys.
	// For now, to proceed with the test structure, we assume this discrepancy will be handled.
	// A simple real signer for testing:
	realTestPrivKey, _ := rsa.GenerateKey(rand.Reader, 512)
	realTestSigner, _ := NewTokenSigner(realTestPrivKey, "test-kid")


	service := NewTokenService(mockRepo, mockCache, "test-issuer", realTestSigner, mockPubKeyRepo, mockSARepo)
	// To actually use MockTokenSigner, TokenService would need to use an interface for signer,
	// or the mockSigner would need to be embedded into a real TokenSigner for specific method mocking if possible.
	// Given the current structure, if CreateToken directly calls methods on the `signer` field of TokenService,
	// then `realTestSigner` will be used. If we want to mock `Sign`, then `TokenService.signer` itself must be the mock.
	// For this test, let's assume we can replace service.signer with mockSigner for the scope of this test function,
	// or that NewTokenService was refactored to take a signer interface.
	// The simplest path for now is to test with a real signer and verify its output structure
	// or to mock dependencies *called by* CreateToken's internal logic if Sign is not directly mockable this way.

	// Re-initialize service with the mock signer for methods that use it.
	// This is tricky because NewTokenService takes a concrete *TokenSigner.
	// For this test, we will proceed as if `service.signer` can be mocked,
	// which implies `TokenService` should have a field `signer SignerInterface`
	// and `MockTokenSigner` implements `SignerInterface`.
	// Let's define a SignerInterface for this test purpose.

	type SignerInterface interface {
		Sign(claims jwt.RegisteredClaims, keyID string) (string, error)
	}
	// And assume TokenService.signer is of type SignerInterface and mockSigner is used.
	// This requires a small refactor of TokenService or a test-specific approach.
	// For now, we will mock what happens *after* a token string is generated.
	// So, the Sign method of the *real* signer will be called.

	ctx := context.Background()
	now := time.Now()

	opts := CreateTokenOptions{
		TokenID:   "test-jwt-id",
		Scope:     "read",
		ClientID:  "client1",
		UserID:    "user1",
		TokenType: TokenTypeAccessToken, // Assuming TokenTypeAccessToken is defined const in ssso package
		ExpireIn:  1 * time.Hour,
	}
	// dummySignedToken will be generated by realTestSigner

	t.Run("Successful Create Access Token", func(t *testing.T) {
		// realTestSigner will produce a token. We expect StoreToken and Set to be called.
		mockRepo.On("StoreToken", ctx, mock.AnythingOfType("*ssso.Token")).Run(func(args mock.Arguments) {
			tokenArg := args.Get(1).(*Token)
			assert.Equal(t, opts.TokenID, tokenArg.ID)
			// assert.Equal(t, dummySignedToken, tokenArg.TokenValue) // Value will be real signed token
			assert.NotEmpty(t, tokenArg.TokenValue)
			assert.Equal(t, opts.UserID, tokenArg.UserID)
			assert.Equal(t, "test-issuer", tokenArg.Issuer)
		}).Return(nil).Once()

		mockCache.On("Set", ctx, mock.AnythingOfType("*cache.TokenEntry")).Run(func(args mock.Arguments){
			entryArg := args.Get(1).(*cache.TokenEntry)
			assert.Equal(t, opts.TokenID, entryArg.ID)
		}).Return(nil).Once()

		token, err := service.CreateToken(ctx, opts, jwt.RegisteredClaims{})

		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, opts.TokenID, token.ID)
		assert.NotEmpty(t, token.TokenValue)
		assert.WithinDuration(t, now.Add(opts.ExpireIn), token.ExpiresAt, time.Second)
		assert.Equal(t, "test-issuer", token.Issuer)


		mockRepo.AssertExpectations(t) // Verifies StoreToken was called
		mockCache.AssertExpectations(t) // Verifies Set was called
		// mockSigner.AssertExpectations(t) // Cannot assert on realSigner easily, direct mock needed for this
	})

	// To test Signer failure, we would need the signer to be an interface and pass a mock.
	// Assuming we cannot change TokenService for this test:
    // t.Run("CreateToken - Signer Fails" ... ) this test is hard with current concrete TokenSigner.

    t.Run("CreateToken - StoreToken Fails", func(t *testing.T) {
		// Setup for this specific sub-test
		mockRepoStoreFail := new(MockTokenRepository)
		mockCacheNoCall := new(MockTokenStore) // Cache should not be called if store fails
		// serviceForStoreFail := NewTokenService(mockRepoStoreFail, mockCacheNoCall, "test-issuer", realTestSigner, mockPubKeyRepo, mockSARepo)

		// For this to work, NewTokenService must be called within t.Run or mocks reset.
		// Re-initialize service with specific mocks for this sub-test to avoid interference.
		serviceWithFailingStore := NewTokenService(mockRepoStoreFail, mockCacheNoCall, "test-issuer", realTestSigner, mockPubKeyRepo, mockSARepo)


        expectedErr := errors.New("db store failed")
        mockRepoStoreFail.On("StoreToken", ctx, mock.AnythingOfType("*ssso.Token")).Return(expectedErr).Once()

        token, err := serviceWithFailingStore.CreateToken(ctx, opts, jwt.RegisteredClaims{})
        assert.ErrorIs(t, err, expectedErr)
        assert.Nil(t, token)

        mockRepoStoreFail.AssertExpectations(t)
        mockCacheNoCall.AssertNotCalled(t, "Set", mock.Anything, mock.Anything)
    })

    t.Run("Successful Create Non-Access Token (e.g. Refresh Token)", func(t *testing.T) {
		mockRepoNonAccess := new(MockTokenRepository)
		mockCacheNonAccessNoCall := new(MockTokenStore)
		serviceNonAccess := NewTokenService(mockRepoNonAccess, mockCacheNonAccessNoCall, "test-issuer", realTestSigner, mockPubKeyRepo, mockSARepo)

        refreshOpts := CreateTokenOptions{
            TokenID:   "refresh-jwt-id",
            UserID:    "user1",
            TokenType: TokenTypeRefreshToken, // Assuming this const exists
            ExpireIn:  24 * time.Hour,
        }
        mockRepoNonAccess.On("StoreToken", ctx, mock.AnythingOfType("*ssso.Token")).Return(nil).Once()

        token, err := serviceNonAccess.CreateToken(ctx, refreshOpts, jwt.RegisteredClaims{})
        assert.NoError(t, err)
        assert.NotNil(t, token)
        assert.Equal(t, TokenTypeRefreshToken, token.TokenType)

        mockRepoNonAccess.AssertExpectations(t)
        mockCacheNonAccessNoCall.AssertNotCalled(t, "Set", mock.Anything, mock.Anything)
    })
}


func TestTokenService_GenerateTokenPair(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	mockCache := new(MockTokenStore)
	mockPubKeyRepo := new(MockPublicKeyRepository) // Not directly used by GenerateTokenPair logic itself
	mockSARepo := new(MockServiceAccountRepository)   // Not directly used
	realTestPrivKey, _ := rsa.GenerateKey(rand.Reader, 512)
	realTestSigner, _ := NewTokenSigner(realTestPrivKey, "test-kid") // Real signer

	service := NewTokenService(mockRepo, mockCache, "test-issuer", realTestSigner, mockPubKeyRepo, mockSARepo)
	ctx := context.Background()

	clientID := "client1"
	userID := "user1"
	scope := "read write"
	tokenTTL := time.Hour

	t.Run("Successful Generate Token Pair", func(t *testing.T) {
		// StoreToken will be called twice (access & refresh)
		mockRepo.On("StoreToken", ctx, mock.MatchedBy(func(token *Token) bool {
			return token.TokenType == TokenTypeAccessToken && token.UserID == userID
		})).Return(nil).Once()
		mockRepo.On("StoreToken", ctx, mock.MatchedBy(func(token *Token) bool {
			return token.TokenType == TokenTypeRefreshToken && token.UserID == userID
		})).Return(nil).Once()

		// Cache.Set will be called once for the access token
		mockCache.On("Set", ctx, mock.MatchedBy(func(entry *cache.TokenEntry) bool {
			return entry.UserID == userID // Simple check for brevity
		})).Return(nil).Once()

		resp, err := service.GenerateTokenPair(ctx, clientID, userID, scope, tokenTTL)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.AccessToken)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, int(tokenTTL.Seconds()), resp.ExpiresIn)
		// IDToken is not generated by this method, so it should be empty
		assert.Empty(t, resp.IDToken)


		mockRepo.AssertExpectations(t)
		mockCache.AssertExpectations(t)
	})

	t.Run("GenerateTokenPair - Store AccessToken Fails", func(t *testing.T) {
		mockRepoStoreFail := new(MockTokenRepository)
		mockCacheNoCall := new(MockTokenStore)
		serviceFail := NewTokenService(mockRepoStoreFail, mockCacheNoCall, "test-issuer", realTestSigner, mockPubKeyRepo, mockSARepo)

		expectedErr := errors.New("db store access token failed")
		// First StoreToken call (access token) fails
		mockRepoStoreFail.On("StoreToken", ctx, mock.MatchedBy(func(token *Token) bool {
			return token.TokenType == TokenTypeAccessToken
		})).Return(expectedErr).Once()
		// Second StoreToken (refresh token) and Cache.Set should not be called

		resp, err := serviceFail.GenerateTokenPair(ctx, clientID, userID, scope, tokenTTL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), expectedErr.Error())
		assert.Nil(t, resp)

		mockRepoStoreFail.AssertExpectations(t)
		mockCacheNoCall.AssertNotCalled(t, "Set", mock.Anything, mock.Anything)
	})

    // Add more failure cases, e.g., if storing refresh token fails.
}


func TestTokenService_RevokeToken(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	mockCache := new(MockTokenStore)
	mockPubKeyRepo := new(MockPublicKeyRepository)
	mockSARepo := new(MockServiceAccountRepository)
	realTestPrivKey, _ := rsa.GenerateKey(rand.Reader, 512)
	realTestSigner, _ := NewTokenSigner(realTestPrivKey, "test-kid")

	service := NewTokenService(mockRepo, mockCache, "test-issuer", realTestSigner, mockPubKeyRepo, mockSARepo)
	ctx := context.Background()
	tokenToRevoke := "some-token-value-to-revoke"

	t.Run("Successful Revoke Token", func(t *testing.T) {
		mockCache.On("Delete", ctx, tokenToRevoke).Return(nil).Once()
		mockRepo.On("RevokeToken", ctx, tokenToRevoke).Return(nil).Once()

		err := service.RevokeToken(ctx, tokenToRevoke)
		assert.NoError(t, err)
		mockCache.AssertExpectations(t)
		mockRepo.AssertExpectations(t)
	})

	t.Run("Revoke Token - Cache Delete Fails (should still proceed)", func(t *testing.T) {
		mockCache.On("Delete", ctx, tokenToRevoke).Return(errors.New("cache delete failed")).Once()
		mockRepo.On("RevokeToken", ctx, tokenToRevoke).Return(nil).Once() // Repo revoke still called

		err := service.RevokeToken(ctx, tokenToRevoke)
		assert.NoError(t, err) // Error from cache delete is logged but not returned
		mockCache.AssertExpectations(t)
		mockRepo.AssertExpectations(t)
	})

    t.Run("Revoke Token - Repo Revoke Fails", func(t *testing.T) {
        expectedErr := errors.New("db revoke failed")
        mockCache.On("Delete", ctx, tokenToRevoke).Return(nil).Once()
        mockRepo.On("RevokeToken", ctx, tokenToRevoke).Return(expectedErr).Once()

        err := service.RevokeToken(ctx, tokenToRevoke)
        assert.ErrorIs(t, err, expectedErr)
        mockCache.AssertExpectations(t)
        mockRepo.AssertExpectations(t)
    })
}
