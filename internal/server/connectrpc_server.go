package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/pilab-dev/shadow-sso/cache"        // For cache.NewMemoryTokenStore or similar
	"github.com/pilab-dev/shadow-sso/domain"       // For repository interfaces
	"github.com/pilab-dev/shadow-sso/gen/sso/v1/ssov1connect" // Generated connect handlers
	"github.com/pilab-dev/shadow-sso/middleware" // Your auth interceptor
	"github.com/pilab-dev/shadow-sso/services"     // Your service implementations
	"github.com/pilab-dev/shadow-sso/ssso"         // For TokenService, TokenSigner, GenerateRSAKey
	"github.com/rs/zerolog/log"
)

// --- Mock/Placeholder Repository & Hasher Implementations ---

type mockTokenRepository struct{}

func (m *mockTokenRepository) StoreToken(ctx context.Context, token *ssso.Token) error {
	log.Debug().Str("token_id", token.ID).Msg("MockTokenRepository: StoreToken called")
	return nil
}
func (m *mockTokenRepository) GetAccessToken(ctx context.Context, tokenValue string) (*ssso.Token, error) {
	log.Debug().Str("token_value", tokenValue).Msg("MockTokenRepository: GetAccessToken called")
	// Simulate not found to force SA token path or specific test cases
	return nil, errors.New("mock TokenRepository: token not found")
}
func (m *mockTokenRepository) RevokeToken(ctx context.Context, tokenValue string) error {
	log.Debug().Str("token_value", tokenValue).Msg("MockTokenRepository: RevokeToken called")
	return nil
}
func (m *mockTokenRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) {
	log.Debug().Str("token_value", tokenValue).Msg("MockTokenRepository: GetRefreshTokenInfo called")
	return nil, errors.New("mock TokenRepository: refresh token info not found")
}
func (m *mockTokenRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) {
	log.Debug().Str("token_value", tokenValue).Msg("MockTokenRepository: GetAccessTokenInfo called")
	return nil, errors.New("mock TokenRepository: access token info not found")
}

var _ ssso.TokenRepository = (*mockTokenRepository)(nil) // Ensure interface compliance

type mockPublicKeyRepository struct{}

func (m *mockPublicKeyRepository) GetPublicKey(ctx context.Context, keyID string) (*domain.PublicKeyInfo, error) {
	log.Debug().Str("kid", keyID).Msg("MockPublicKeyRepository: GetPublicKey called")
	// Example: Allow a specific kid for testing SA JWT validation
	// if keyID == "test-kid-active" {
	// 	// This key would need to correspond to a private key used to sign a test SA JWT
	// 	return &domain.PublicKeyInfo{
	// 		ID:        keyID,
	// 		PublicKey: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0pdyN6S00kheyLg3N7xS\nZ6xT7xVb9v9Z6S7Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z\n6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z\n6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z\n6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z6T6Z7R9Z\nCAwEAAQ==\n-----END PUBLIC KEY-----", // Replace with actual dummy PEM public key
	// 		Algorithm: "RS256",
	// 		Status:    "ACTIVE",
	// 	}, nil
	// }
	return nil, errors.New("mock PublicKeyRepository: key not found")
}

var _ domain.PublicKeyRepository = (*mockPublicKeyRepository)(nil) // Ensure interface compliance

type mockServiceAccountRepository struct{}

func (m *mockServiceAccountRepository) GetServiceAccountByClientEmail(ctx context.Context, clientEmail string) (*domain.ServiceAccount, error) {
	log.Debug().Str("client_email", clientEmail).Msg("MockSARepository: GetServiceAccountByClientEmail called")
	return nil, errors.New("mock ServiceAccountRepository: not found by email")
}
func (m *mockServiceAccountRepository) GetServiceAccount(ctx context.Context, id string) (*domain.ServiceAccount, error) {
	log.Debug().Str("id", id).Msg("MockSARepository: GetServiceAccount called")
	return nil, errors.New("mock ServiceAccountRepository: not found by ID")
}

var _ domain.ServiceAccountRepository = (*mockServiceAccountRepository)(nil) // Ensure interface compliance

type mockUserRepository struct{}
func (m *mockUserRepository) CreateUser(ctx context.Context, user *domain.User) error { return nil }
func (m *mockUserRepository) GetUserByID(ctx context.Context, id string) (*domain.User, error) { return nil, errors.New("not found")}
func (m *mockUserRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) { return nil, errors.New("not found")}
func (m *mockUserRepository) UpdateUser(ctx context.Context, user *domain.User) error { return nil }
func (m *mockUserRepository) ListUsers(ctx context.Context, pagination domain.Pagination) ([]*domain.User, error) { return nil, nil }

var _ domain.UserRepository = (*mockUserRepository)(nil) // Ensure interface compliance


type mockPasswordHasher struct{}
func (m *mockPasswordHasher) Hash(password string) (string, error) { return password + "-hashed", nil }
func (m *mockPasswordHasher) Verify(hashedPassword, password string) error {
	if hashedPassword == password + "-hashed" {
		return nil
	}
	return errors.New("mock PasswordHasher: password mismatch")
}
var _ services.PasswordHasher = (*mockPasswordHasher)(nil) // Ensure interface compliance


// StartConnectRPCServer initializes and starts the ConnectRPC server.
func StartConnectRPCServer(addr string) error {
	log.Info().Msgf("Starting ConnectRPC server on %s", addr)

	// 1. Initialize Dependencies (using mocks)
	privKey, err := ssso.GenerateRSAKey() // From ssso package (keys.go)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate RSA key for mock TokenSigner")
	}
	mockSigner, err := ssso.NewTokenSigner(privKey, "mock-kid-for-user-tokens")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create mock TokenSigner")
	}

	mockUserTokenRepo := &mockTokenRepository{}
	mockCache := cache.NewMemoryTokenStore(1*time.Minute, 1000)
	mockPubKeyRepo := &mockPublicKeyRepository{}
	mockSARepo := &mockServiceAccountRepository{}
	mockUserRepo := &mockUserRepository{}
	mockHasher := &mockPasswordHasher{}

	tokenService := ssso.NewTokenService(
		mockUserTokenRepo,
		mockCache,
		"sso-issuer-user", // Issuer for user tokens
		mockSigner,
		mockPubKeyRepo,
		mockSARepo,
	)

	// 2. Initialize Authentication Interceptor
	authInterceptor := middleware.NewAuthInterceptor(tokenService)

	// 3. Initialize Service Implementations
	defaultKeyGen := &services.DefaultSAKeyGenerator{}
	saServer := services.NewServiceAccountServer(defaultKeyGen, mockSARepo, mockPubKeyRepo)
	userServer := services.NewUserServer(mockUserRepo, mockHasher)
	authServer := services.NewAuthServer(mockUserRepo, tokenService, mockHasher) // Pass concrete *ssso.TokenService

	// 4. Create a new mux (router) and apply interceptors
	mux := http.NewServeMux()

	saPath, saHandler := ssov1connect.NewServiceAccountServiceHandler(saServer, connect.WithInterceptors(authInterceptor))
	mux.Handle(saPath, saHandler)

	userPath, userHandler := ssov1connect.NewUserServiceHandler(userServer, connect.WithInterceptors(authInterceptor))
	mux.Handle(userPath, userHandler)

	authPath, authHandler := ssov1connect.NewAuthServiceHandler(authServer, connect.WithInterceptors(authInterceptor))
	mux.Handle(authPath, authHandler)
    // TODO: Add logic to Authenticator to bypass auth for public endpoints like Login, RegisterUser.

	// 5. Create and start the HTTP/2 server
	srv := &http.Server{
		Addr:              addr,
		Handler:           h2c.NewHandler(mux, &http2.Server{}),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}

	log.Info().Msgf("ConnectRPC server listening on %s", addr)
	return srv.ListenAndServe()
}
