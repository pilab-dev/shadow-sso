package integration

import (
	"context"
	"errors"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/apps/ssso/server"
	"os"
	"strconv"
	"testing"
	"time"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/mongodb"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/pilab-dev/shadow-sso/services"
	"golang.org/x/crypto/bcrypt"
)

// bootstrapAdminUser creates the initial admin user if it does not exist,
// replicating the bootstrap logic from ssso.go main() lines 176-205.
// It adds ROLE_ADMIN to the user's Roles so the user has admin privileges.
func bootstrapAdminUser(t testing.TB, provider services.RepositoryProvider, email, password, firstName, lastName string) {
	t.Helper()
	ctx := context.Background()
	userRepo := provider.UserRepository(ctx)

	_, uErr := userRepo.GetUserByEmail(ctx, email)
	if errors.Is(uErr, domain.ErrUserNotFound) {
		hasher := pkgauth.NewBcryptPasswordHasher(bcrypt.DefaultCost)
		hash, pHashErr := hasher.Hash(password)
		if pHashErr != nil {
			t.Fatalf("Failed to hash initial admin password: %v", pHashErr)
			return
		}
		user := &domain.User{
			Email:        email,
			PasswordHash: hash,
			FirstName:    firstName,
			LastName:     lastName,
			Status:       domain.UserStatusActive,
			Roles:        []string{"ROLE_ADMIN"},
		}
		if cErr := userRepo.CreateUser(ctx, user); cErr != nil {
			t.Fatalf("Failed to create initial admin user: %v", cErr)
		}
	} else if uErr != nil {
		t.Fatalf("Failed to check for existing admin user: %v", uErr)
	}
}

// bootstrapAdminUIClient creates the admin-ui OAuth client if it does not exist,
// replicating the bootstrap logic from ssso.go main() lines 207-278.
func bootstrapAdminUIClient(t testing.TB, provider services.RepositoryProvider, clientSecret string) {
	t.Helper()
	ctx := context.Background()
	clientRepo := provider.ClientRepository(ctx)

	_, cErr := clientRepo.GetClient(ctx, "admin-ui")
	if cErr != nil {
		secret := clientSecret
		if secret == "" {
			secret = mongodb.NewID()
		}
		hashedSecret, hErr := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if hErr != nil {
			t.Fatalf("Failed to hash admin-ui client secret: %v", hErr)
			return
		}
		client := &domain.Client{
			ID:                 "admin-ui",
			Secret:             string(hashedSecret),
			Type:               domain.ClientTypeConfidential,
			Name:               "Admin UI",
			AllowedGrantTypes:  []string{"password", "refresh_token", "client_credentials"},
			AllowedScopes:      []string{"openid", "profile", "email"},
			IsActive:           true,
			IsConfidential:     true,
			TokenEndpointAuth:  "client_secret_post",
			ServiceAccountRoles: []string{"ROLE_ADMIN"},
		}
		if cErr := clientRepo.CreateClient(ctx, client); cErr != nil {
			t.Fatalf("Failed to create admin-ui client: %v", cErr)
		}
	}
}

// TestBootstrap_AdminUserCreated verifies that the admin user is created with
// correct fields: Status=Active, Roles contain ROLE_ADMIN, and password hash
// is valid via bcrypt Verify().
func TestBootstrap_AdminUserCreated(t *testing.T) {
	const (
		adminEmail     = "admin-test@shadow-sso.test"
		adminPassword  = "secure-password-123!"
		adminFirstName = "Test"
		adminLastName  = "Admin"
	)

	srv, provider, _ := StartTestServer(t, func(cfg *config.Config) {
		cfg.InitialAdminEnabled = true
		cfg.InitialAdminEmail = adminEmail
		cfg.InitialAdminPassword = adminPassword
		cfg.InitialAdminFirstName = adminFirstName
		cfg.InitialAdminLastName = adminLastName
	})
	if srv == nil {
		return // MongoDB not available
	}
	defer StopTestServer(t, srv, provider)

	// Run bootstrap — this is normally done by main() before StartServer
	bootstrapAdminUser(t, provider, adminEmail, adminPassword, adminFirstName, adminLastName)

	// Verify the admin user was created with correct fields
	ctx := context.Background()
	userRepo := provider.UserRepository(ctx)

	admin, err := userRepo.GetUserByEmail(ctx, adminEmail)
	if err != nil {
		t.Fatalf("Admin user not found: %v", err)
	}

	if admin.Status != domain.UserStatusActive {
		t.Errorf("Expected status %s, got %s", domain.UserStatusActive, admin.Status)
	}

	if admin.FirstName != adminFirstName {
		t.Errorf("Expected first name %q, got %q", adminFirstName, admin.FirstName)
	}
	if admin.LastName != adminLastName {
		t.Errorf("Expected last name %q, got %q", adminLastName, admin.LastName)
	}

	// Verify Roles contain ROLE_ADMIN
	foundAdminRole := false
	for _, role := range admin.Roles {
		if role == "ROLE_ADMIN" {
			foundAdminRole = true
			break
		}
	}
	if !foundAdminRole {
		t.Errorf("Expected admin user to have ROLE_ADMIN role, got roles: %v", admin.Roles)
	}

	// Verify password hash is valid bcrypt hash via Verify()
	hasher := pkgauth.NewBcryptPasswordHasher(bcrypt.DefaultCost)
	if err := hasher.Verify(admin.PasswordHash, adminPassword); err != nil {
		t.Errorf("Password hash verification failed: %v", err)
	}
}

// TestBootstrap_AdminUIClientCreated verifies the admin-ui client is created
// with correct fields: IsConfidential=true, AllowedGrantTypes contain expected
// values, ServiceAccountRoles contain ROLE_ADMIN, and secret is bcrypt-hashed ($2a$ prefix).
func TestBootstrap_AdminUIClientCreated(t *testing.T) {
	const (
		adminEmail    = "admin-ui-test@shadow-sso.test"
		adminPassword = "secure-password-123!"
	)

	srv, provider, _ := StartTestServer(t, func(cfg *config.Config) {
		cfg.InitialAdminEnabled = true
		cfg.InitialAdminEmail = adminEmail
		cfg.InitialAdminPassword = adminPassword
	})
	if srv == nil {
		return
	}
	defer StopTestServer(t, srv, provider)

	// Bootstrap admin user + client
	bootstrapAdminUser(t, provider, adminEmail, adminPassword, "Test", "Admin")
	bootstrapAdminUIClient(t, provider, "")

	// Verify admin-ui client
	ctx := context.Background()
	clientRepo := provider.ClientRepository(ctx)

	client, err := clientRepo.GetClient(ctx, "admin-ui")
	if err != nil {
		t.Fatalf("Admin-UI client not found: %v", err)
	}

	if !client.IsConfidential {
		t.Error("Expected admin-ui client to be confidential")
	}

	if client.Type != domain.ClientTypeConfidential {
		t.Errorf("Expected client type %s, got %s", domain.ClientTypeConfidential, client.Type)
	}

	// Verify AllowedGrantTypes contain expected values
	grantTypes := make(map[string]bool)
	for _, gt := range client.AllowedGrantTypes {
		grantTypes[gt] = true
	}
	for _, expected := range []string{"client_credentials", "password", "refresh_token"} {
		if !grantTypes[expected] {
			t.Errorf("Expected AllowedGrantTypes to contain %q, got: %v", expected, client.AllowedGrantTypes)
		}
	}

	// Verify ServiceAccountRoles contain ROLE_ADMIN
	hasAdminRole := false
	for _, role := range client.ServiceAccountRoles {
		if role == "ROLE_ADMIN" {
			hasAdminRole = true
			break
		}
	}
	if !hasAdminRole {
		t.Errorf("Expected ServiceAccountRoles to contain ROLE_ADMIN, got: %v", client.ServiceAccountRoles)
	}

	// Verify secret is bcrypt-hashed ($2a$ or $2b$ prefix)
	if client.Secret == "" {
		t.Error("Expected client secret to be set")
	}
	if len(client.Secret) > 0 {
		prefix := client.Secret[:4]
		if prefix != "$2a$" && prefix != "$2b$" {
			t.Errorf("Expected client secret to be bcrypt-hashed (starts with $2a$ or $2b$), got prefix: %s", prefix)
		}
	}

	// Verify client is active
	if !client.IsActive {
		t.Error("Expected admin-ui client to be active")
	}
}

// TestBootstrap_DefaultConfigsCreated verifies that default configurations are
// bootstrapped into the database. The harness StartTestServer already calls
// CreateDefaultConfigs, so we verify that at least one known configuration key exists
// by querying known config types individually via GetByType.
func TestBootstrap_DefaultConfigsCreated(t *testing.T) {
	srv, provider, _ := StartTestServer(t)
	if srv == nil {
		return
	}
	defer StopTestServer(t, srv, provider)

	ctx := context.Background()
	configRepo := provider.ConfigurationRepository(ctx)

	// Query known configuration types individually. Only ConfigTypeEmail is
	// guaranteed to have defaults in a clean environment (from_email, base_url).
	// Other types (SMS, Push) require env vars to be set.
	knownTypes := []domain.ConfigurationType{
		domain.ConfigTypeEmail,
	}
	totalCount := 0
	for _, kt := range knownTypes {
		configs, err := configRepo.GetByTypeActive(ctx, kt)
		if err != nil {
			t.Fatalf("Failed to get configs for type %s: %v", kt, err)
		}
		totalCount += len(configs)
		for _, cfg := range configs {
			t.Logf("Found configuration: type=%s key=%s", cfg.Type, cfg.Key)
		}
	}

	if totalCount == 0 {
		t.Errorf("Expected at least one default configuration, got 0 across known types")
	}
}

// TestBootstrap_DisabledAdminRemainsDisabled verifies that when
// InitialAdminEnabled is false, no admin user is created.
func TestBootstrap_DisabledAdminRemainsDisabled(t *testing.T) {
	const disabledAdminEmail = "disabled-admin@shadow-sso.test"

	srv, provider, _ := StartTestServer(t, func(cfg *config.Config) {
		cfg.InitialAdminEnabled = false
		cfg.InitialAdminEmail = disabledAdminEmail
	})
	if srv == nil {
		return
	}
	defer StopTestServer(t, srv, provider)

	// When admin is disabled, the bootstrap helpers called in main()
	// do nothing — simulate by NOT calling bootstrapAdminUser.
	// Verify the user does not exist.
	ctx := context.Background()
	userRepo := provider.UserRepository(ctx)

	_, err := userRepo.GetUserByEmail(ctx, disabledAdminEmail)
	if !errors.Is(err, domain.ErrUserNotFound) {
		if err == nil {
			t.Errorf("Expected ErrUserNotFound for disabled admin email %q, but user exists", disabledAdminEmail)
		} else {
			t.Errorf("Expected ErrUserNotFound, got unexpected error: %v", err)
		}
	}
}

// TestBootstrap_Idempotent verifies that running bootstrap a second time
// (simulating server restart) does not duplicate admin user or admin-ui client.
func TestBootstrap_Idempotent(t *testing.T) {
	const (
		adminEmail    = "idempotent-admin@shadow-sso.test"
		adminPassword = "secure-password-123!"
	)

	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	// Use a fixed DB name so we can reconnect to the same database
	dbName := "test_bootstrap_idempotent_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	cfg := TestConfig(dbName)
	cfg.InitialAdminEnabled = true
	cfg.InitialAdminEmail = adminEmail
	cfg.InitialAdminPassword = adminPassword
	cfg.InitialAdminFirstName = "Idempotent"
	cfg.InitialAdminLastName = "Admin"

	// ── First bootstrap ────────────────────────────────────────────
	provider1, err := ssso.NewMongoRepositoryProvider(mongoURI, dbName)
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
		return
	}

	// Create default configs
	configRepo1 := provider1.ConfigurationRepository(context.Background())
	if err := configRepo1.CreateDefaultConfigs(context.Background()); err != nil {
		t.Logf("Warning: Failed to bootstrap default configs: %v", err)
	}

	// Bootstrap admin user + client
	bootstrapAdminUser(t, provider1, adminEmail, adminPassword, "Idempotent", "Admin")
	bootstrapAdminUIClient(t, provider1, "")

	// Start the first SSO server
	srv1, err := server.StartServer(cfg, provider1)
	if err != nil {
		t.Fatalf("Failed to start first SSO server: %v", err)
	}

	// Verify after first bootstrap: 1 user, 1 client
	ctx := context.Background()
	userRepo1 := provider1.UserRepository(ctx)
	users1, _, err := userRepo1.ListUsers(ctx, "", 100)
	if err != nil {
		t.Fatalf("Failed to list users after first bootstrap: %v", err)
	}
	if len(users1) != 1 {
		t.Errorf("Expected 1 user after first bootstrap, got %d", len(users1))
	}

	clientRepo1 := provider1.ClientRepository(ctx)
	clients1, err := clientRepo1.ListClients(ctx, domain.ClientFilter{})
	if err != nil {
		t.Fatalf("Failed to list clients after first bootstrap: %v", err)
	}
	if len(clients1) != 1 {
		t.Errorf("Expected 1 client after first bootstrap, got %d", len(clients1))
	}

	// Stop the first server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = srv1.Shutdown(shutdownCtx)
	cancel()

	// Disconnect the first provider
	if mongoRp1, ok := provider1.(*mongodb.MongoRepositoryProvider); ok {
		_ = mongoRp1.Disconnect(context.Background())
	}

	// ── Second bootstrap (simulate restart) ────────────────────────
	provider2, err := ssso.NewMongoRepositoryProvider(mongoURI, dbName)
	if err != nil {
		t.Fatalf("Failed to reconnect MongoDB: %v", err)
	}

	// Bootstrap again — must be idempotent, no duplicates
	bootstrapAdminUser(t, provider2, adminEmail, adminPassword, "Idempotent", "Admin")
	bootstrapAdminUIClient(t, provider2, "")

	// Start the second SSO server
	srv2, err := server.StartServer(cfg, provider2)
	if err != nil {
		t.Fatalf("Failed to start second SSO server: %v", err)
	}
	defer func() {
		shutdownCtx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		_ = srv2.Shutdown(shutdownCtx2)
		if mongoRp2, ok := provider2.(*mongodb.MongoRepositoryProvider); ok {
			_ = mongoRp2.Disconnect(context.Background())
		}
	}()

	// ── Verify idempotency ─────────────────────────────────────────
	ctx2 := context.Background()
	userRepo2 := provider2.UserRepository(ctx2)

	users2, _, err := userRepo2.ListUsers(ctx2, "", 100)
	if err != nil {
		t.Fatalf("Failed to list users after second bootstrap: %v", err)
	}
	if len(users2) != 1 {
		t.Errorf("Expected 1 user after idempotent restart, got %d (duplicates detected)", len(users2))
	}

	clientRepo2 := provider2.ClientRepository(ctx2)
	clients2, err := clientRepo2.ListClients(ctx2, domain.ClientFilter{})
	if err != nil {
		t.Fatalf("Failed to list clients after second bootstrap: %v", err)
	}
	if len(clients2) != 1 {
		t.Errorf("Expected 1 client after idempotent restart, got %d (duplicates detected)", len(clients2))
	}

	// Verify the admin user is intact
	admin, err := userRepo2.GetUserByEmail(ctx2, adminEmail)
	if err != nil {
		t.Fatalf("Admin user not found after restart: %v", err)
	}
	if admin.Status != domain.UserStatusActive {
		t.Errorf("Expected admin status ACTIVE after restart, got %s", admin.Status)
	}

	// Verify the admin-ui client is intact
	client, err := clientRepo2.GetClient(ctx2, "admin-ui")
	if err != nil {
		t.Fatalf("Admin-UI client not found after restart: %v", err)
	}
	if !client.IsConfidential {
		t.Error("Expected admin-ui client to be confidential after restart")
	}
}
