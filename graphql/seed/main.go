package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/pilab-dev/shadow-sso/graphql"
	"github.com/pilab-dev/shadow-sso/mongodb"
)

// MockEmailService implements domain.EmailService for testing
type MockEmailService struct{}

func (m *MockEmailService) SendVerificationEmail(to, name, verificationLink string) error {
	fmt.Printf("[EMAIL] Verification email to %s: %s\n", to, verificationLink)
	return nil
}
func (m *MockEmailService) SendPasswordResetEmail(to, name, resetLink string) error {
	fmt.Printf("[EMAIL] Password reset email to %s: %s\n", to, resetLink)
	return nil
}
func (m *MockEmailService) SendOTPEmail(to, otp string) error {
	fmt.Printf("[EMAIL] OTP to %s: %s\n", to, otp)
	return nil
}
func (m *MockEmailService) SendMFAEmail(to, name, otp, method string) error {
	fmt.Printf("[EMAIL] MFA to %s (%s): %s\n", to, method, otp)
	return nil
}

// MockPasswordHasher implements domain.PasswordHasher for testing
type MockPasswordHasher struct{}

func (m *MockPasswordHasher) Hash(password string) (string, error)    { return "hashed_" + password, nil }
func (m *MockPasswordHasher) Verify(hashedPassword, password string) error { return nil }

func main() {
	ctx := context.Background()

	// Get MongoDB URI from environment or use default
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017/sso_dev"
	}

	// Connect to MongoDB via the same repository provider the real server
	// uses, instead of hand-rolling a separate connection + repository set.
	repoProvider, err := mongodb.NewMongoRepositoryProvider(mongoURI, "sso_dev")
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer repoProvider.Disconnect(ctx)
	fmt.Println("Connected to MongoDB!")

	// Create resolver
	resolver := &graphql.Resolver{
		UserRepo:            repoProvider.UserRepository(ctx),
		ClientRepo:          repoProvider.ClientRepository(ctx),
		SessionRepo:         repoProvider.SessionRepository(ctx),
		IdPRepo:             repoProvider.IdPRepository(ctx),
		GroupRepo:           repoProvider.GroupRepository(ctx),
		RoleRepo:            repoProvider.RoleRepository(ctx),
		ProtocolMapperRepo:  repoProvider.ProtocolMapperRepository(ctx),
		AuthFlowRepo:        repoProvider.AuthenticationFlowRepository(ctx),
		ClientScopeRepo:     repoProvider.ClientScopeRepository(ctx),
		RealmSettingsRepo:   repoProvider.RealmSettingsRepository(ctx),
		RealmKeysRepo:       repoProvider.RealmKeysRepository(ctx),
		EmailService:        &MockEmailService{},
		PasswordHasher:      &MockPasswordHasher{},
	}

	mutation := resolver.Mutation()
	query := resolver.Query()

	// Seed data
	fmt.Println("\n=== SEEDING DATABASE ===")

	// Create roles
	adminRole, err := mutation.CreateRole(ctx, graphql.CreateRoleInput{
		Name:        "admin",
		Description: stringPtr("Administrator role"),
	})
	if err != nil {
		fmt.Printf("CreateRole admin failed: %v\n", err)
	} else {
		fmt.Printf("Created role: %s (ID: %s)\n", adminRole.Name, adminRole.ID)
	}

	userRole, err := mutation.CreateRole(ctx, graphql.CreateRoleInput{
		Name:        "user",
		Description: stringPtr("Regular user role"),
	})
	if err != nil {
		fmt.Printf("CreateRole user failed: %v\n", err)
	} else {
		fmt.Printf("Created role: %s (ID: %s)\n", userRole.Name, userRole.ID)
	}

	editorRole, err := mutation.CreateRole(ctx, graphql.CreateRoleInput{
		Name:        "editor",
		Description: stringPtr("Editor role"),
	})
	if err != nil {
		fmt.Printf("CreateRole editor failed: %v\n", err)
	} else {
		fmt.Printf("Created role: %s (ID: %s)\n", editorRole.Name, editorRole.ID)
	}

	// Create groups
	adminsGroup, err := mutation.CreateGroup(ctx, graphql.CreateGroupInput{
		Name: "Admins",
		Path: stringPtr("/Admins"),
	})
	if err != nil {
		fmt.Printf("CreateGroup Admins failed: %v\n", err)
	} else {
		fmt.Printf("Created group: %s (ID: %s)\n", adminsGroup.Name, adminsGroup.ID)
	}

	usersGroup, err := mutation.CreateGroup(ctx, graphql.CreateGroupInput{
		Name: "Users",
		Path: stringPtr("/Users"),
	})
	if err != nil {
		fmt.Printf("CreateGroup Users failed: %v\n", err)
	} else {
		fmt.Printf("Created group: %s (ID: %s)\n", usersGroup.Name, usersGroup.ID)
	}

	// Create client
	testClient, err := mutation.CreateClient(ctx, graphql.CreateClientInput{
		ClientID:   "test-app",
		ClientName: "Test Application",
		Description: stringPtr("A test OAuth client"),
		Enabled:    boolPtr(true),
		RedirectUris: []string{
			"http://localhost:3000/callback",
			"http://localhost:8080/callback",
		},
		AllowedGrantTypes: []string{
			"authorization_code",
			"refresh_token",
			"password",
		},
		StandardFlowEnabled: boolPtr(true),
		ImplicitFlowEnabled: boolPtr(false),
		DirectAccessGrantsEnabled: boolPtr(true),
	})
	if err != nil {
		fmt.Printf("CreateClient failed: %v\n", err)
	} else {
		fmt.Printf("Created client: %s (ID: %s)\n", testClient.Name, testClient.ID)
	}

	// Create confidential client with generated secret
	confidentialClient, err := mutation.CreateClient(ctx, graphql.CreateClientInput{
		ClientID:   "confidential-app",
		ClientName: "Confidential Application",
		Description: stringPtr("A confidential (server-side) OAuth client"),
		Enabled:    boolPtr(true),
		RedirectUris: []string{
			"https://app.example.com/callback",
		},
		AllowedGrantTypes: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},
		StandardFlowEnabled: boolPtr(true),
		DirectAccessGrantsEnabled: boolPtr(true),
		ServiceAccountsEnabled: boolPtr(true),
		PublicClient: boolPtr(false),
		ClientType: stringPtr("confidential"),
		ClientSecret: stringPtr(generateClientSecret()),
	})
	if err != nil {
		fmt.Printf("CreateClient confidential-app failed: %v\n", err)
	} else {
		fmt.Printf("Created confidential client: %s (ID: %s)\n", confidentialClient.Name, confidentialClient.ID)
	}

	// Create public client (SPA example)
	publicClient, err := mutation.CreateClient(ctx, graphql.CreateClientInput{
		ClientID:   "spa-app",
		ClientName: "Single Page Application",
		Description: stringPtr("A public SPA client"),
		Enabled:    boolPtr(true),
		RedirectUris: []string{
			"http://localhost:3000/callback",
			"https://app.example.com/callback",
		},
		WebOrigins: []string{
			"http://localhost:3000",
			"https://app.example.com",
		},
		AllowedGrantTypes: []string{
			"authorization_code",
			"refresh_token",
		},
		StandardFlowEnabled: boolPtr(true),
		PublicClient: boolPtr(true),
		ClientType: stringPtr("public"),
	})
	if err != nil {
		fmt.Printf("CreateClient spa-app failed: %v\n", err)
	} else {
		fmt.Printf("Created public client: %s (ID: %s)\n", publicClient.Name, publicClient.ID)
	}

	// Create users
	adminUser, err := mutation.CreateUser(ctx, graphql.CreateUserInput{
		Username: "admin@example.com",
		Email:    "admin@example.com",
		FirstName: stringPtr("Admin"),
		LastName:  stringPtr("User"),
		Enabled:   boolPtr(true),
	})
	if err != nil {
		fmt.Printf("CreateUser admin failed: %v\n", err)
	} else {
		fmt.Printf("Created user: %s (ID: %s)\n", adminUser.Email, adminUser.ID)
	}

	// Set password for admin user
	if adminUser != nil {
		_, err = mutation.SetUserPassword(ctx, adminUser.ID, "admin123", false)
		if err != nil {
			fmt.Printf("SetUserPassword failed: %v\n", err)
		} else {
			fmt.Println("Set password for admin user")
		}
	}

	testUser, err := mutation.CreateUser(ctx, graphql.CreateUserInput{
		Username: "test@example.com",
		Email:    "test@example.com",
		FirstName: stringPtr("Test"),
		LastName:  stringPtr("User"),
		Enabled:   boolPtr(true),
	})
	if err != nil {
		fmt.Printf("CreateUser test failed: %v\n", err)
	} else {
		fmt.Printf("Created user: %s (ID: %s)\n", testUser.Email, testUser.ID)
	}

	// Create authentication flow
	authFlow, err := mutation.CreateAuthenticationFlow(ctx, graphql.CreateAuthenticationFlowInput{
		Alias:       "browser",
		DisplayName: "Browser Flow",
		Description: stringPtr("Default browser authentication flow"),
		TopLevel:    boolPtr(true),
	})
	if err != nil {
		fmt.Printf("CreateAuthenticationFlow failed: %v\n", err)
	} else {
		fmt.Printf("Created auth flow: %s (ID: %s)\n", authFlow.Alias, authFlow.ID)
	}

	// Create realm settings
	realm, err := mutation.UpdateRealm(ctx, graphql.UpdateRealmInput{
		DisplayName:            stringPtr("Shadow SSO"),
		Enabled:               boolPtr(true),
		RegistrationAllowed:   boolPtr(true),
		LoginWithEmailAllowed: boolPtr(true),
		ResetPasswordAllowed:  boolPtr(true),
	})
	if err != nil {
		fmt.Printf("UpdateRealm failed: %v\n", err)
	} else {
		fmt.Printf("Updated realm: %s\n", realm.DisplayName)
	}

	// Generate RSA key pair for realm signing keys
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Failed to generate RSA key: %v\n", err)
	} else {
		// Convert keys to PEM/base64
		pubKeyBytes := base64.StdEncoding.EncodeToString(rsaKey.PublicKey.N.Bytes())
		privKeyBytes := base64.StdEncoding.EncodeToString(rsaKey.D.Bytes())

		realmKeys, err := mutation.UpdateRealmKeys(ctx, graphql.UpdateRealmKeysInput{
			Keys: []graphql.RealmKeyInput{
				{
					Name:        "rsa-generated",
					Type:        "RSA",
					ProviderID: "rsa-generated",
					Active:     boolPtr(true),
					Priority:   intPtr(0),
					PublicKey:  stringPtr(pubKeyBytes),
					PrivateKey: stringPtr(privKeyBytes),
				},
			},
		})
		if err != nil {
			fmt.Printf("UpdateRealmKeys failed: %v\n", err)
		} else {
			fmt.Printf("Created realm keys: %d key(s)\n", len(realmKeys))
		}
	}

	// Test queries
	fmt.Println("\n=== TESTING QUERIES ===")

	// Query users
	users, err := query.Users(ctx, nil, nil, nil)
	if err != nil {
		fmt.Printf("Query Users failed: %v\n", err)
	} else {
		fmt.Printf("Users total: %d\n", users.TotalCount)
		for _, edge := range users.Edges {
			fmt.Printf("  - %s (%s)\n", edge.Node.Email, edge.Node.ID)
		}
	}

	// Query clients
	clients, err := query.Clients(ctx, nil, nil, nil)
	if err != nil {
		fmt.Printf("Query Clients failed: %v\n", err)
	} else {
		fmt.Printf("Clients total: %d\n", clients.TotalCount)
		for _, edge := range clients.Edges {
			fmt.Printf("  - %s (%s)\n", edge.Node.Name, edge.Node.ID)
		}
	}

	// Query roles
	roles, err := query.Roles(ctx)
	if err != nil {
		fmt.Printf("Query Roles failed: %v\n", err)
	} else {
		fmt.Printf("Roles total: %d\n", len(roles))
		for _, role := range roles {
			fmt.Printf("  - %s\n", role.Name)
		}
	}

	// Query groups
	groups, err := query.Groups(ctx)
	if err != nil {
		fmt.Printf("Query Groups failed: %v\n", err)
	} else {
		fmt.Printf("Groups total: %d\n", len(groups))
		for _, group := range groups {
			fmt.Printf("  - %s (%s)\n", group.Name, group.Path)
		}
	}

	// Query realm
	realmSettings, err := query.Realm(ctx)
	if err != nil {
		fmt.Printf("Query Realm failed: %v\n", err)
	} else {
		fmt.Printf("Realm: %s (enabled: %v)\n", realmSettings.DisplayName, realmSettings.Enabled)
	}

	// Test mutation: send verification email
	fmt.Println("\n=== TESTING MUTATIONS ===")
	if adminUser != nil {
		_, err = mutation.SendVerificationEmail(ctx, adminUser.ID)
		if err != nil {
			fmt.Printf("SendVerificationEmail failed: %v\n", err)
		} else {
			fmt.Println("Sent verification email!")
		}

		// Test reset password
		_, err = mutation.SendPasswordResetEmail(ctx, adminUser.ID)
		if err != nil {
			fmt.Printf("SendPasswordResetEmail failed: %v\n", err)
		} else {
			fmt.Println("Sent password reset email!")
		}
	}

	// Add user to group
	if testUser != nil && usersGroup != nil {
		_, err = mutation.AddUserToGroup(ctx, testUser.ID, usersGroup.ID)
		if err != nil {
			fmt.Printf("AddUserToGroup failed: %v\n", err)
		} else {
			fmt.Printf("Added user %s to group %s\n", testUser.Email, usersGroup.Name)
		}
	}

	// Add role to user
	if adminUser != nil && adminRole != nil {
		_, err = mutation.AddRealmRoleToUser(ctx, adminUser.ID, adminRole.ID)
		if err != nil {
			fmt.Printf("AddRealmRoleToUser failed: %v\n", err)
		} else {
			fmt.Printf("Added role %s to user %s\n", adminRole.Name, adminUser.Email)
		}
	}

	// Query user sessions (if user exists)
	if adminUser != nil {
		sessions, err := query.UserSessions(ctx, adminUser.ID)
		if err != nil {
			fmt.Printf("Query UserSessions failed: %v\n", err)
		} else {
			fmt.Printf("User sessions for %s: %d\n", adminUser.Email, len(sessions))
		}
	}

	fmt.Println("\n=== SEEDING COMPLETE ===")
}

func stringPtr(s string) *string { return &s }
func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int { return &i }
func timePtr(t time.Time) *time.Time { return &t }

func generateClientSecret() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "fallback-secret-" + mongodb.NewID()
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func jwksFromRSAKey(rsaKey *rsa.PrivateKey) (string, error) {
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"n":  rsaKey.PublicKey.N.Text(10),
				"e":  rsaKey.PublicKey.E,
			},
		},
	}
	jsonBytes, err := json.Marshal(jwks)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}
