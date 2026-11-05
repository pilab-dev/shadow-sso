package mongodb_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/pilab-dev/shadow-sso/mongodb"
)

// setupUserListPageTest connects to the test Mongo instance and returns the
// UserRepository plus the raw users collection so the test can seed documents
// carrying fields not modeled by domain.User (username, enabled).
func setupUserListPageTest(t *testing.T) (domain.UserRepository, *mongo.Collection, func(), error) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	dbName := "test_sso_user_repo_" + strconv.FormatInt(time.Now().UnixNano(), 10)

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second))
	if err != nil {
		return nil, nil, func() {}, fmt.Errorf("mongo.Connect failed: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		client.Disconnect(ctx)
		return nil, nil, func() {}, fmt.Errorf("mongo.Ping failed: %w", err)
	}
	db := client.Database(dbName)

	userRepo, err := mongodb.NewUserRepository(ctx, db)
	if err != nil {
		client.Disconnect(ctx)
		return nil, nil, func() {}, fmt.Errorf("NewUserRepositoryMongo failed: %w", err)
	}

	cleanupFunc := func() {
		if dropErr := db.Drop(context.Background()); dropErr != nil {
			t.Logf("Warning: failed to drop test database %s during cleanup: %v", dbName, dropErr)
		}
		if disconnectErr := client.Disconnect(context.Background()); disconnectErr != nil {
			t.Logf("Warning: failed to disconnect test client during cleanup: %v", disconnectErr)
		}
	}

	return userRepo, db.Collection(mongodb.UsersCollection), cleanupFunc, nil
}

func TestUserRepositoryMongo_ListUsersPage(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	userRepo, users, cleanup, err := setupUserListPageTest(t)
	require.NoError(t, err, "Failed to setup user repo test")
	defer cleanup()

	ctx := context.Background()

	// Seed via raw inserts so every document carries the same field set
	// (username and enabled are not modeled by domain.User) and deterministic
	// created_at timestamps for ordering assertions.
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	seed := []interface{}{
		bson.M{"_id": "seed-alice", "email": "alice@example.com", "username": "alice.a", "first_name": "Alice", "last_name": "Anderson", "enabled": true, "is_email_verified": true, "created_at": base.Add(1 * time.Second)},
		bson.M{"_id": "seed-bob", "email": "bob@example.com", "username": "bob.b", "first_name": "Bob", "last_name": "Baker", "enabled": true, "is_email_verified": false, "created_at": base.Add(2 * time.Second)},
		bson.M{"_id": "seed-carol", "email": "carol@example.com", "username": "carol.c", "first_name": "Carol", "last_name": "Clark", "enabled": false, "is_email_verified": true, "created_at": base.Add(3 * time.Second)},
		bson.M{"_id": "seed-dave", "email": "dave@example.com", "username": "dave.d", "first_name": "Dave", "last_name": "Duncan", "enabled": true, "is_email_verified": false, "created_at": base.Add(4 * time.Second)},
		bson.M{"_id": "seed-erin", "email": "erin@example.com", "username": "erin.e", "first_name": "Erin", "last_name": "Ebert", "enabled": false, "is_email_verified": true, "created_at": base.Add(5 * time.Second)},
	}
	_, err = users.InsertMany(ctx, seed)
	require.NoError(t, err, "seeding users")

	emails := func(result []*domain.User) []string {
		got := make([]string, 0, len(result))
		for _, u := range result {
			got = append(got, u.Email)
		}
		return got
	}
	page := func(t *testing.T, filter domain.UserFilter, sort domain.SortSpec, skip, limit int) ([]string, int64) {
		t.Helper()
		result, total, err := userRepo.ListUsersPage(ctx, filter, sort, skip, limit)
		require.NoError(t, err)
		return emails(result), total
	}

	t.Run("SearchIsCaseInsensitiveAcrossFields", func(t *testing.T) {
		search := "alice" // matches email, username and first name of the same user
		got, _ := page(t, domain.UserFilter{Search: &search}, domain.SortSpec{}, 0, 100)
		assert.ElementsMatch(t, []string{"alice@example.com"}, got)

		upper := "ALICE"
		got, _ = page(t, domain.UserFilter{Search: &upper}, domain.SortSpec{}, 0, 100)
		assert.ElementsMatch(t, []string{"alice@example.com"}, got)

		lastName := "clark" // matches last_name only
		got, _ = page(t, domain.UserFilter{Search: &lastName}, domain.SortSpec{}, 0, 100)
		assert.ElementsMatch(t, []string{"carol@example.com"}, got)

		username := "dave.d" // matches username only
		got, _ = page(t, domain.UserFilter{Search: &username}, domain.SortSpec{}, 0, 100)
		assert.ElementsMatch(t, []string{"dave@example.com"}, got)

		domainWide := "@example.com" // matches every email
		got, total := page(t, domain.UserFilter{Search: &domainWide}, domain.SortSpec{}, 0, 100)
		assert.ElementsMatch(t, []string{"alice@example.com", "bob@example.com", "carol@example.com", "dave@example.com", "erin@example.com"}, got)
		assert.Equal(t, int64(5), total)
	})

	t.Run("ExactFieldFilters", func(t *testing.T) {
		email := "bob@example.com"
		got, total := page(t, domain.UserFilter{Email: &email}, domain.SortSpec{}, 0, 100)
		assert.Equal(t, []string{"bob@example.com"}, got)
		assert.Equal(t, int64(1), total)

		username := "erin.e"
		got, _ = page(t, domain.UserFilter{Username: &username}, domain.SortSpec{}, 0, 100)
		assert.Equal(t, []string{"erin@example.com"}, got)

		firstName := "Carol"
		got, _ = page(t, domain.UserFilter{FirstName: &firstName}, domain.SortSpec{}, 0, 100)
		assert.Equal(t, []string{"carol@example.com"}, got)

		lastName := "Duncan"
		got, _ = page(t, domain.UserFilter{LastName: &lastName}, domain.SortSpec{}, 0, 100)
		assert.Equal(t, []string{"dave@example.com"}, got)

		enabled := true
		got, total = page(t, domain.UserFilter{Enabled: &enabled}, domain.SortSpec{}, 0, 100)
		assert.ElementsMatch(t, []string{"alice@example.com", "bob@example.com", "dave@example.com"}, got)
		assert.Equal(t, int64(3), total)

		disabled := false
		got, _ = page(t, domain.UserFilter{Enabled: &disabled}, domain.SortSpec{}, 0, 100)
		assert.ElementsMatch(t, []string{"carol@example.com", "erin@example.com"}, got)

		verified := true
		got, _ = page(t, domain.UserFilter{EmailVerified: &verified}, domain.SortSpec{}, 0, 100)
		assert.ElementsMatch(t, []string{"alice@example.com", "carol@example.com", "erin@example.com"}, got)

		unverified := false
		got, _ = page(t, domain.UserFilter{EmailVerified: &unverified}, domain.SortSpec{}, 0, 100)
		assert.ElementsMatch(t, []string{"bob@example.com", "dave@example.com"}, got)
	})

	t.Run("SortByAllowlistedFields", func(t *testing.T) {
		cases := []struct {
			name string
			sort domain.SortSpec
			want []string // emails in expected order
		}{
			{"createdAt asc", domain.SortSpec{Field: "createdAt", Dir: "asc"}, []string{"alice@example.com", "bob@example.com", "carol@example.com", "dave@example.com", "erin@example.com"}},
			{"createdAt desc", domain.SortSpec{Field: "createdAt", Dir: "desc"}, []string{"erin@example.com", "dave@example.com", "carol@example.com", "bob@example.com", "alice@example.com"}},
			{"email asc", domain.SortSpec{Field: "email", Dir: "asc"}, []string{"alice@example.com", "bob@example.com", "carol@example.com", "dave@example.com", "erin@example.com"}},
			{"email desc", domain.SortSpec{Field: "email", Dir: "desc"}, []string{"erin@example.com", "dave@example.com", "carol@example.com", "bob@example.com", "alice@example.com"}},
			{"username asc", domain.SortSpec{Field: "username", Dir: "asc"}, []string{"alice@example.com", "bob@example.com", "carol@example.com", "dave@example.com", "erin@example.com"}},
			{"username desc", domain.SortSpec{Field: "username", Dir: "desc"}, []string{"erin@example.com", "dave@example.com", "carol@example.com", "bob@example.com", "alice@example.com"}},
			{"empty dir defaults to asc", domain.SortSpec{Field: "email", Dir: ""}, []string{"alice@example.com", "bob@example.com", "carol@example.com", "dave@example.com", "erin@example.com"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, _ := page(t, domain.UserFilter{}, tc.sort, 0, 100)
				assert.Equal(t, tc.want, got)
			})
		}
	})

	t.Run("UnknownSortFieldFallsBackToDefault", func(t *testing.T) {
		defaultOrder := []string{"erin@example.com", "dave@example.com", "carol@example.com", "bob@example.com", "alice@example.com"}

		bogus := domain.SortSpec{Field: "bogus", Dir: "desc"}
		got, _ := page(t, domain.UserFilter{}, bogus, 0, 100)
		assert.Equal(t, defaultOrder, got)

		got, _ = page(t, domain.UserFilter{}, domain.SortSpec{}, 0, 100)
		assert.Equal(t, defaultOrder, got)
	})

	t.Run("TotalCountReflectsFilterNotPaging", func(t *testing.T) {
		_, total, err := userRepo.ListUsersPage(ctx, domain.UserFilter{}, domain.SortSpec{}, 0, 2)
		require.NoError(t, err)
		assert.Equal(t, int64(5), total)

		_, total, err = userRepo.ListUsersPage(ctx, domain.UserFilter{}, domain.SortSpec{}, 100, 100)
		require.NoError(t, err)
		assert.Equal(t, int64(5), total)
	})

	t.Run("SkipAndLimitPageThroughResults", func(t *testing.T) {
		defaultOrder := []string{"erin@example.com", "dave@example.com", "carol@example.com", "bob@example.com", "alice@example.com"}

		got, total := page(t, domain.UserFilter{}, domain.SortSpec{}, 0, 2)
		assert.Equal(t, defaultOrder[:2], got)
		assert.Equal(t, int64(5), total)

		got, _ = page(t, domain.UserFilter{}, domain.SortSpec{}, 2, 2)
		assert.Equal(t, defaultOrder[2:4], got)

		got, _ = page(t, domain.UserFilter{}, domain.SortSpec{}, 4, 2)
		assert.Equal(t, defaultOrder[4:], got)

		got, _ = page(t, domain.UserFilter{}, domain.SortSpec{}, 10, 2)
		assert.Empty(t, got)
	})
}
