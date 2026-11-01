package ssosession

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeAccount_MovesAccountToFront(t *testing.T) {
	now := time.Now()
	existing := &Session{
		SessionID: "session-1",
		Accounts: []Account{
			{UserID: "old", Email: "old@example.com", Name: "Old User", LastUsed: now.Add(-time.Hour)},
			{UserID: "current", Email: "current@example.com", Name: "Current User", LastUsed: now.Add(-time.Minute)},
		},
	}

	merged := MergeAccount(existing, Account{
		UserID:   "new",
		Email:    "new@example.com",
		Name:     "New User",
		LastUsed: now,
	})

	require.Len(t, merged.Accounts, 3)
	assert.Equal(t, "session-1", merged.SessionID)
	assert.Equal(t, "new", merged.Accounts[0].UserID)
	assert.Equal(t, "old", merged.Accounts[1].UserID)
	assert.Equal(t, "current", merged.Accounts[2].UserID)
}

func TestMergeAccount_PreservesMissingMetadata(t *testing.T) {
	existing := &Session{
		SessionID: "session-1",
		Accounts: []Account{{
			UserID: "user-1",
			Email:  "user@example.com",
			Name:   "Test User",
		}},
	}

	merged := MergeAccount(existing, Account{UserID: "user-1"})

	require.Len(t, merged.Accounts, 1)
	assert.Equal(t, "user@example.com", merged.Accounts[0].Email)
	assert.Equal(t, "Test User", merged.Accounts[0].Name)
}

func TestMergeAccount_KeepsOnlyMostRecentAccounts(t *testing.T) {
	existing := &Session{SessionID: "session-1"}
	for i := 0; i < MaxAccounts; i++ {
		existing.Accounts = append(existing.Accounts, Account{UserID: string(rune('a' + i))})
	}

	merged := MergeAccount(existing, Account{UserID: "new"})

	require.Len(t, merged.Accounts, MaxAccounts)
	assert.Equal(t, "new", merged.Accounts[0].UserID)
	assert.Equal(t, "a", merged.Accounts[1].UserID)
	assert.Equal(t, "d", merged.Accounts[MaxAccounts-1].UserID)
}

func TestMergeAccount_NewSessionWithoutExisting(t *testing.T) {
	merged := MergeAccount(nil, Account{UserID: "user-1", Email: "user@example.com"})

	require.NotNil(t, merged)
	assert.NotEmpty(t, merged.SessionID)
	require.Len(t, merged.Accounts, 1)
	assert.Equal(t, "user-1", merged.Accounts[0].UserID)
}
