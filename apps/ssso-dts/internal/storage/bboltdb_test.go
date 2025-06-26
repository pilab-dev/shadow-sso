package storage

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func setupTestDB(t *testing.T) (store *BBoltStore, dbPath string, cleanup func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "dts_bbolt_test_")
	require.NoError(t, err)

	dbPath = filepath.Join(tempDir, "test_dts.db")
	store, err = NewBBoltStore(dbPath, 1*time.Hour, 10*time.Minute) // Default TTL 1hr, cleanup 10min
	require.NoError(t, err)

	// For storage tests, we don't need the cleanup goroutine running aggressively,
	// but ensure buckets are there.KnownBuckets() are created by service layer.
	// Here, ensureBucket is called by Set if needed.
	// store.StartCleanupRoutine(KnownBuckets()) // Not strictly needed for these unit tests unless testing cleanup itself

	cleanup = func() {
		err := store.Close()
		assert.NoError(t, err, "Failed to close BBoltStore")
		err = os.RemoveAll(tempDir)
		assert.NoError(t, err, "Failed to remove temp dir")
	}

	return store, dbPath, cleanup
}

func TestBBoltStore_SetGetDelete(t *testing.T) {
	store, _, cleanup := setupTestDB(t)
	defer cleanup()

	bucket := "testbucket"
	key := "testkey"
	value := []byte("testvalue")

	// 1. Test Set
	err := store.Set(bucket, key, value, 0) // Use default TTL
	require.NoError(t, err)

	// 2. Test Get
	retrievedValue, expiresAt, found, err := store.Get(bucket, key)
	require.NoError(t, err)
	require.True(t, found, "Value should be found")
	assert.Equal(t, value, retrievedValue, "Retrieved value does not match original")
	assert.False(t, expiresAt.IsZero(), "ExpiresAt should be set for default TTL")
	assert.True(t, expiresAt.After(time.Now()), "ExpiresAt should be in the future")

	// 3. Test Get non-existent key
	_, _, notFound, err := store.Get(bucket, "nonexistentkey")
	require.NoError(t, err)
	assert.False(t, notFound, "Non-existent key should not be found")

	// 4. Test Delete
	err = store.Delete(bucket, key)
	require.NoError(t, err)

	// 5. Test Get after delete
	_, _, foundAfterDelete, err := store.Get(bucket, key)
	require.NoError(t, err)
	assert.False(t, foundAfterDelete, "Value should not be found after delete")
}

func TestBBoltStore_TTL(t *testing.T) {
	store, _, cleanup := setupTestDB(t)
	defer cleanup()

	bucket := "ttlbucket"
	key := "ttlkey"
	value := []byte("ttlvalue")
	shortTTL := 100 * time.Millisecond // Very short TTL for testing

	// 1. Set with short TTL
	err := store.Set(bucket, key, value, shortTTL)
	require.NoError(t, err)

	// 2. Get immediately (should be found)
	retrievedValue, expiresAt, found, err := store.Get(bucket, key)
	require.NoError(t, err)
	require.True(t, found, "Value should be found immediately")
	assert.Equal(t, value, retrievedValue)
	assert.WithinDuration(t, time.Now().Add(shortTTL), expiresAt, 20*time.Millisecond) // Check expiry is roughly correct

	// 3. Wait for TTL to expire
	time.Sleep(shortTTL + 50*time.Millisecond) // Sleep a bit longer than TTL

	// 4. Get after TTL expiry (should not be found)
	_, _, foundAfterExpiry, err := store.Get(bucket, key)
	require.NoError(t, err)
	assert.False(t, foundAfterExpiry, "Value should not be found after TTL expiry")

	// 5. Test "never expires"
	neverExpireKey := "neverexpirekey"
	err = store.Set(bucket, neverExpireKey, value, -1) // Negative TTL means never expires
	require.NoError(t, err)

	_, expiresAtNever, foundNever, err := store.Get(bucket, neverExpireKey)
	require.NoError(t, err)
	require.True(t, foundNever)
	assert.True(t, expiresAtNever.IsZero(), "ExpiresAt should be zero for never-expiring item")
}

func TestBBoltStore_Persistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dts_persist_test_")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "persist_dts.db")

	bucket := "persistbucket"
	key := "persistkey"
	value := []byte("persistvalue")

	// 1. Create store, set value, close store
	store1, err := NewBBoltStore(dbPath, 1*time.Hour, 10*time.Minute)
	require.NoError(t, err)
	err = store1.Set(bucket, key, value, 0) // Default TTL
	require.NoError(t, err)
	err = store1.Close()
	require.NoError(t, err)

	// 2. Create new store instance with the same DB file
	store2, err := NewBBoltStore(dbPath, 1*time.Hour, 10*time.Minute)
	require.NoError(t, err)
	defer store2.Close()

	// 3. Get the value, should exist
	retrievedValue, _, found, err := store2.Get(bucket, key)
	require.NoError(t, err)
	assert.True(t, found, "Value should be found after reopening DB")
	assert.Equal(t, value, retrievedValue, "Retrieved value does not match original after reopening")
}

func TestBBoltStore_CleanupRoutine(t *testing.T) {
	t.Skip("Skipping cleanup routine test in automated unit tests due to timing complexities; test manually or with specific mock time.")
	// This test is harder to make reliable in CI without time mocking.
	// Manual verification or longer integration tests are better.

	// store, _, cleanup := setupTestDB(t)
	// store.cleanupInterval = 50 * time.Millisecond // Override for test
	// defer cleanup()

	// store.StartCleanupRoutine([]string{"cleanupbucket_ops", "cleanupbucket_exp"})

	// bucketOps := "cleanupbucket_ops" // Operations bucket
	// bucketExp := "cleanupbucket_exp" // Expiration bucket

	// // Item that should expire and be cleaned up
	// err := store.Set(bucketExp, "keyToExpire", []byte("data"), 10*time.Millisecond)
	// require.NoError(t, err)

	// // Item that should not expire
	// err = store.Set(bucketOps, "keyToKeep", []byte("data"), 1*time.Hour)
	// require.NoError(t, err)

	// // Wait for multiple cleanup cycles
	// time.Sleep(3 * store.cleanupInterval) // Wait for cleanup to run

	// // Check expired item is gone
	// _, _, foundExpired, err := store.Get(bucketExp, "keyToExpire")
	// require.NoError(t, err)
	// assert.False(t, foundExpired, "Expired item should have been cleaned up")

	// // Check non-expired item is still there
	// _, _, foundKeep, err := store.Get(bucketOps, "keyToKeep")
	// require.NoError(t, err)
	// assert.True(t, foundKeep, "Non-expired item should still exist")
}

func TestBBoltStore_EnsureBucket(t *testing.T) {
	store, _, cleanup := setupTestDB(t)
	defer cleanup()

	bucketName := "ensure_test_bucket"

	// ensureBucket is private, but Set calls it.
	err := store.Set(bucketName, "dummykey", []byte("dummy"), 1*time.Hour)
	require.NoError(t, err)

	err = store.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return fmt.Errorf("bucket '%s' was not created", bucketName)
		}
		metaBucketName := bucketName + metadataSuffix
		mb := tx.Bucket([]byte(metaBucketName))
		if mb == nil {
			return fmt.Errorf("metadata bucket '%s' was not created", metaBucketName)
		}
		return nil
	})
	assert.NoError(t, err, "EnsureBucket failed to create main or metadata bucket")
}

func TestBBoltStore_Get_MetadataDecodeError(t *testing.T) {
	store, _, cleanup := setupTestDB(t)
	defer cleanup()

	bucket := "decode_error_bucket"
	key := "baddata_key"

	// Manually insert malformed metadata
	require.NoError(t, store.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		require.NoError(t, err)
		metaB, err := tx.CreateBucketIfNotExists([]byte(bucket + metadataSuffix))
		require.NoError(t, err)

		// Put some data in the main bucket
		mainB := tx.Bucket([]byte(bucket))
		err = mainB.Put([]byte(key), []byte("some data"))
		require.NoError(t, err)

		// Put invalid GOB data into metadata bucket
		return metaB.Put([]byte(key), []byte("this is not valid gob data"))
	}))

	_, _, found, err := store.Get(bucket, key)
	assert.Error(t, err, "Expected an error due to metadata decode failure")
	assert.Contains(t, err.Error(), "failed to decode metadata", "Error message should indicate decode failure")
	assert.False(t, found, "Item should not be considered found if metadata is corrupt")

	// Test with empty metadata (should be treated as not found or no TTL)
	keyEmptyMeta := "empty_meta_key"
	require.NoError(t, store.db.Update(func(tx *bbolt.Tx) error {
		metaB := tx.Bucket([]byte(bucket + metadataSuffix))
		require.NotNil(t, metaB)
		mainB := tx.Bucket([]byte(bucket))
		require.NotNil(t, mainB)

		err := mainB.Put([]byte(keyEmptyMeta), []byte("data for empty meta"))
		require.NoError(t, err)
		// No Put to metaB for keyEmptyMeta, or Put with nil/empty bytes
		return metaB.Put([]byte(keyEmptyMeta), nil) // Explicitly nil metadata
	}))

	_, _, found, err = store.Get(bucket, keyEmptyMeta)
	assert.NoError(t, err, "Error should be nil for nil metadata bytes (treated as not found by Get)")
	assert.False(t, found, "Item should not be found if metadata bytes are nil")
}

func TestBBoltStore_Get_DataMissingWithMetadata(t *testing.T) {
	store, _, cleanup := setupTestDB(t)
	defer cleanup()

	bucket := "missing_data_bucket"
	key := "metadata_exists_data_gone"

	// Manually insert metadata but no corresponding data
	require.NoError(t, store.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		require.NoError(t, err)
		metaB, err := tx.CreateBucketIfNotExists([]byte(bucket + metadataSuffix))
		require.NoError(t, err)

		// Valid metadata for a non-expired item
		metadata := StoredItemMetadata{ExpiresAtUnixNano: time.Now().Add(1 * time.Hour).UnixNano()}
		var metaBuf bytes.Buffer
		require.NoError(t, gob.NewEncoder(&metaBuf).Encode(metadata))
		err = metaB.Put([]byte(key), metaBuf.Bytes())
		require.NoError(t, err)

		// Ensure no data in the main bucket for this key
		mainB := tx.Bucket([]byte(bucket))
		return mainB.Delete([]byte(key)) // Ensure it's deleted if it somehow existed
	}))

	val, exp, found, err := store.Get(bucket, key)
	assert.NoError(t, err, "Get should not error if data is missing but metadata exists")
	assert.False(t, found, "Item should not be found if data is missing, even if metadata exists")
	assert.Nil(t, val)
	assert.True(t, exp.IsZero())
}
