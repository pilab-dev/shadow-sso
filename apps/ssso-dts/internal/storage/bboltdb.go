package storage

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"path/filepath"
	"os"
	"time"

	"go.etcd.io/bbolt"
)

const (
	// DefaultBucketName is used if no specific bucket is provided for generic operations.
	DefaultBucketName = "default"
	metadataSuffix    = "_meta"
)

// StoredItemMetadata holds metadata for a stored item, primarily its expiration time.
type StoredItemMetadata struct {
	ExpiresAtUnixNano int64
}

// BBoltStore is a wrapper around BBoltDB providing key-value storage with TTL.
type BBoltStore struct {
	db              *bbolt.DB
	defaultTTL      time.Duration
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewBBoltStore initializes and returns a new BBoltStore.
// It also creates necessary buckets if they don't exist and starts the cleanup goroutine.
func NewBBoltStore(dbPath string, defaultTTL, cleanupInterval time.Duration) (*BBoltStore, error) {
	// Ensure the directory for the database file exists
	dir := filepath.Dir(dbPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Printf("Directory %s does not exist, creating it.", dir)
		if err := os.MkdirAll(dir, 0750); err != nil { // rwxr-x---
			return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to check database directory %s: %w", dir, err)
	}


	log.Printf("Initializing BBoltDB at path: %s", dbPath)
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 5 * time.Second}) // Read/Write for owner only
	if err != nil {
		return nil, fmt.Errorf("failed to open bbolt db at %s: %w", dbPath, err)
	}

	store := &BBoltStore{
		db:              db,
		defaultTTL:      defaultTTL,
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
	}

	// Ensure default bucket exists
	if err := store.ensureBucket(DefaultBucketName); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ensure default bucket: %w", err)
	}

	log.Println("BBoltDB initialized successfully.")
	return store, nil
}

// StartCleanupRoutine starts the background process for cleaning up expired items.
func (s *BBoltStore) StartCleanupRoutine(initialBuckets []string) {
	if s.cleanupInterval <= 0 {
		log.Println("Cleanup interval is zero or negative, not starting cleanup routine.")
		return
	}
	log.Printf("Starting cleanup routine with interval: %v", s.cleanupInterval)
	go s.runCleanupLoop(initialBuckets)
}


func (s *BBoltStore) ensureBucket(bucketName string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return fmt.Errorf("failed to create bucket %s: %w", bucketName, err)
		}
		// Also ensure metadata bucket exists for this main bucket
		_, err = tx.CreateBucketIfNotExists([]byte(bucketName + metadataSuffix))
		if err != nil {
			return fmt.Errorf("failed to create metadata bucket for %s: %w", bucketName, err)
		}
		return nil
	})
}

// Set stores a key-value pair in the specified bucket with an optional TTL.
// If ttl is 0, defaultTTL is used. If ttl is negative, item never expires.
func (s *BBoltStore) Set(bucketName, key string, value []byte, ttl time.Duration) error {
	if bucketName == "" {
		bucketName = DefaultBucketName
	}
	if err := s.ensureBucket(bucketName); err != nil {
		return err
	}

	var expiresAtUnixNano int64
	if ttl < 0 { // Never expires
		expiresAtUnixNano = 0
	} else {
		if ttl == 0 {
			ttl = s.defaultTTL
		}
		expiresAtUnixNano = time.Now().Add(ttl).UnixNano()
	}

	metadata := StoredItemMetadata{ExpiresAtUnixNano: expiresAtUnixNano}
	var metaBuf bytes.Buffer
	if err := gob.NewEncoder(&metaBuf).Encode(metadata); err != nil {
		return fmt.Errorf("failed to encode metadata for key %s: %w", key, err)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return fmt.Errorf("bucket %s not found (should have been created)", bucketName)
		}
		if err := b.Put([]byte(key), value); err != nil {
			return fmt.Errorf("failed to put value for key %s in bucket %s: %w", key, bucketName, err)
		}

		metaB := tx.Bucket([]byte(bucketName + metadataSuffix))
		if metaB == nil {
			return fmt.Errorf("metadata bucket for %s not found", bucketName)
		}
		return metaB.Put([]byte(key), metaBuf.Bytes())
	})
}

// Get retrieves a value by key from the specified bucket.
// It returns the value, its expiration timestamp, a boolean indicating if found, and any error.
// If the item is expired, it's treated as not found and may be deleted.
func (s *BBoltStore) Get(bucketName, key string) ([]byte, time.Time, bool, error) {
	if bucketName == "" {
		bucketName = DefaultBucketName
	}

	var value []byte
	var expiresAt time.Time
	var found bool

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return nil // Bucket not found, so key isn't either
		}
		metaB := tx.Bucket([]byte(bucketName + metadataSuffix))
		if metaB == nil {
			return nil // Metadata bucket not found
		}

		metaBytes := metaB.Get([]byte(key))
		if metaBytes == nil {
			return nil // No metadata, so key effectively not found or not managed by this system
		}

		var metadata StoredItemMetadata
		if err := gob.NewDecoder(bytes.NewReader(metaBytes)).Decode(&metadata); err != nil {
			return fmt.Errorf("failed to decode metadata for key %s: %w", key, err)
		}

		if metadata.ExpiresAtUnixNano != 0 && time.Now().UnixNano() > metadata.ExpiresAtUnixNano {
			// Item expired
			// Optionally, we could delete it here, but that requires a db.Update.
			// The cleanup routine will handle it. For Get, just report as not found.
			log.Printf("Key %s in bucket %s found but expired at %v", key, bucketName, time.Unix(0, metadata.ExpiresAtUnixNano))
			return nil
		}

		valBytes := b.Get([]byte(key))
		if valBytes == nil {
			// Data missing but metadata exists? Inconsistent. Treat as not found.
			return nil
		}

		// Need to copy the value, as it's only valid during the transaction.
		value = make([]byte, len(valBytes))
		copy(value, valBytes)

		if metadata.ExpiresAtUnixNano != 0 {
			expiresAt = time.Unix(0, metadata.ExpiresAtUnixNano)
		}
		found = true
		return nil
	})

	if err != nil {
		return nil, time.Time{}, false, err
	}

	// If found but expired during the read (edge case if clock changed or long view tx)
	// This check is mostly redundant due to the check inside the View func but provides safety.
	if found && !expiresAt.IsZero() && time.Now().After(expiresAt) {
		// Consider deleting it proactively, though this needs an Update transaction.
		// For simplicity, let cleanup handle it.
		// s.Delete(bucketName, key) // This would require changing Get to use Update tx or a more complex flow.
		return nil, expiresAt, false, nil
	}

	return value, expiresAt, found, nil
}

// Delete removes a key-value pair from the specified bucket.
func (s *BBoltStore) Delete(bucketName, key string) error {
	if bucketName == "" {
		bucketName = DefaultBucketName
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return nil // Bucket not found, nothing to delete
		}
		if err := b.Delete([]byte(key)); err != nil {
			return fmt.Errorf("failed to delete key %s from bucket %s: %w", key, bucketName, err)
		}

		metaB := tx.Bucket([]byte(bucketName + metadataSuffix))
		if metaB == nil {
			return nil // Metadata bucket not found
		}
		return metaB.Delete([]byte(key))
	})
}

// runCleanupLoop periodically scans all managed buckets and removes expired items.
// `initialBuckets` are the buckets known at startup. More buckets might be created dynamically.
func (s *BBoltStore) runCleanupLoop(initialBuckets []string) {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	dynamicBuckets := make(map[string]struct{})
	for _, b := range initialBuckets {
		dynamicBuckets[b] = struct{}{}
	}


	for {
		select {
		case <-ticker.C:
			log.Println("Running cleanup for expired items...")

			// Discover current buckets, as new ones might have been created
			// This is a simplified discovery; a more robust way might be needed if buckets are numerous or dynamic.
			err := s.db.View(func(tx *bbolt.Tx) error {
				return tx.ForEach(func(name []byte, _ *bbolt.Bucket) error {
					bucketName := string(name)
					if !bytes.HasSuffix(name, []byte(metadataSuffix)) { // Only consider main data buckets
						dynamicBuckets[bucketName] = struct{}{}
					}
					return nil
				})
			})
			if err != nil {
				log.Printf("Error discovering buckets during cleanup: %v", err)
				continue // Try again next tick
			}

			for bucketName := range dynamicBuckets {
				log.Printf("Cleaning bucket: %s", bucketName)
				var keysToDelete []string
				err := s.db.View(func(tx *bbolt.Tx) error {
					metaB := tx.Bucket([]byte(bucketName + metadataSuffix))
					if metaB == nil {
						log.Printf("Metadata bucket for %s not found during cleanup.", bucketName)
						return nil // Nothing to clean in this non-existent meta bucket
					}

					c := metaB.Cursor()
					nowNano := time.Now().UnixNano()
					for k, v := c.First(); k != nil; k, v = c.Next() {
						var metadata StoredItemMetadata
						if err := gob.NewDecoder(bytes.NewReader(v)).Decode(&metadata); err != nil {
							log.Printf("Error decoding metadata for key %s in bucket %s during cleanup: %v. Skipping.", string(k), bucketName, err)
							continue
						}
						if metadata.ExpiresAtUnixNano != 0 && nowNano > metadata.ExpiresAtUnixNano {
							keysToDelete = append(keysToDelete, string(k))
						}
					}
					return nil
				})

				if err != nil {
					log.Printf("Error during view scan for cleanup in bucket %s: %v", bucketName, err)
					continue // Try next bucket or next tick
				}

				if len(keysToDelete) > 0 {
					log.Printf("Deleting %d expired items from bucket %s", len(keysToDelete), bucketName)
					err := s.db.Update(func(tx *bbolt.Tx) error {
						b := tx.Bucket([]byte(bucketName))
						metaB := tx.Bucket([]byte(bucketName + metadataSuffix))
						if b == nil || metaB == nil {
							log.Printf("Data or metadata bucket for %s disappeared during cleanup update.", bucketName)
							return nil // Or an error
						}
						for _, key := range keysToDelete {
							if err := b.Delete([]byte(key)); err != nil {
								log.Printf("Error deleting key %s from data bucket %s: %v", key, bucketName, err)
								// Continue to delete other keys
							}
							if err := metaB.Delete([]byte(key)); err != nil {
								log.Printf("Error deleting key %s from metadata bucket %s: %v", key, bucketName, err)
								// Continue
							}
						}
						return nil
					})
					if err != nil {
						log.Printf("Error during batch delete in bucket %s: %v", bucketName, err)
					}
				} else {
					log.Printf("No expired items to delete in bucket %s", bucketName)
				}
			}
		case <-s.stopCleanup:
			log.Println("Stopping cleanup routine.")
			return
		}
	}
}

// Close closes the BBoltDB database.
func (s *BBoltStore) Close() error {
	log.Println("Closing BBoltStore...")
	if s.stopCleanup != nil {
		close(s.stopCleanup)
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetDB returns the underlying bbolt.DB instance.
// Useful for more complex operations if needed, or for backup.
func (s *BBoltStore) GetDB() *bbolt.DB {
	return s.db
}

// KnownBuckets lists the names of buckets that are expected to be used by the DTS service.
// This can be used to initialize the cleanup routine.
func KnownBuckets() []string {
	return []string{
		DefaultBucketName, // Generic items
		"authcodes",
		"refreshtokens",
		"accesstokenmetadata",
		"oidcflows",
		"usersessions",
		"deviceauthgrants",
		"pkcestates",
	}
}
