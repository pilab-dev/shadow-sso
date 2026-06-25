package mongodb

import (
	"github.com/google/uuid"
)

// NewID generates a new UUID as a string (replaces MongoDB ObjectID)
func NewID() string {
	return uuid.New().String()
}