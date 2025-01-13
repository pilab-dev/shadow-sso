//go:build mongodb

package mongodb

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// NewObjectID generates a new MongoDB ObjectID as a string
func NewObjectID() string {
	return primitive.NewObjectID().Hex()
}
