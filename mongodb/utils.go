package mongodb

import "go.mongodb.org/mongo-driver/v2/bson"

// NewObjectID generates a new MongoDB ObjectID as a string
func NewObjectID() string {
	return bson.NewObjectID().Hex()
}
