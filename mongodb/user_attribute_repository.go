package mongodb

import (
	"context"
	"fmt"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const UserAttributesCollection = "user_attributes"

type UserAttributeRepository struct {
	collection *mongo.Collection
}

func NewUserAttributeRepository(ctx context.Context, db *mongo.Database) (domain.UserAttributeRepository, error) {
	repo := &UserAttributeRepository{
		collection: db.Collection(UserAttributesCollection),
	}
	if err := repo.createIndexes(ctx); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *UserAttributeRepository) createIndexes(ctx context.Context) error {
	_, err := r.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys:    bson.D{{Key: "user_id", Value: 1}, {Key: "name", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	})
	return err
}

func (r *UserAttributeRepository) CreateAttribute(ctx context.Context, attr *domain.UserAttribute) error {
	attr.ID = bson.NewObjectID().Hex()
	_, err := r.collection.InsertOne(ctx, attr)
	return err
}

func (r *UserAttributeRepository) GetAttributeByID(ctx context.Context, id string) (*domain.UserAttribute, error) {
	var attr domain.UserAttribute
	err := r.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&attr)
	if err != nil {
		return nil, err
	}
	return &attr, nil
}

func (r *UserAttributeRepository) GetAttributesByUserID(ctx context.Context, userID string) ([]*domain.UserAttribute, error) {
	cursor, err := r.collection.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var attrs []*domain.UserAttribute
	if err := cursor.All(ctx, &attrs); err != nil {
		return nil, err
	}
	return attrs, nil
}

func (r *UserAttributeRepository) ListAllAttributes(ctx context.Context) ([]*domain.UserAttribute, error) {
	cursor, err := r.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var attrs []*domain.UserAttribute
	if err := cursor.All(ctx, &attrs); err != nil {
		return nil, err
	}
	return attrs, nil
}

func (r *UserAttributeRepository) UpdateAttribute(ctx context.Context, attr *domain.UserAttribute) error {
	res, err := r.collection.UpdateOne(ctx, bson.M{"_id": attr.ID}, bson.M{"$set": attr})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return fmt.Errorf("user attribute not found")
	}
	return nil
}

func (r *UserAttributeRepository) DeleteAttribute(ctx context.Context, id string) error {
	res, err := r.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return fmt.Errorf("user attribute not found")
	}
	return nil
}

func (r *UserAttributeRepository) DeleteAttributesByUserID(ctx context.Context, userID string) error {
	_, err := r.collection.DeleteMany(ctx, bson.M{"user_id": userID})
	return err
}

const UserAttributeMappersCollection = "user_attribute_mappers"

type UserAttributeMapperRepository struct {
	collection *mongo.Collection
}

func NewUserAttributeMapperRepository(ctx context.Context, db *mongo.Database) (domain.UserAttributeMapperRepository, error) {
	repo := &UserAttributeMapperRepository{
		collection: db.Collection(UserAttributeMappersCollection),
	}
	if err := repo.createIndexes(ctx); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *UserAttributeMapperRepository) createIndexes(ctx context.Context) error {
	_, err := r.collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "token_type", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "client_id", Value: 1}},
		},
	})
	return err
}

func (r *UserAttributeMapperRepository) CreateMapper(ctx context.Context, mapper *domain.UserAttributeMapper) error {
	mapper.ID = bson.NewObjectID().Hex()
	mapper.CreatedAt = time.Now()
	mapper.UpdatedAt = time.Now()
	_, err := r.collection.InsertOne(ctx, mapper)
	return err
}

func (r *UserAttributeMapperRepository) GetMapperByID(ctx context.Context, id string) (*domain.UserAttributeMapper, error) {
	var mapper domain.UserAttributeMapper
	err := r.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&mapper)
	if err != nil {
		return nil, err
	}
	return &mapper, nil
}

func (r *UserAttributeMapperRepository) GetMappersByTokenType(ctx context.Context, tokenType string) ([]*domain.UserAttributeMapper, error) {
	cursor, err := r.collection.Find(ctx, bson.M{"token_type": tokenType})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var mappers []*domain.UserAttributeMapper
	if err := cursor.All(ctx, &mappers); err != nil {
		return nil, err
	}
	return mappers, nil
}

func (r *UserAttributeMapperRepository) GetMappersForClient(ctx context.Context, clientID string, tokenType string) ([]*domain.UserAttributeMapper, error) {
	cursor, err := r.collection.Find(ctx, bson.M{
		"token_type": tokenType,
		"$or": []bson.M{
			{"client_id": clientID},
			{"client_id": bson.M{"$exists": false}},
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var mappers []*domain.UserAttributeMapper
	if err := cursor.All(ctx, &mappers); err != nil {
		return nil, err
	}
	return mappers, nil
}

func (r *UserAttributeMapperRepository) GetClientMappers(ctx context.Context, clientID string) ([]*domain.UserAttributeMapper, error) {
	cursor, err := r.collection.Find(ctx, bson.M{"client_id": clientID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var mappers []*domain.UserAttributeMapper
	if err := cursor.All(ctx, &mappers); err != nil {
		return nil, err
	}
	return mappers, nil
}

func (r *UserAttributeMapperRepository) ListAllMappers(ctx context.Context) ([]*domain.UserAttributeMapper, error) {
	cursor, err := r.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var mappers []*domain.UserAttributeMapper
	if err := cursor.All(ctx, &mappers); err != nil {
		return nil, err
	}
	return mappers, nil
}

func (r *UserAttributeMapperRepository) UpdateMapper(ctx context.Context, mapper *domain.UserAttributeMapper) error {
	mapper.UpdatedAt = time.Now()
	res, err := r.collection.UpdateOne(ctx, bson.M{"_id": mapper.ID}, bson.M{"$set": mapper})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return fmt.Errorf("user attribute mapper not found")
	}
	return nil
}

func (r *UserAttributeMapperRepository) DeleteMapper(ctx context.Context, id string) error {
	res, err := r.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return fmt.Errorf("user attribute mapper not found")
	}
	return nil
}

func ptr[T any](v T) *T {
	return &v
}
