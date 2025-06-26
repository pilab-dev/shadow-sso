package mongodb

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	serrors "github.com/pilab-dev/shadow-sso/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type DeviceAuthRepository struct {
	deviceAuth *mongo.Collection
}

func NewDeviceAuthRepository(db *mongo.Database) *DeviceAuthRepository {
	return &DeviceAuthRepository{
		deviceAuth: db.Collection(DeviceAuthCollectionName),
	}
}

// DeviceAuthorizationRepository implementation
func (r *DeviceAuthRepository) SaveDeviceAuth(ctx context.Context, auth *domain.DeviceCode) error {
	auth.ID = uuid.NewString()
	auth.CreatedAt = time.Now().UTC()

	_, err := r.deviceAuth.InsertOne(ctx, auth)
	if err != nil {
		return err
	}

	return nil
}

func (r *DeviceAuthRepository) GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*domain.DeviceCode, error) {
	var result domain.DeviceCode

	err := r.deviceAuth.FindOne(ctx, bson.M{"device_code": deviceCode}).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, serrors.ErrDeviceCodeNotFound
		}

		return nil, err
	}

	return &result, nil
}

func (r *DeviceAuthRepository) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*domain.DeviceCode, error) {
	var result domain.DeviceCode
	filter := bson.M{
		"user_code":  userCode,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}
	err := r.deviceAuth.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, serrors.ErrUserCodeNotFound
		}
		return nil, err
	}
	return &result, nil
}

func (r *DeviceAuthRepository) ApproveDeviceAuth(ctx context.Context, userCode string, userID string) (*domain.DeviceCode, error) {
	filter := bson.M{
		"user_code":  userCode,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
		"status":     domain.DeviceCodeStatusPending,
	}
	update := bson.M{
		"$set": bson.M{
			"status":  domain.DeviceCodeStatusAuthorized,
			"user_id": userID,
		},
	}
	opt := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var updatedDoc domain.DeviceCode

	err := r.deviceAuth.FindOneAndUpdate(ctx, filter, update, opt).Decode(&updatedDoc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, serrors.ErrCannotApproveDeviceAuth
		}
		return nil, err
	}

	return &updatedDoc, nil
}

func (r *DeviceAuthRepository) UpdateDeviceAuthStatus(ctx context.Context, deviceCode string, status domain.DeviceCodeStatus) error {
	filter := bson.M{"device_code": deviceCode}
	update := bson.M{"$set": bson.M{"status": status}}

	result, err := r.deviceAuth.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return serrors.ErrDeviceCodeNotFound
	}

	return nil
}

func (r *DeviceAuthRepository) UpdateDeviceAuthLastPolledAt(ctx context.Context, deviceCode string) error {
	filter := bson.M{"device_code": deviceCode}
	update := bson.M{"$set": bson.M{"last_polled_at": time.Now().UTC()}}

	result, err := r.deviceAuth.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return serrors.ErrDeviceCodeNotFound
	}

	return nil
}

func (r *DeviceAuthRepository) DeleteExpiredDeviceAuths(ctx context.Context) error {
	filter := bson.M{
		"$or": []bson.M{
			{"expires_at": bson.M{"$lte": time.Now().UTC()}},
		},
	}

	_, err := r.deviceAuth.DeleteMany(ctx, filter)

	return err
}
