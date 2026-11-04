package mongodb

import (
	"context"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const AuditEventsCollection = "audit_events"

// AuditRepository implements domain.AuditLogRepository backed by MongoDB.
type AuditRepository struct {
	db    *mongo.Database
	audit *mongo.Collection
}

// NewAuditRepository creates a new AuditRepository and ensures the query
// indexes (user,timestamp) and (action,timestamp) exist. Index creation
// failures are logged, not fatal — reads still work, just more slowly.
func NewAuditRepository(ctx context.Context, db *mongo.Database) (domain.AuditLogRepository, error) {
	repo := &AuditRepository{
		db:    db,
		audit: db.Collection(AuditEventsCollection),
	}
	if err := repo.createIndexes(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create audit event indexes")
	}
	return repo, nil
}

func (r *AuditRepository) createIndexes(ctx context.Context) error {
	indexModels := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "user", Value: 1}, {Key: "timestamp", Value: -1}},
		},
		{
			Keys: bson.D{{Key: "action", Value: 1}, {Key: "timestamp", Value: -1}},
		},
		{
			// Global followers sort by timestamp with no user/action filter.
			Keys: bson.D{{Key: "timestamp", Value: 1}},
		},
	}
	_, err := r.audit.Indexes().CreateMany(ctx, indexModels)
	return err
}

func (r *AuditRepository) Insert(ctx context.Context, event *domain.AuditLog) error {
	if event.ID == "" {
		event.ID = NewID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	_, err := r.audit.InsertOne(ctx, event)
	return err
}

// List returns audit events matching the filter ordered newest-first, with
// offset/limit pagination. A non-positive limit falls back to a sane default
// so an absent page size cannot return unbounded results.
func (r *AuditRepository) List(ctx context.Context, filter domain.AuditLogFilter, limit, offset int) ([]*domain.AuditLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	findOpts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetSkip(int64(offset)).
		SetLimit(int64(limit))

	cursor, err := r.audit.Find(ctx, r.buildFilter(filter), findOpts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var events []*domain.AuditLog
	if err := cursor.All(ctx, &events); err != nil {
		return nil, err
	}
	return events, nil
}

func (r *AuditRepository) Count(ctx context.Context, filter domain.AuditLogFilter) (int64, error) {
	return r.audit.CountDocuments(ctx, r.buildFilter(filter))
}

// ListAfter returns events at or after `after` ordered oldest-first. The
// inclusive bound is intentional: the follower de-duplicates by event ID, and
// an inclusive cursor cannot drop an event whose timestamp ties the cursor.
func (r *AuditRepository) ListAfter(ctx context.Context, filter domain.AuditLogFilter, after time.Time, limit int) ([]*domain.AuditLog, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := r.buildFilter(filter)
	bound := after
	if filter.From != nil && filter.From.After(bound) {
		bound = *filter.From
	}
	if ts, ok := query["timestamp"].(bson.M); ok {
		ts["$gte"] = bound
	} else {
		query["timestamp"] = bson.M{"$gte": bound}
	}

	findOpts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: 1}}).
		SetLimit(int64(limit))

	cursor, err := r.audit.Find(ctx, query, findOpts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var events []*domain.AuditLog
	if err := cursor.All(ctx, &events); err != nil {
		return nil, err
	}
	return events, nil
}

func (r *AuditRepository) buildFilter(filter domain.AuditLogFilter) bson.M {
	query := bson.M{}
	if filter.User != "" {
		query["user"] = filter.User
	}
	if filter.Action != "" {
		query["action"] = filter.Action
	}
	if filter.From != nil || filter.To != nil {
		tsRange := bson.M{}
		if filter.From != nil {
			tsRange["$gte"] = *filter.From
		}
		if filter.To != nil {
			tsRange["$lte"] = *filter.To
		}
		query["timestamp"] = tsRange
	}
	return query
}
