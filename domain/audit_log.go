package domain

//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_audit_log_repository.go -package=mock_domain AuditLogRepository

import (
	"context"
	"time"
)

// AuditLog is a persisted audit event. It mirrors the fields logged to stdout
// by internal/audit (Event) plus a stable identifier for querying. It must
// never carry token contents or passwords — only metadata about an action.
type AuditLog struct {
	ID        string    `bson:"_id,omitempty" json:"id"`
	Timestamp time.Time `bson:"timestamp" json:"timestamp"`
	Service   string    `bson:"service" json:"service"`
	Action    string    `bson:"action" json:"action"`
	User      string    `bson:"user,omitempty" json:"user,omitempty"`     // User ID or username
	Target    string    `bson:"target,omitempty" json:"target,omitempty"` // Target resource ID or name
	Details   string    `bson:"details,omitempty" json:"details,omitempty"`
	Success   bool      `bson:"success" json:"success"`
	Error     string    `bson:"error,omitempty" json:"error,omitempty"` // Error message if the action failed
}

// AuditLogFilter restricts audit event listing to a user, an action and/or a
// time window. Zero-valued fields are ignored.
type AuditLogFilter struct {
	User    string
	Action  string
	From    *time.Time
	To      *time.Time
	SortBy  string
	SortDir string
}

// AuditLogRepository defines persistence for audit events. The interface is
// deliberately narrow: writes are fire-and-forget (the async sink must never
// block the auth path), reads are the admin-facing query surface.
type AuditLogRepository interface {
	Insert(ctx context.Context, event *AuditLog) error
	List(ctx context.Context, filter AuditLogFilter, limit, offset int) ([]*AuditLog, error)
	Count(ctx context.Context, filter AuditLogFilter) (int64, error)
}
