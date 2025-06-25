package domain

import "time"

// DeviceCodeStatus represents the status of a device authorization request.
type DeviceCodeStatus string

const (
	DeviceCodeStatusPending    DeviceCodeStatus = "pending"
	DeviceCodeStatusAuthorized DeviceCodeStatus = "authorized"
	DeviceCodeStatusDenied     DeviceCodeStatus = "denied"
	DeviceCodeStatusExpired    DeviceCodeStatus = "expired"
	DeviceCodeStatusRedeemed   DeviceCodeStatus = "redeemed"
)

// DeviceCode holds the information for a device authorization grant.
type DeviceCode struct {
	ID           string           `bson:"_id" json:"id"`
	DeviceCode   string           `bson:"device_code" json:"device_code"`
	UserCode     string           `bson:"user_code" json:"user_code"`
	ClientID     string           `bson:"client_id" json:"client_id"`
	Scope        string           `bson:"scope" json:"scope"`
	Status       DeviceCodeStatus `bson:"status" json:"status"`
	UserID       string           `bson:"user_id,omitempty" json:"user_id,omitempty"`
	ExpiresAt    time.Time        `bson:"expires_at" json:"expires_at"`
	Interval     int              `bson:"interval" json:"interval"`
	CreatedAt    time.Time        `bson:"created_at" json:"created_at"`
	LastPolledAt time.Time        `bson:"last_polled_at,omitempty" json:"last_polled_at,omitempty"`
}
