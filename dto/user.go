package dto

import (
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
)

// UserCreateRequest defines the payload for creating a new user.
type UserCreateRequest struct {
	Email     string   `json:"email"`
	Password  string   `json:"password"` // Raw password, to be hashed by the service
	FirstName string   `json:"first_name,omitempty"`
	LastName  string   `json:"last_name,omitempty"`
	Roles     []string `json:"roles,omitempty"`
}

// UserUpdateRequest defines the payload for updating an existing user.
// All fields are optional.
type UserUpdateRequest struct {
	Email     *string   `json:"email,omitempty"`
	Password  *string   `json:"password,omitempty"` // Raw password, to be hashed by the service
	FirstName *string   `json:"first_name,omitempty"`
	LastName  *string   `json:"last_name,omitempty"`
	Status    *string   `json:"status,omitempty"` // e.g., "ACTIVE", "LOCKED"
	Roles     *[]string `json:"roles,omitempty"`
	// 2FA fields are typically handled by dedicated endpoints
}

// UserResponse defines the structure for API responses containing user information.
// Sensitive fields like PasswordHash, TwoFactorSecret, etc., are omitted.
type UserResponse struct {
	ID                 string            `json:"id"`
	Email              string            `json:"email"`
	Status             domain.UserStatus `json:"status"`
	FirstName          string            `json:"first_name,omitempty"`
	LastName           string            `json:"last_name,omitempty"`
	Roles              []string          `json:"roles,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
	LastLoginAt        *time.Time        `json:"last_login_at,omitempty"`
	IsTwoFactorEnabled bool              `json:"is_two_factor_enabled,omitempty"`
	TwoFactorMethod    string            `json:"two_factor_method,omitempty"`
	Password           []byte            `json:"password"`
}

// ToDomainUser converts UserCreateRequest to domain.User.
// Password is kept raw; service layer is responsible for hashing.
// ID, CreatedAt, UpdatedAt, etc. are set by the service/repository.
func ToDomainUser(dto UserCreateRequest) *domain.User {
	return &domain.User{
		Email: dto.Email,
		// PasswordHash will be set by the service after hashing dto.Password
		FirstName: dto.FirstName,
		LastName:  dto.LastName,
		Roles:     dto.Roles,
		// Status typically defaults to PENDING_ACTIVATION or ACTIVE in the service layer
	}
}

// ToDomainUserUpdate prepares a domain.User object for updates.
// This is a simplified version. In a real scenario, you'd fetch the existing User
// and apply updates to it. The service layer will need to handle merging.
// Password hashing is also a service layer responsibility.
func ToDomainUserUpdate(userID string, dto UserUpdateRequest) *domain.User {
	user := &domain.User{
		ID: userID, // ID must be set for update operations
	}
	if dto.Email != nil {
		user.Email = *dto.Email
	}
	// Password should be handled by the service (hashing if dto.Password is not nil)
	if dto.FirstName != nil {
		user.FirstName = *dto.FirstName
	}
	if dto.LastName != nil {
		user.LastName = *dto.LastName
	}
	if dto.Status != nil {
		user.Status = domain.UserStatus(*dto.Status)
	}
	if dto.Roles != nil {
		user.Roles = *dto.Roles
	}
	return user
}

// FromDomainUser converts domain.User to UserResponse.
func FromDomainUser(user *domain.User) *UserResponse {
	if user == nil {
		return nil
	}
	return &UserResponse{
		ID:                 user.ID,
		Email:              user.Email,
		Status:             user.Status,
		FirstName:          user.FirstName,
		LastName:           user.LastName,
		Roles:              user.Roles,
		CreatedAt:          user.CreatedAt,
		UpdatedAt:          user.UpdatedAt,
		LastLoginAt:        user.LastLoginAt,
		IsTwoFactorEnabled: user.IsTwoFactorEnabled,
		TwoFactorMethod:    user.TwoFactorMethod,
	}
}

// FromDomainUsers converts a slice of domain.User to a slice of UserResponse.
func FromDomainUsers(users []*domain.User) []*UserResponse {
	if users == nil {
		return nil
	}
	responses := make([]*UserResponse, len(users))
	for i, user := range users {
		responses[i] = FromDomainUser(user)
	}
	return responses
}
