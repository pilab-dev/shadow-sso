package services

import (
	"context"

	"github.com/pilab-dev/shadow-sso/dto"
	// ssso "github.com/pilab-dev/shadow-sso" // For ssso.TokenInfo if needed by any original interface
)

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hashedPassword, password string) bool
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type IdPServiceInternal interface {
	AddIdP(ctx context.Context, req *dto.IdentityProviderCreateRequest) (*dto.IdentityProviderResponse, error)
	GetIdPByID(ctx context.Context, idpID string) (*dto.IdentityProviderResponse, error)
	GetIdPByName(ctx context.Context, name string) (*dto.IdentityProviderResponse, error)
	ListIdPs(ctx context.Context, onlyEnabled bool) ([]*dto.IdentityProviderResponse, error)
	UpdateIdP(ctx context.Context, idpID string, req *dto.IdentityProviderUpdateRequest) (*dto.IdentityProviderResponse, error)
	DeleteIdP(ctx context.Context, idpID string) error
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type UserServiceInternal interface {
	CreateUser(ctx context.Context, req *dto.UserCreateRequest) (*dto.UserResponse, error)
	GetUserByID(ctx context.Context, userID string) (*dto.UserResponse, error)
	GetUserByEmail(ctx context.Context, email string) (*dto.UserResponse, error)
	ListUsers(ctx context.Context /* TODO: Add pagination/filter DTOs */) ([]*dto.UserResponse, error)
	UpdateUser(ctx context.Context, userID string, req *dto.UserUpdateRequest) (*dto.UserResponse, error)
	ActivateUser(ctx context.Context, userID string) error
	LockUser(ctx context.Context, userID string) error
	ChangePassword(ctx context.Context, userID string, oldPassword string, newPassword string) error
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type ClientServiceInternal interface {
	RegisterClient(ctx context.Context, req *dto.ClientCreateRequest) (*dto.ClientResponse, string, error)
	GetClientByID(ctx context.Context, clientID string) (*dto.ClientResponse, error)
	ListClients(ctx context.Context, pageSize int32, pageToken string) ([]*dto.ClientResponse, string, error)
	UpdateClient(ctx context.Context, clientID string, req *dto.ClientUpdateRequest) (*dto.ClientResponse, error)
	DeleteClient(ctx context.Context, clientID string) error
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type TokenServiceInternal interface {
	GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*dto.TokenInfoResponse, error)
	GetAccessTokenInfo(ctx context.Context, tokenValue string) (*dto.TokenInfoResponse, error)
}
