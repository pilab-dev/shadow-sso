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
