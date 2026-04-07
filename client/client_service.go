package client

import (
	"context"

	"github.com/pilab-dev/shadow-sso/domain"
)

//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_client_service.go -package=mock_client ClientServiceInterface

type ClientServiceInterface interface {
	CreateConfidentialClient(ctx context.Context, name string, redirectURIs []string, allowedScopes []string) (*domain.Client, error)
	CreatePublicClient(ctx context.Context, name string, redirectURIs []string, allowedScopes []string) (*domain.Client, error)
	CreateClient(ctx context.Context, client *domain.Client) (*domain.Client, error)
	ValidateRedirectURI(ctx context.Context, clientID, redirectURI string) error
	ValidateScope(ctx context.Context, clientID string, requestedScopes []string) error
	ValidateGrantType(ctx context.Context, clientID, grantType string) error
	RequiresPKCE(ctx context.Context, clientID string) (bool, error)
	GetClient(ctx context.Context, clientID string) (*domain.Client, error)
	ValidateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error)
}
