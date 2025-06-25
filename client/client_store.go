package client

import "context"

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type ClientStore interface {
	CreateClient(ctx context.Context, client *Client) error
	GetClient(ctx context.Context, clientID string) (*Client, error)
	UpdateClient(ctx context.Context, client *Client) error
	DeleteClient(ctx context.Context, clientID string) error
	ListClients(ctx context.Context, filter ClientFilter) ([]*Client, error)
	ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error)
}
