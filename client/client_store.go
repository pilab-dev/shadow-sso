package client

import "context"

// ClientStore defines the interface for client storage and retrieval
type ClientStore interface {
	// CreateClient creates a new OAuth2 client
	CreateClient(ctx context.Context, client *Client) error

	// GetClient retrieves a client by ID
	GetClient(ctx context.Context, clientID string) (*Client, error)

	// UpdateClient updates an existing client
	UpdateClient(ctx context.Context, client *Client) error

	// DeleteClient deletes a client
	DeleteClient(ctx context.Context, clientID string) error

	// ListClients returns all clients, with optional filtering
	ListClients(ctx context.Context, filter ClientFilter) ([]*Client, error)

	// ValidateClient validates client credentials
	ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error)
}
