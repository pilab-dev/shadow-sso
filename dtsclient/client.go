package dtsclient

import (
	"context"
	"log"
	"time"

	dtsv1 "github.com/pilab-dev/ssso/gen/proto/dts/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure" // Use secure credentials in production
	// "google.golang.org/grpc/resolver"
	// "google.golang.org/grpc/balancer/roundrobin"
)

// Client wraps the gRPC client for the TokenStoreService.
type Client struct {
	conn   *grpc.ClientConn
	DTS    dtsv1.TokenStoreServiceClient
	config Config
}

// Config holds configuration for the DTS client.
type Config struct {
	Address        string        // Address of the DTS gRPC service (e.g., "localhost:50051")
	ConnectTimeout time.Duration // Timeout for establishing a connection
	// Add more config options like TLS, retry policies etc. as needed
	MaxMsgSize     int
}

// NewClient creates a new DTS gRPC client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		log.Printf("DTS client address is empty, using default: localhost:50051")
		cfg.Address = "localhost:50051"
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.MaxMsgSize <=0 {
		cfg.MaxMsgSize = 16 * 1024 * 1024 // 16MB default, matching server
	}


	// For now, using insecure credentials. In a production environment, use TLS.
	// TODO: Add TLS support based on configuration.
	opts := []grpc.DialOption{
		grpc.withTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // Block until the connection is established or fails
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(cfg.MaxMsgSize),
			grpc.MaxCallSendMsgSize(cfg.MaxMsgSize),
		),
		// Example: Round-robin load balancing if multiple DTS instances are behind a VIP/headless service
		// grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`),
	}

	// If using a custom resolver for multiple DTS instances (e.g. DNS based)
	// resolver.SetDefaultScheme("dns") // Or your custom scheme


	log.Printf("Attempting to connect to DTS service at %s with timeout %v", cfg.Address, cfg.ConnectTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.Address, opts...)
	if err != nil {
		log.Printf("Failed to connect to DTS service at %s: %v", cfg.Address, err)
		return nil, err
	}

	log.Printf("Successfully connected to DTS service at %s", cfg.Address)
	dtsServiceClient := dtsv1.NewTokenStoreServiceClient(conn)

	return &Client{
		conn:   conn,
		DTS:    dtsServiceClient,
		config: cfg,
	}, nil
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		log.Printf("Closing connection to DTS service at %s", c.config.Address)
		return c.conn.Close()
	}
	return nil
}

// EnsureConnected tries to reconnect if the client is not connected.
// This is a basic example; more robust handling might be needed.
// func (c *Client) EnsureConnected() error {
// 	if c.conn == nil || c.conn.GetState() == connectivity.TransientFailure || c.conn.GetState() == connectivity.Shutdown {
// 		log.Printf("DTS client disconnected, attempting to reconnect to %s", c.config.Address)
// 		newClient, err := NewClient(c.config)
// 		if err != nil {
// 			return fmt.Errorf("failed to reconnect to DTS: %w", err)
// 		}
// 		*c = *newClient // Replace current client with the new one
// 		log.Printf("Successfully reconnected to DTS service at %s", c.config.Address)
// 	}
// 	return nil
// }
