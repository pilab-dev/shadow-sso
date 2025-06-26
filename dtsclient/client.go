package dtsclient

import (
	"log"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/gen/proto/dts/v1/dtsv1connect"
	// Use secure credentials in production
	// "google.golang.org/grpc/resolver"
	// "google.golang.org/grpc/balancer/roundrobin"
)

// Client wraps the gRPC client for the TokenStoreService.
type Client struct {
	DTS    dtsv1connect.TokenStoreServiceClient
	config Config
}

// Config holds configuration for the DTS client.
type Config struct {
	Address        string        // Address of the DTS gRPC service (e.g., "localhost:50051")
	ConnectTimeout time.Duration // Timeout for establishing a connection
	// Add more config options like TLS, retry policies etc. as needed
	MaxMsgSize int
}

// NewClient creates a new DTS gRPC client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		log.Printf("DTS client address is empty, using default: http://localhost:50051")
		cfg.Address = "http://localhost:50051"
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.MaxMsgSize <= 0 {
		cfg.MaxMsgSize = 16 * 1024 * 1024 // 16MB default, matching server
	}

	client := dtsv1connect.NewTokenStoreServiceClient(
		http.DefaultClient,
		cfg.Address,
		connect.WithGRPC(),
	)

	return &Client{
		DTS:    client,
		config: cfg,
	}, nil
}
