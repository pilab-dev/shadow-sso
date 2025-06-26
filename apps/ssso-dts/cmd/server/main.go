package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pilab-dev/ssso/apps/ssso-dts/config"
	"github.com/pilab-dev/ssso/apps/ssso-dts/internal/service"
	"github.com/pilab-dev/ssso/apps/ssso-dts/internal/storage"
	dtsv1 "github.com/pilab-dev/ssso/gen/proto/dts/v1" // Assuming buf generate worked

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	cfg := config.LoadConfig()
	log.Printf("Configuration loaded: %+v", cfg)

	// Initialize BBoltStore
	store, err := storage.NewBBoltStore(cfg.BBoltDBPath, cfg.DefaultTTL, cfg.CleanupInterval)
	if err != nil {
		log.Fatalf("Failed to initialize BBoltStore: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Printf("Error closing BBoltStore: %v", err)
		}
	}()

	// Start cleanup routine for BBoltStore
	// Pass the list of known buckets that will be used by the service.
	// The cleanup routine will also dynamically discover other buckets if they are created.
	store.StartCleanupRoutine(storage.KnownBuckets())


	// Create DTS service implementation
	dtsServer := service.NewDTSService(store)

	// Create gRPC server
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(cfg.MaxMsgSize),
		grpc.MaxSendMsgSize(cfg.MaxMsgSize),
	)

	// Register DTS service
	dtsv1.RegisterTokenStoreServiceServer(grpcServer, dtsServer)
	log.Println("TokenStoreService registered.")

	// Register gRPC reflection service (optional, useful for debugging with grpcurl)
	reflection.Register(grpcServer)
	log.Println("gRPC reflection service registered.")

	// Register gRPC health check service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus(dtsv1.TokenStoreService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING) // For overall server health
	log.Println("gRPC health check service registered.")


	// Start gRPC server
	lis, err := net.Listen("tcp", cfg.GRPCServerAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.GRPCServerAddress, err)
	}
	log.Printf("gRPC server listening on %s", cfg.GRPCServerAddress)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop // Wait for interrupt signal

	log.Println("Shutting down gRPC server...")
	// GracefulStop waits for pending RPCs to complete, then stops the server.
	// It's good practice to set a timeout for GracefulStop.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		log.Println("gRPC server gracefully stopped.")
	case <-shutdownCtx.Done():
		log.Println("gRPC server shutdown timed out. Forcing stop.")
		grpcServer.Stop() // Force stop if GracefulStop times out
	}

	log.Println("DTS Service shut down successfully.")
}

func init() {
	// Optional: Customize log output format
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("DTS Service starting...")
}

// Example of how to ensure all necessary buckets are created at startup by the service layer,
// if not handled by the storage layer's EnsureBucket on first use.
// This could be called after store initialization.
// func ensureServiceBuckets(store *storage.BBoltStore) error {
// 	buckets := []string{
// 		service.authCodesBucket,
// 		service.refreshTokensBucket,
// 		service.accessTokenMetadataBucket,
// 		service.oidcFlowsBucket,
// 		service.userSessionsBucket,
// 		service.deviceAuthGrantsBucket,
// 		service.deviceAuthUserCodeBucket,
// 		service.pkceStatesBucket,
// 	}
// 	for _, bucketName := range buckets {
// 		if err := store.EnsureBucket(bucketName); err != nil { // EnsureBucket needs to be public in storage
// 			return fmt.Errorf("failed to ensure service bucket %s: %w", bucketName, err)
// 		}
// 	}
// 	log.Println("All service-specific buckets ensured.")
// 	return nil
// }
