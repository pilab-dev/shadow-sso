package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pilab-dev/shadow-sso/apps/ssso-dts/config"
	"github.com/pilab-dev/shadow-sso/apps/ssso-dts/internal/service"
	"github.com/pilab-dev/shadow-sso/apps/ssso-dts/internal/storage" // Assuming buf generate worked
	"github.com/pilab-dev/shadow-sso/gen/proto/dts/v1/dtsv1connect"

	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
)

func main() {
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

	// Register DTS service
	path, tokenServiceHandler := dtsv1connect.NewTokenStoreServiceHandler(dtsServer)
	log.Println("TokenStoreService registered.")

	mux := http.NewServeMux()
	mux.Handle(path, tokenServiceHandler)
	// Register gRPC reflection service (optional, useful for debugging with grpcurl)

	checker := grpchealth.NewStaticChecker(
		// protoc-gen-connect-go generates package-level constants
		// for these fully-qualified protobuf service names, so you'd more likely
		// reference userv1.UserServiceName and groupv1.GroupServiceName.
		dtsv1connect.TokenStoreServiceName,
	)

	reflector := grpcreflect.NewStaticReflector(
		dtsv1connect.TokenStoreServiceName,
		// protoc-gen-connect-go generates package-level constants
		// for these fully-qualified protobuf service names, so you'd more likely
		// reference userv1.UserServiceName and groupv1.GroupServiceName.
	)

	// Register gRPC health check service
	mux.Handle(grpchealth.NewHandler(checker))
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
	log.Println("gRPC health check service registered.")

	// Start gRPC server
	lis, err := net.Listen("tcp", cfg.GRPCServerAddress)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.GRPCServerAddress, err)
	}
	log.Printf("gRPC server listening on %s", cfg.GRPCServerAddress)

	go func() {
		if err := http.Serve(lis, mux); err != nil {
			log.Fatalf("Failed to serve mux: %v", err)
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

	go func() {
		<-shutdownCtx.Done()
		log.Println("gRPC server shutdown timed out. Forcing stop.")
		_ = lis.Close() // Force stop if GracefulStop times out
	}()

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
