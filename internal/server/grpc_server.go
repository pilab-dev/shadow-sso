package server

import (
	"github.com/pilab-dev/shadow-sso/config"
	"github.com/pilab-dev/shadow-sso/log"
	// Import necessary gRPC service definitions (e.g., ssov1connect)
	// and service implementations (e.g., from services package)
	// ssov1connect "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	// "github.com/pilab-dev/shadow-sso/services"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel" // To get the global TracerProvider
	"google.golang.org/grpc"
)

// NewGRPCServer creates and configures a new gRPC server.
// Dependencies for the actual service handlers (e.g., IdPService, UserService, ClientService)
// need to be passed in or created here.
func NewGRPCServer(
	cfg *config.ServerConfig,
	appLogger log.Logger,
	// Placeholder for actual service implementations:
	// idpService services.IdPServiceInternal,
	// userService services.UserServiceInternal,
	// clientService services.ClientServiceInternal,
	// authService ssov1connect.AuthServiceHandler, // Or the internal service if RPC handlers use internal services
	// twoFactorService ssov1connect.TwoFactorServiceHandler,
	// serviceAccountService ssov1connect.ServiceAccountServiceHandler,
) *grpc.Server {
	appLogger.Info(context.Background(), "Initializing gRPC server with OpenTelemetry interceptors...")

	// Create gRPC server with OpenTelemetry interceptors.
	// The TracerProvider should be the global one configured by InitTracerProvider.
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			otelgrpc.UnaryServerInterceptor(otelgrpc.WithTracerProvider(otel.GetTracerProvider())),
			// Add other unary interceptors here, e.g., for logging, auth, recovery
			// Example: loggingUnaryInterceptor(appLogger),
		),
		grpc.ChainStreamInterceptor(
			otelgrpc.StreamServerInterceptor(otelgrpc.WithTracerProvider(otel.GetTracerProvider())),
			// Add other stream interceptors here
		),
	)

	// Register gRPC services.
	// These would be the server instances from the services package that implement the
	// gRPC service interfaces (e.g., services.IdPManagementServer, services.UserServer).
	// The NewXxxServer constructors in the services package take the *ServiceImpl DTO-based services.
	// Example (actual service instances need to be passed into NewGRPCServer or created here):
	// if idpService != nil { // Assuming idpService is the IdPManagementServer RPC handler
	//    ssov1connect.RegisterIdPManagementServiceServer(grpcServer, idpService)
	//    appLogger.Info(context.Background(), "Registered IdPManagementService")
	// }
	// if userService != nil { // Assuming userService is the UserServer RPC handler
	//    ssov1connect.RegisterUserServiceServer(grpcServer, userService)
	//    appLogger.Info(context.Background(), "Registered UserService")
	// }
	// if clientService != nil { // Assuming clientService is the ClientManagementServer RPC handler
	//    ssov1connect.RegisterClientManagementServiceServer(grpcServer, clientService)
	//    appLogger.Info(context.Background(), "Registered ClientManagementService")
	// }
	// if authService != nil {
	// 	ssov1connect.RegisterAuthServiceServer(grpcServer, authService)
	// 	appLogger.Info(context.Background(), "Registered AuthService")
	// }
	// if twoFactorService != nil {
	// 	ssov1connect.RegisterTwoFactorServiceServer(grpcServer, twoFactorService)
	// 	appLogger.Info(context.Background(), "Registered TwoFactorService")
	// }
	// if serviceAccountService != nil {
	// 	ssov1connect.RegisterServiceAccountServiceServer(grpcServer, serviceAccountService)
	// 	appLogger.Info(context.Background(), "Registered ServiceAccountService")
	// }


	appLogger.Info(context.Background(), "gRPC services (placeholders) registered.")
	// A simple health check service can also be registered here.
	// grpc_health_v1.RegisterHealthServer(grpcServer, health.NewServer())
	// appLogger.Info(context.Background(), "Registered gRPC HealthCheckService.")

	return grpcServer
}

// Example logging interceptor (unary)
// func loggingUnaryInterceptor(logger log.Logger) grpc.UnaryServerInterceptor {
// 	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
// 		start := time.Now()
// 		resp, err := handler(ctx, req)
// 		latency := time.Since(start)
// 		fields := map[string]interface{}{
// 			"method":  info.FullMethod,
// 			"latency": latency.String(),
// 		}
// 		if err != nil {
// 			logger.Error(ctx, "gRPC Request", err, fields)
// 		} else {
// 			logger.Info(ctx, "gRPC Request", fields)
// 		}
// 		return resp, err
// 	}
// }

// Note: The actual service handler instances (e.g., IdPManagementServer, UserServer from the services package)
// need to be created and passed into NewGRPCServer. This requires their own dependencies (the *ServiceImpl DTO-based services)
// to be available. The main.go will be responsible for this wiring.
// The commented-out service registration lines are placeholders until these dependencies are fully plumbed through.
// For this subtask, the focus is on setting up the gRPC server with OTel interceptors.
// The ConnectRPC services are already set up in connectrpc_server.go; this grpc_server.go is for plain gRPC if needed,
// or if ConnectRPC services were to be registered on a grpc.Server instance directly (Connect can do that).
// However, connectrpc_server.go uses its own http.ServeMux.
// If the intent is to use *this* grpc.Server for the ConnectRPC services, then the registration logic
// from connectrpc_server.go (mux.Handle(path, handler)) would need to be adapted to grpcServer.RegisterService.

// Given that `internal/server/connectrpc_server.go` already exists and sets up an HTTP server for Connect services,
// this `grpc_server.go` might be for a *separate* plain gRPC server, or it might be intended to *replace*
// parts of `connectrpc_server.go` if the goal is to use `grpc.NewServer` as the base for Connect.
// For now, I will assume this is for a standard gRPC server setup that might co-exist or where
// Connect services could be registered. The current Connect setup uses its own mux.
// The placeholders for service registration will reflect standard gRPC service registration.
// If ConnectRPC services are meant to be registered here, the method is different:
//
// import (
//    "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
//    "github.com/pilab-dev/shadow-sso/services" // for the server implementations
// )
//
// func NewGRPCServer(...) (*grpc.Server, ...) {
//    ...
//    saPath, saHandler := ssov1connect.NewServiceAccountServiceHandler(saServerImpl, interceptors)
//    // This handler is http.Handler, not directly registerable with grpc.Server.
//    // To use grpc.Server as the base for Connect, you'd typically use connectrpc.com/grpchealth
//    // and connectrpc.com/grpcreflect and then the handlers are used with an HTTP server
//    // that routes to this grpc.Server, or Connect's own server.
//
//    // The current setup in connectrpc_server.go is more typical for Connect: it creates an http.ServeMux
//    // and uses h2c for HTTP/2 cleartext.
//
//    // If the goal is to have a pure gRPC server (not Connect style which is HTTP based),
//    // then the services need to be generated with gRPC stubs, not just Connect stubs.
//    // Assuming the current .proto files generate standard gRPC service descriptors as well.
//    // Example with standard gRPC registration:
//    // ssov1.RegisterUserServiceServer(grpcServer, userServiceImpl) // userServiceImpl must be a UserServiceServer
// }
// The current service implementations (e.g., services.UserServer) are Connect handlers, not raw gRPC service implementations.
// This grpc_server.go might be more of a conceptual setup for a *different* type of gRPC exposure.
// For the purpose of this subtask (OTel interceptors), the structure is fine.
// The actual service registration will depend on whether these are Connect handlers or standard gRPC service impls.
// I will use placeholder comments for service registration.
// The OTel interceptors are correctly added for a standard grpc.Server.
import "context" // For context.Background in logger calls inside NewGRPCServer
// import "time" // For example logging interceptor
// import "google.golang.org/grpc/health" // For health checks
// import "google.golang.org/grpc/health/grpc_health_v1"
// import "google.golang.org/grpc/reflection" // For server reflection
