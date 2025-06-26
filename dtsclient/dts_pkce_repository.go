package dtsclient

import (
	"context"
	"log"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	dtsv1 "github.com/pilab-dev/shadow-sso/gen/proto/dts/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// dtsPkceRepository implements domain.PkceRepository
type dtsPkceRepository struct {
	client           *Client
	defaultTTLExpiry time.Duration
}

// NewDTSPkceRepository creates a new DTS-backed PkceRepository.
// It requires a DTS client and a default TTL for PKCE states (e.g., 10 minutes).
func NewDTSPkceRepository(client *Client, defaultTTL time.Duration) domain.PkceRepository {
	if client == nil {
		log.Fatal("DTS client cannot be nil for NewDTSPkceRepository")
	}
	if defaultTTL <= 0 {
		defaultTTL = 10 * time.Minute // Default to 10 minutes if not specified or invalid
		log.Printf("Using default TTL for PKCE states: %v", defaultTTL)
	}
	return &dtsPkceRepository{client: client, defaultTTLExpiry: defaultTTL}
}

// SaveCodeChallenge stores the PKCE code challenge.
// The 'code' parameter is treated as the code_hash (key).
// CodeChallengeMethod is not provided by the interface, so it's stored as empty.
func (r *dtsPkceRepository) SaveCodeChallenge(ctx context.Context, codeHash, challenge string) error {
	if codeHash == "" || challenge == "" {
		return status.Error(codes.InvalidArgument, "code hash and challenge cannot be empty")
	}

	expiresAt := time.Now().Add(r.defaultTTLExpiry)
	protoState := &dtsv1.PKCEState{
		CodeHash:            codeHash,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "", // Not available from current PkceRepository interface
		ExpiresAt:           timestamppb.New(expiresAt),
	}

	req := connect.NewRequest(&dtsv1.StorePKCEStateRequest{
		PkceState: protoState,
	})

	_, err := r.client.DTS.StorePKCEState(ctx, req)
	if err != nil {
		log.Printf("Error storing PKCE state for code_hash %s to DTS: %v", codeHash, err)

		return status.Errorf(codes.Internal, "failed to store PKCE state: %v", err)
	}

	log.Printf("PKCE state for code_hash %s stored in DTS.", codeHash)

	return nil
}

// GetCodeChallenge retrieves the PKCE code challenge.
// Returns the challenge string and an error if any.
// Returns empty string, nil if not found (or specific error if preferred).
func (r *dtsPkceRepository) GetCodeChallenge(ctx context.Context, codeHash string) (string, error) {
	if codeHash == "" {
		return "", status.Error(codes.InvalidArgument, "code hash cannot be empty")
	}

	req := connect.NewRequest(&dtsv1.GetPKCEStateRequest{
		CodeHash: codeHash,
	})
	protoState, err := r.client.DTS.GetPKCEState(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("PKCE state for code_hash %s not found in DTS.", codeHash)

			return "", nil // Not found
		}
		log.Printf("Error getting PKCE state for code_hash %s from DTS: %v", codeHash, err)

		return "", status.Errorf(codes.Internal, "failed to get PKCE state: %v", err)
	}

	// Check for expiration, though DTS Get should ideally handle this
	if protoState.Msg.ExpiresAt != nil && protoState.Msg.ExpiresAt.AsTime().Before(time.Now()) {
		log.Printf("PKCE state for code_hash %s retrieved from DTS but is expired.", codeHash)
		// Optionally delete it proactively
		// r.DeleteCodeChallenge(ctx, codeHash)
		return "", nil // Treat as not found if expired
	}

	log.Printf("PKCE challenge for code_hash %s retrieved from DTS.", codeHash)

	return protoState.Msg.CodeChallenge, nil
}

// DeleteCodeChallenge removes the PKCE state from DTS.
func (r *dtsPkceRepository) DeleteCodeChallenge(ctx context.Context, codeHash string) error {
	if codeHash == "" {
		return status.Error(codes.InvalidArgument, "code hash cannot be empty")
	}

	req := connect.NewRequest(&dtsv1.DeletePKCEStateRequest{
		CodeHash: codeHash,
	})
	_, err := r.client.DTS.DeletePKCEState(ctx, req)
	if err != nil {
		// It's okay if it's already deleted (NotFound), effectively a successful deletion.
		// However, other errors should be reported.
		// The DTS DeletePKCEState RPC doesn't distinguish NotFound from other errors in its response (Empty).
		// We rely on the gRPC status code if the DTS service returns one.
		// If the DTS service's Delete operation itself doesn't return NotFound, then we can't tell here.
		// For simplicity, any error from DTS is passed through.
		log.Printf("Error deleting PKCE state for code_hash %s from DTS: %v", codeHash, err)

		return status.Errorf(codes.Internal, "failed to delete PKCE state: %v", err)
	}

	log.Printf("PKCE state for code_hash %s deleted from DTS.", codeHash)

	return nil
}
