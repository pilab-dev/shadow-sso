package dtsclient

import (
	"context"
	"errors"
	"log"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	dtsv1 "github.com/pilab-dev/shadow-sso/gen/proto/dts/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// dtsSessionRepository implements domain.SessionRepository using a DTS client.
// Note: Some methods like GetSessionByTokenID, ListSessionsByUserID, DeleteSessionsByUserID
// are not directly supported by the current DTS proto and will be no-ops or return errors.
type dtsSessionRepository struct {
	client *Client
}

// NewDTSSessionRepository creates a new DTS-backed SessionRepository.
func NewDTSSessionRepository(client *Client) domain.SessionRepository {
	if client == nil {
		log.Fatal("DTS client cannot be nil for NewDTSSessionRepository")
	}
	return &dtsSessionRepository{client: client}
}

// --- Helper functions for conversion ---

func domainSessionToProtoUserSession(session *domain.Session) *dtsv1.UserSession {
	if session == nil {
		return nil
	}
	// domain.Session.TokenID is not stored in dtsv1.UserSession.
	// domain.Session.IsRevoked: if true, conceptually the session wouldn't be in DTS or would be deleted.
	// domain.Session.ACR and AMR are not directly in domain.Session but are in dtsv1.UserSession.
	// For now, we map available fields.
	return &dtsv1.UserSession{
		SessionId:       session.ID,
		UserId:          session.UserID,
		AuthenticatedAt: timestamppb.New(session.CreatedAt), // Mapping CreatedAt to AuthenticatedAt
		ExpiresAt:       timestamppb.New(session.ExpiresAt),
		UserAgent:       session.UserAgent,
		IpAddress:       session.IPAddress,
		// AcrLevel: session.ACR, // If domain.Session had these
		// AmrMethods: session.AMR, // If domain.Session had these
	}
}

func protoUserSessionToDomainSession(protoUS *dtsv1.UserSession) *domain.Session {
	if protoUS == nil {
		return nil
	}
	return &domain.Session{
		ID:        protoUS.SessionId,
		UserID:    protoUS.UserId,
		CreatedAt: protoUS.AuthenticatedAt.AsTime(), // Mapping AuthenticatedAt to CreatedAt
		ExpiresAt: protoUS.ExpiresAt.AsTime(),
		UserAgent: protoUS.UserAgent,
		IPAddress: protoUS.IpAddress,
		IsRevoked: false, // If retrieved from DTS, it's considered not revoked
		// UpdatedAt: // Not in dtsv1.UserSession, could use AuthenticatedAt or leave as zero
		// TokenID: // Not in dtsv1.UserSession
		// ACR/AMR could be mapped if domain.Session is extended
	}
}

// StoreSession stores a session in DTS.
func (r *dtsSessionRepository) StoreSession(ctx context.Context, session *domain.Session) error {
	if session == nil {
		return errors.New("session cannot be nil")
	}
	if session.ID == "" {
		return errors.New("session ID cannot be empty")
	}
	if session.ExpiresAt.IsZero() || session.ExpiresAt.Before(time.Now()) {
		return status.Error(codes.InvalidArgument, "session is already expired or has invalid expiration")
	}
	if session.IsRevoked { // Do not store revoked sessions
		log.Printf("Attempted to store an already revoked session ID '%s'. Skipping.", session.ID)
		return errors.New("cannot store an already revoked session")
	}

	protoUS := domainSessionToProtoUserSession(session)
	req := connect.NewRequest(&dtsv1.StoreUserSessionRequest{
		UserSession: protoUS,
	})

	_, err := r.client.DTS.StoreUserSession(ctx, req)
	if err != nil {
		log.Printf("Error storing session ID '%s' to DTS: %v", session.ID, err)
		return status.Errorf(codes.Internal, "failed to store session in DTS: %v", err)
	}
	log.Printf("Session ID '%s' stored in DTS.", session.ID)
	return nil
}

// GetSessionByID retrieves a session by its ID from DTS.
func (r *dtsSessionRepository) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	if id == "" {
		return nil, errors.New("session ID cannot be empty")
	}

	req := connect.NewRequest(&dtsv1.GetUserSessionRequest{
		SessionId: id,
	})

	protoUS, err := r.client.DTS.GetUserSession(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("Session ID '%s' not found in DTS.", id)
			return nil, nil // Not found
		}
		log.Printf("Error getting session ID '%s' from DTS: %v", id, err)
		return nil, status.Errorf(codes.Internal, "failed to get session from DTS: %v", err)
	}

	if protoUS.Msg.ExpiresAt.AsTime().Before(time.Now()) {
		log.Printf("Session ID '%s' retrieved from DTS but is expired.", id)
		return nil, nil // Treat as not found if expired
	}

	return protoUserSessionToDomainSession(protoUS.Msg), nil
}

// GetSessionByTokenID is not supported by DTS as UserSession doesn't store token_id.
func (r *dtsSessionRepository) GetSessionByTokenID(ctx context.Context, tokenID string) (*domain.Session, error) {
	log.Printf("GetSessionByTokenID is not supported by DTS-backed SessionRepository. TokenID: %s", tokenID)
	return nil, status.Error(codes.Unimplemented, "GetSessionByTokenID is not implemented for DTS session store")
}

// UpdateSession updates a session in DTS. If session.IsRevoked is true, it deletes the session.
// Otherwise, it re-stores (upserts) the session.
func (r *dtsSessionRepository) UpdateSession(ctx context.Context, session *domain.Session) error {
	if session == nil {
		return errors.New("session cannot be nil for update")
	}
	if session.ID == "" {
		return errors.New("session ID cannot be empty for update")
	}

	if session.IsRevoked {
		log.Printf("Session ID '%s' marked as revoked, deleting from DTS.", session.ID)
		return r.DeleteSession(ctx, session.ID)
	}

	// For non-revocation updates, effectively re-store it (upsert)
	// Ensure it's not expired before attempting to store
	if session.ExpiresAt.IsZero() || session.ExpiresAt.Before(time.Now()) {
		log.Printf("Attempted to update session ID '%s' with an expired time. Deleting instead.", session.ID)
		return r.DeleteSession(ctx, session.ID) // Or return error: cannot update with expired time
	}

	log.Printf("Updating session ID '%s' in DTS (re-storing).", session.ID)
	return r.StoreSession(ctx, session) // StoreSession handles nil, empty ID, and expiration checks
}

// DeleteSession deletes a session from DTS.
func (r *dtsSessionRepository) DeleteSession(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("session ID cannot be empty for deletion")
	}

	req := connect.NewRequest(&dtsv1.DeleteUserSessionRequest{
		SessionId: id,
	})

	_, err := r.client.DTS.DeleteUserSession(ctx, req)
	if err != nil {
		// DTS DeleteUserSession returns Empty, so no specific NotFound status.
		log.Printf("Error deleting session ID '%s' from DTS: %v", id, err)
		return status.Errorf(codes.Internal, "failed to delete session from DTS: %v", err)
	}

	log.Printf("Session ID '%s' deleted from DTS.", id)

	return nil
}

// ListSessionsByUserID is not supported by DTS.
func (r *dtsSessionRepository) ListSessionsByUserID(ctx context.Context, userID string, filter domain.SessionFilter) ([]*domain.Session, error) {
	log.Printf("ListSessionsByUserID is not supported by DTS-backed SessionRepository. UserID: %s", userID)

	return nil, status.Error(codes.Unimplemented, "ListSessionsByUserID is not implemented for DTS session store")
}

// DeleteSessionsByUserID is not supported by DTS.
func (r *dtsSessionRepository) DeleteSessionsByUserID(ctx context.Context, userID string, exceptSessionID ...string) (int64, error) {
	log.Printf("DeleteSessionsByUserID is not supported by DTS-backed SessionRepository. UserID: %s", userID)
	return 0, status.Error(codes.Unimplemented, "DeleteSessionsByUserID is not implemented for DTS session store")
}

// Ensure dtsSessionRepository implements domain.SessionRepository
var _ domain.SessionRepository = (*dtsSessionRepository)(nil)
