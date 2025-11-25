package dtsclient

import (
	"context"
	"log"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain" // Corrected: Using domain.UserSession
	dtsv1 "github.com/pilab-dev/shadow-sso/gen/proto/dts/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DTSUserSessionStore provides an OIDC user session store backed by the DTS.
// It mimics the methods of domain.UserSessionStore.
type DTSUserSessionStore struct {
	client *Client
}

// NewDTSUserSessionStore creates a new DTSUserSessionStore.
func NewDTSUserSessionStore(client *Client) *DTSUserSessionStore {
	if client == nil {
		log.Fatal("DTS client cannot be nil for NewDTSUserSessionStore")
	}
	return &DTSUserSessionStore{client: client}
}

func toProtoUserSession(session *domain.UserSession) *dtsv1.UserSession { // Changed to domain.UserSession
	if session == nil {
		return nil
	}
	return &dtsv1.UserSession{
		SessionId:       session.SessionID,
		UserId:          session.UserID,
		AuthenticatedAt: timestamppb.New(session.AuthenticatedAt),
		ExpiresAt:       timestamppb.New(session.ExpiresAt),
		UserAgent:       session.UserAgent,
		IpAddress:       session.IPAddress,
		// acr_level, amr_methods are not in domain.UserSession
	}
}

func fromProtoUserSession(protoSession *dtsv1.UserSession) *domain.UserSession { // Changed to domain.UserSession
	if protoSession == nil {
		return nil
	}
	return &domain.UserSession{ // Changed to domain.UserSession
		SessionID:       protoSession.SessionId,
		UserID:          protoSession.UserId,
		AuthenticatedAt: protoSession.AuthenticatedAt.AsTime(),
		ExpiresAt:       protoSession.ExpiresAt.AsTime(),
		UserAgent:       protoSession.UserAgent,
		IPAddress:       protoSession.IpAddress,
	}
}

// StoreUserSession adds a new user session to DTS.
// Unlike InMemoryUserSessionStore, it expects SessionID to be set by the caller.
// If SessionID generation is needed here, uuid.NewString() could be used if session.SessionID is empty.
func (s *DTSUserSessionStore) StoreUserSession(ctx context.Context, session *domain.UserSession) error { // Changed to domain.UserSession
	if session == nil || session.SessionID == "" {
		// InMemoryUserSessionStore generates ID if empty. This one requires it.
		// If ID generation is desired here:
		// if session.SessionID == "" { session.SessionID = uuid.NewString() }
		return status.Error(codes.InvalidArgument, "session or session ID cannot be empty")
	}

	protoSession := toProtoUserSession(session)
	if protoSession.ExpiresAt.AsTime().Before(time.Now()) || protoSession.ExpiresAt.AsTime().IsZero() {
		return domain.ErrSessionExpired // Changed to domain.ErrSessionExpired
	}
	// Note: InMemoryUserSessionStore checks for domain.ErrSessionIDConflict.
	// DTS StoreUserSession is an upsert, so it won't return conflict on existing ID, it will overwrite.
	// If conflict detection is critical, a Get call would be needed first, making the operation non-atomic.

	req := connect.NewRequest(&dtsv1.StoreUserSessionRequest{
		UserSession: protoSession,
	})

	_, err := s.client.DTS.StoreUserSession(ctx, req)
	if err != nil {
		log.Printf("Error storing user session %s to DTS: %v", session.SessionID, err)

		return status.Errorf(codes.Internal, "failed to store user session: %v", err)
	}
	log.Printf("User session %s stored in DTS.", session.SessionID)

	return nil
}

// GetUserSession retrieves a user session by its ID from DTS.
func (s *DTSUserSessionStore) GetUserSession(ctx context.Context, sessionID string) (*domain.UserSession, error) { // Changed to domain.UserSession
	if sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "session ID cannot be empty")
	}

	req := connect.NewRequest(&dtsv1.GetUserSessionRequest{SessionId: sessionID})
	protoSession, err := s.client.DTS.GetUserSession(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("User session %s not found in DTS.", sessionID)

			return nil, domain.ErrSessionNotFound // Changed to domain.ErrSessionNotFound
		}
		log.Printf("Error getting user session %s from DTS: %v", sessionID, err)

		return nil, status.Errorf(codes.Internal, "failed to get user session: %v", err)
	}

	session := fromProtoUserSession(protoSession.Msg)
	if session.ExpiresAt.Before(time.Now()) {
		log.Printf("User session %s retrieved from DTS but is expired.", sessionID)
		return session, domain.ErrSessionExpired // Changed to domain.ErrSessionExpired
	}
	return session, nil
}

// DeleteUserSession removes a user session from DTS.
func (s *DTSUserSessionStore) DeleteUserSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return status.Error(codes.InvalidArgument, "session ID cannot be empty")
	}

	req := connect.NewRequest(&dtsv1.DeleteUserSessionRequest{
		SessionId: sessionID,
	})

	_, err := s.client.DTS.DeleteUserSession(ctx, req)
	if err != nil {
		log.Printf("Error deleting user session %s from DTS: %v", sessionID, err)

		return status.Errorf(codes.Internal, "failed to delete user session: %v", err)
	}
	log.Printf("User session %s deleted from DTS.", sessionID)

	return nil
}

// CleanupExpiredSessions is a no-op for DTSUserSessionStore as DTS handles TTL internally.
func (s *DTSUserSessionStore) CleanupExpiredSessions() {
	log.Println("CleanupExpiredSessions is a no-op for DTSUserSessionStore; DTS handles TTL cleanup automatically.")
}
