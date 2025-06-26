package dtsclient

import (
	"context"
	"log"
	"time"

	"github.com/pilab-dev/ssso/internal/oidcflow" // For oidcflow.LoginFlowState and errors
	dtsv1 "github.com/pilab-dev/ssso/gen/proto/dts/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DTSFlowStore provides an OIDC flow store backed by the DTS.
// It mimics the methods of oidcflow.InMemoryFlowStore.
type DTSFlowStore struct {
	client *Client
	// ctx is included if all operations need a default context,
	// otherwise context should be passed into each method.
	// For repository/store patterns, passing context per method is common.
}

// NewDTSFlowStore creates a new DTSFlowStore.
func NewDTSFlowStore(client *Client) *DTSFlowStore {
	if client == nil {
		log.Fatal("DTS client cannot be nil for NewDTSFlowStore")
	}
	return &DTSFlowStore{client: client}
}

func toProtoOIDCFlw(state *oidcflow.LoginFlowState) *dtsv1.OIDCFlw {
	if state == nil {
		return nil
	}
	var userAuthAt *timestamppb.Timestamp
	if !state.UserAuthenticatedAt.IsZero() {
		userAuthAt = timestamppb.New(state.UserAuthenticatedAt)
	}

	return &dtsv1.OIDCFlw{
		FlowId:              state.FlowID,
		ClientId:            state.ClientID,
		RedirectUri:         state.RedirectURI,
		Scope:               state.Scope,
		State:               state.State,
		Nonce:               state.Nonce,
		CodeChallenge:       state.CodeChallenge,
		CodeChallengeMethod: state.CodeChallengeMethod,
		UserId:              state.UserID,
		UserAuthenticatedAt: userAuthAt,
		ExpiresAt:           timestamppb.New(state.ExpiresAt),
		OriginalOidcParams:  state.OriginalOIDCParams,
		// acr_level, amr_methods, session_id are not in oidcflow.LoginFlowState
		// They will be default/empty when converting from it.
	}
}

func fromProtoOIDCFlw(protoFlw *dtsv1.OIDCFlw) *oidcflow.LoginFlowState {
	if protoFlw == nil {
		return nil
	}
	var userAuthAt time.Time
	if protoFlw.UserAuthenticatedAt != nil && protoFlw.UserAuthenticatedAt.IsValid() {
		userAuthAt = protoFlw.UserAuthenticatedAt.AsTime()
	}
	return &oidcflow.LoginFlowState{
		FlowID:              protoFlw.FlowId,
		ClientID:            protoFlw.ClientId,
		RedirectURI:         protoFlw.RedirectUri,
		Scope:               protoFlw.Scope,
		State:               protoFlw.State,
		Nonce:               protoFlw.Nonce,
		CodeChallenge:       protoFlw.CodeChallenge,
		CodeChallengeMethod: protoFlw.CodeChallengeMethod,
		UserID:              protoFlw.UserId,
		UserAuthenticatedAt: userAuthAt,
		ExpiresAt:           protoFlw.ExpiresAt.AsTime(),
		OriginalOIDCParams:  protoFlw.OriginalOidcParams,
	}
}

// StoreFlow adds a new login flow state to DTS.
func (s *DTSFlowStore) StoreFlow(ctx context.Context, flowID string, state oidcflow.LoginFlowState) error {
	if flowID == "" || state.FlowID != flowID { // Ensure consistency if flowID is passed separately
		log.Printf("Warning: flowID parameter ('%s') and state.FlowID ('%s') mismatch or empty. Using state.FlowID.", flowID, state.FlowID)
		if state.FlowID == "" {
			return status.Error(codes.InvalidArgument, "flow ID in state cannot be empty")
		}
	}

	protoFlw := toProtoOIDCFlw(&state)
	if protoFlw.ExpiresAt.AsTime().Before(time.Now()) || protoFlw.ExpiresAt.AsTime().IsZero() {
		return oidcflow.ErrFlowExpired // Or codes.InvalidArgument
	}

	req := &dtsv1.StoreOIDCFlwRequest{OidcFlow: protoFlw}
	_, err := s.client.DTS.StoreOIDCFlw(ctx, req)
	if err != nil {
		log.Printf("Error storing OIDC flow %s to DTS: %v", state.FlowID, err)
		return status.Errorf(codes.Internal, "failed to store OIDC flow: %v", err)
	}
	log.Printf("OIDC flow %s stored in DTS.", state.FlowID)
	return nil
}

// GetFlow retrieves a login flow state by its ID from DTS.
func (s *DTSFlowStore) GetFlow(ctx context.Context, flowID string) (*oidcflow.LoginFlowState, error) {
	if flowID == "" {
		return nil, status.Error(codes.InvalidArgument, "flow ID cannot be empty")
	}
	req := &dtsv1.GetOIDCFlwRequest{FlowId: flowID}
	protoFlw, err := s.client.DTS.GetOIDCFlw(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("OIDC flow %s not found in DTS.", flowID)
			return nil, oidcflow.ErrFlowNotFound
		}
		log.Printf("Error getting OIDC flow %s from DTS: %v", flowID, err)
		return nil, status.Errorf(codes.Internal, "failed to get OIDC flow: %v", err)
	}

	state := fromProtoOIDCFlw(protoFlw)
	if state.ExpiresAt.Before(time.Now()) {
		log.Printf("OIDC flow %s retrieved from DTS but is expired.", flowID)
		return state, oidcflow.ErrFlowExpired // Return state along with expired error as per InMemoryFlowStore
	}
	return state, nil
}

// UpdateFlow updates an existing login flow state in DTS.
func (s *DTSFlowStore) UpdateFlow(ctx context.Context, flowID string, state *oidcflow.LoginFlowState) error {
	if flowID == "" || state == nil || state.FlowID != flowID {
		return status.Error(codes.InvalidArgument, "flow ID mismatch or state is nil")
	}

	protoFlw := toProtoOIDCFlw(state)
	// Expiration check might be relevant here too, depending on desired behavior for updating expired flows
	// if protoFlw.ExpiresAt.AsTime().Before(time.Now()) {
	// 	return oidcflow.ErrFlowExpired
	// }

	req := &dtsv1.UpdateOIDCFlwRequest{OidcFlow: protoFlw}
	_, err := s.client.DTS.UpdateOIDCFlw(ctx, req)
	if err != nil {
		// DTS UpdateOIDCFlw might return NotFound if the flow doesn't exist and it's not an upsert.
		// The current DTS service implementation of Update is an upsert (uses storeProtoMessage).
		// If it were a strict update, we'd map status.Code(err) == codes.NotFound to oidcflow.ErrFlowNotFound
		log.Printf("Error updating OIDC flow %s in DTS: %v", flowID, err)
		return status.Errorf(codes.Internal, "failed to update OIDC flow: %v", err)
	}
	log.Printf("OIDC flow %s updated in DTS.", flowID)
	return nil
}

// DeleteFlow removes a login flow state from DTS.
func (s *DTSFlowStore) DeleteFlow(ctx context.Context, flowID string) error {
	if flowID == "" {
		return status.Error(codes.InvalidArgument, "flow ID cannot be empty")
	}
	req := &dtsv1.DeleteOIDCFlwRequest{FlowId: flowID}
	_, err := s.client.DTS.DeleteOIDCFlw(ctx, req)
	if err != nil {
		log.Printf("Error deleting OIDC flow %s from DTS: %v", flowID, err)
		return status.Errorf(codes.Internal, "failed to delete OIDC flow: %v", err)
	}
	log.Printf("OIDC flow %s deleted from DTS.", flowID)
	return nil
}

// CleanupExpiredFlows is a no-op for DTSFlowStore as DTS handles TTL internally.
func (s *DTSFlowStore) CleanupExpiredFlows() {
	log.Println("CleanupExpiredFlows is a no-op for DTSFlowStore; DTS handles TTL cleanup automatically.")
}

// Ensure DTSFlowStore satisfies a potential FlowStore interface (if one were defined matching these methods)
// type FlowStoreInterface interface {
//   StoreFlow(ctx context.Context, flowID string, state oidcflow.LoginFlowState) error
//   GetFlow(ctx context.Context, flowID string) (*oidcflow.LoginFlowState, error)
//   UpdateFlow(ctx context.Context, flowID string, state *oidcflow.LoginFlowState) error
//   DeleteFlow(ctx context.Context, flowID string) error
//   CleanupExpiredFlows()
// }
// var _ FlowStoreInterface = (*DTSFlowStore)(nil)
