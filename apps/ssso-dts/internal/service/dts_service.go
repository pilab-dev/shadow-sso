package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/pilab-dev/ssso/apps/ssso-dts/internal/storage"
	dtsv1 "github.com/pilab-dev/ssso/gen/proto/dts/v1" // Assuming buf generate worked
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Buckets constants defined as per spec and common usage
const (
	authCodesBucket           = "authcodes"
	refreshTokensBucket       = "refreshtokens"
	accessTokenMetadataBucket = "accesstokenmetadata"
	oidcFlowsBucket           = "oidcflows"
	userSessionsBucket        = "usersessions"
	deviceAuthGrantsBucket    = "deviceauthgrants" // For device codes
	deviceAuthUserCodeBucket  = "deviceauthusercodes" // For user codes mapping to device codes
	pkceStatesBucket          = "pkcestates"
)

// DTSService implements the gRPC TokenStoreService.
type DTSService struct {
	dtsv1.UnimplementedTokenStoreServiceServer // For forward compatibility
	store *storage.BBoltStore
}

// NewDTSService creates a new DTSService.
func NewDTSService(store *storage.BBoltStore) *DTSService {
	return &DTSService{store: store}
}

// --- Generic Key-Value operations ---

// Set stores a generic key-value pair.
func (s *DTSService) Set(ctx context.Context, req *dtsv1.SetRequest) (*emptypb.Empty, error) {
	if req.Bucket == "" {
		return nil, status.Error(codes.InvalidArgument, "bucket name cannot be empty")
	}
	if req.Key == "" {
		return nil, status.Error(codes.InvalidArgument, "key cannot be empty")
	}
	var ttl time.Duration
	if req.Ttl != nil {
		ttl = req.Ttl.AsDuration()
	}
	err := s.store.Set(req.Bucket, req.Key, req.Value, ttl)
	if err != nil {
		log.Printf("Error in Set operation (bucket: %s, key: %s): %v", req.Bucket, req.Key, err)
		return nil, status.Errorf(codes.Internal, "failed to set value: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// Get retrieves a generic key-value pair.
func (s *DTSService) Get(ctx context.Context, req *dtsv1.GetRequest) (*dtsv1.GetResponse, error) {
	if req.Bucket == "" {
		return nil, status.Error(codes.InvalidArgument, "bucket name cannot be empty")
	}
	if req.Key == "" {
		return nil, status.Error(codes.InvalidArgument, "key cannot be empty")
	}
	value, expiresAt, found, err := s.store.Get(req.Bucket, req.Key)
	if err != nil {
		log.Printf("Error in Get operation (bucket: %s, key: %s): %v", req.Bucket, req.Key, err)
		return nil, status.Errorf(codes.Internal, "failed to get value: %v", err)
	}
	if !found {
		return &dtsv1.GetResponse{Found: false}, nil
	}
	return &dtsv1.GetResponse{
		Value:     value,
		Found:     true,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

// Delete removes a generic key-value pair.
func (s *DTSService) Delete(ctx context.Context, req *dtsv1.DeleteRequest) (*emptypb.Empty, error) {
	if req.Bucket == "" {
		return nil, status.Error(codes.InvalidArgument, "bucket name cannot be empty")
	}
	if req.Key == "" {
		return nil, status.Error(codes.InvalidArgument, "key cannot be empty")
	}
	err := s.store.Delete(req.Bucket, req.Key)
	if err != nil {
		log.Printf("Error in Delete operation (bucket: %s, key: %s): %v", req.Bucket, req.Key, err)
		return nil, status.Errorf(codes.Internal, "failed to delete value: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// --- Helper for specialized object operations ---
func storeProtoMessage(s *storage.BBoltStore, bucket, key string, msg proto.Message, expiresAt *timestamppb.Timestamp) error {
	if key == "" {
		return status.Error(codes.InvalidArgument, "key for storing message cannot be empty")
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal proto message: %v", err)
	}
	var ttl time.Duration
	if expiresAt != nil {
		ttl = time.Until(expiresAt.AsTime())
		if ttl <= 0 { // Already expired or invalid
			return status.Error(codes.InvalidArgument, "provided expiration time is in the past or invalid")
		}
	} else {
		ttl = 0 // Use store's default TTL
	}
	return s.Set(bucket, key, data, ttl)
}

func getProtoMessage[T proto.Message](s *storage.BBoltStore, bucket, key string, msg T) (T, bool, error) {
	var zero T
	if key == "" {
		return zero, false, status.Error(codes.InvalidArgument, "key for getting message cannot be empty")
	}
	data, _, found, err := s.Get(bucket, key)
	if err != nil {
		return zero, false, status.Errorf(codes.Internal, "failed to get data from store: %v", err)
	}
	if !found {
		return zero, false, nil // Not found, no error
	}
	if err := proto.Unmarshal(data, msg); err != nil {
		return zero, true, status.Errorf(codes.Internal, "failed to unmarshal data to proto message: %v", err)
	}
	return msg, true, nil
}

// --- Authorization Codes ---
func (s *DTSService) StoreAuthCode(ctx context.Context, req *dtsv1.StoreAuthCodeRequest) (*emptypb.Empty, error) {
	if req.AuthCode == nil || req.AuthCode.Code == "" {
		return nil, status.Error(codes.InvalidArgument, "auth code or its ID is missing")
	}
	err := storeProtoMessage(s.store, authCodesBucket, req.AuthCode.Code, req.AuthCode, req.AuthCode.ExpiresAt)
	if err != nil { return nil, err }
	return &emptypb.Empty{}, nil
}

func (s *DTSService) GetAuthCode(ctx context.Context, req *dtsv1.GetAuthCodeRequest) (*dtsv1.AuthCode, error) {
	if req.Code == "" { return nil, status.Error(codes.InvalidArgument, "auth code ID is missing") }
	authCode := &dtsv1.AuthCode{}
	res, found, err := getProtoMessage(s.store, authCodesBucket, req.Code, authCode)
	if err != nil { return nil, err }
	if !found { return nil, status.Errorf(codes.NotFound, "auth code %s not found", req.Code) }
	return res, nil
}

func (s *DTSService) DeleteAuthCode(ctx context.Context, req *dtsv1.DeleteAuthCodeRequest) (*emptypb.Empty, error) {
	if req.Code == "" { return nil, status.Error(codes.InvalidArgument, "auth code ID is missing") }
	err := s.store.Delete(authCodesBucket, req.Code)
	if err != nil { return nil, status.Errorf(codes.Internal, "failed to delete auth code: %v", err) }
	return &emptypb.Empty{}, nil
}

// --- Refresh Tokens ---
func (s *DTSService) StoreRefreshToken(ctx context.Context, req *dtsv1.StoreRefreshTokenRequest) (*emptypb.Empty, error) {
	if req.RefreshToken == nil || req.RefreshToken.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token or its ID is missing")
	}
	err := storeProtoMessage(s.store, refreshTokensBucket, req.RefreshToken.Token, req.RefreshToken, req.RefreshToken.ExpiresAt)
	if err != nil { return nil, err }
	return &emptypb.Empty{}, nil
}

func (s *DTSService) GetRefreshToken(ctx context.Context, req *dtsv1.GetRefreshTokenRequest) (*dtsv1.RefreshToken, error) {
	if req.Token == "" { return nil, status.Error(codes.InvalidArgument, "refresh token ID is missing") }
	refreshToken := &dtsv1.RefreshToken{}
	res, found, err := getProtoMessage(s.store, refreshTokensBucket, req.Token, refreshToken)
	if err != nil { return nil, err }
	if !found { return nil, status.Errorf(codes.NotFound, "refresh token %s not found", req.Token) }
	return res, nil
}

func (s *DTSService) DeleteRefreshToken(ctx context.Context, req *dtsv1.DeleteRefreshTokenRequest) (*emptypb.Empty, error) {
	if req.Token == "" { return nil, status.Error(codes.InvalidArgument, "refresh token ID is missing") }
	err := s.store.Delete(refreshTokensBucket, req.Token)
	if err != nil { return nil, status.Errorf(codes.Internal, "failed to delete refresh token: %v", err) }
	return &emptypb.Empty{}, nil
}

// --- Access Token Metadata ---
func (s *DTSService) StoreAccessTokenMetadata(ctx context.Context, req *dtsv1.StoreAccessTokenMetadataRequest) (*emptypb.Empty, error) {
	if req.AccessTokenMetadata == nil || req.AccessTokenMetadata.TokenHash == "" {
		return nil, status.Error(codes.InvalidArgument, "access token metadata or its token hash is missing")
	}
	err := storeProtoMessage(s.store, accessTokenMetadataBucket, req.AccessTokenMetadata.TokenHash, req.AccessTokenMetadata, req.AccessTokenMetadata.ExpiresAt)
	if err != nil { return nil, err }
	return &emptypb.Empty{}, nil
}

func (s *DTSService) GetAccessTokenMetadata(ctx context.Context, req *dtsv1.GetAccessTokenMetadataRequest) (*dtsv1.AccessTokenMetadata, error) {
	if req.TokenHash == "" { return nil, status.Error(codes.InvalidArgument, "access token metadata token hash is missing") }
	atMeta := &dtsv1.AccessTokenMetadata{}
	res, found, err := getProtoMessage(s.store, accessTokenMetadataBucket, req.TokenHash, atMeta)
	if err != nil { return nil, err }
	if !found { return nil, status.Errorf(codes.NotFound, "access token metadata for hash %s not found", req.TokenHash) }
	return res, nil
}

func (s *DTSService) DeleteAccessTokenMetadata(ctx context.Context, req *dtsv1.DeleteAccessTokenMetadataRequest) (*emptypb.Empty, error) {
	if req.TokenHash == "" { return nil, status.Error(codes.InvalidArgument, "access token metadata token hash is missing") }
	err := s.store.Delete(accessTokenMetadataBucket, req.TokenHash)
	if err != nil { return nil, status.Errorf(codes.Internal, "failed to delete access token metadata: %v", err) }
	return &emptypb.Empty{}, nil
}

// --- OIDC Flows ---
func (s *DTSService) StoreOIDCFlw(ctx context.Context, req *dtsv1.StoreOIDCFlwRequest) (*emptypb.Empty, error) {
	if req.OidcFlow == nil || req.OidcFlow.FlowId == "" {
		return nil, status.Error(codes.InvalidArgument, "OIDC flow or its ID is missing")
	}
	err := storeProtoMessage(s.store, oidcFlowsBucket, req.OidcFlow.FlowId, req.OidcFlow, req.OidcFlow.ExpiresAt)
	if err != nil { return nil, err }
	return &emptypb.Empty{}, nil
}

func (s *DTSService) GetOIDCFlw(ctx context.Context, req *dtsv1.GetOIDCFlwRequest) (*dtsv1.OIDCFlw, error) {
	if req.FlowId == "" { return nil, status.Error(codes.InvalidArgument, "OIDC flow ID is missing") }
	flow := &dtsv1.OIDCFlw{}
	res, found, err := getProtoMessage(s.store, oidcFlowsBucket, req.FlowId, flow)
	if err != nil { return nil, err }
	if !found { return nil, status.Errorf(codes.NotFound, "OIDC flow %s not found", req.FlowId) }
	return res, nil
}

func (s *DTSService) DeleteOIDCFlw(ctx context.Context, req *dtsv1.DeleteOIDCFlwRequest) (*emptypb.Empty, error) {
	if req.FlowId == "" { return nil, status.Error(codes.InvalidArgument, "OIDC flow ID is missing") }
	err := s.store.Delete(oidcFlowsBucket, req.FlowId)
	if err != nil { return nil, status.Errorf(codes.Internal, "failed to delete OIDC flow: %v", err) }
	return &emptypb.Empty{}, nil
}

func (s *DTSService) UpdateOIDCFlw(ctx context.Context, req *dtsv1.UpdateOIDCFlwRequest) (*emptypb.Empty, error) {
	if req.OidcFlow == nil || req.OidcFlow.FlowId == "" {
		return nil, status.Error(codes.InvalidArgument, "OIDC flow or its ID is missing for update")
	}
	// Update is effectively a Set operation that overwrites; ensure the item exists if that's a requirement (not explicit in spec)
	// For simplicity, this is an upsert. If "must exist" is needed, add a Get check first.
	err := storeProtoMessage(s.store, oidcFlowsBucket, req.OidcFlow.FlowId, req.OidcFlow, req.OidcFlow.ExpiresAt)
	if err != nil { return nil, err }
	return &emptypb.Empty{}, nil
}

// --- OIDC User Sessions ---
func (s *DTSService) StoreUserSession(ctx context.Context, req *dtsv1.StoreUserSessionRequest) (*emptypb.Empty, error) {
	if req.UserSession == nil || req.UserSession.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "user session or its ID is missing")
	}
	err := storeProtoMessage(s.store, userSessionsBucket, req.UserSession.SessionId, req.UserSession, req.UserSession.ExpiresAt)
	if err != nil { return nil, err }
	return &emptypb.Empty{}, nil
}

func (s *DTSService) GetUserSession(ctx context.Context, req *dtsv1.GetUserSessionRequest) (*dtsv1.UserSession, error) {
	if req.SessionId == "" { return nil, status.Error(codes.InvalidArgument, "user session ID is missing") }
	session := &dtsv1.UserSession{}
	res, found, err := getProtoMessage(s.store, userSessionsBucket, req.SessionId, session)
	if err != nil { return nil, err }
	if !found { return nil, status.Errorf(codes.NotFound, "user session %s not found", req.SessionId) }
	return res, nil
}

func (s *DTSService) DeleteUserSession(ctx context.Context, req *dtsv1.DeleteUserSessionRequest) (*emptypb.Empty, error) {
	if req.SessionId == "" { return nil, status.Error(codes.InvalidArgument, "user session ID is missing") }
	err := s.store.Delete(userSessionsBucket, req.SessionId)
	if err != nil { return nil, status.Errorf(codes.Internal, "failed to delete user session: %v", err) }
	return &emptypb.Empty{}, nil
}

// --- Device Authorization Grants & Codes ---
func (s *DTSService) StoreDeviceAuth(ctx context.Context, req *dtsv1.StoreDeviceAuthRequest) (*emptypb.Empty, error) {
	da := req.DeviceAuth
	if da == nil || da.DeviceCode == "" || da.UserCode == "" {
		return nil, status.Error(codes.InvalidArgument, "device auth grant, device code, or user code is missing")
	}

	// Store the main grant by device code
	err := storeProtoMessage(s.store, deviceAuthGrantsBucket, da.DeviceCode, da, da.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("storing device auth by device code: %w", err)
	}

	// Store a mapping from user_code to device_code for easy lookup
	// This mapping should have the same TTL as the main grant.
	// The value stored is just the device_code string.
	var ttl time.Duration
	if da.ExpiresAt != nil {
		ttl = time.Until(da.ExpiresAt.AsTime())
		if ttl <= 0 {
			// Attempt to clean up the primary record if this secondary part fails due to expiration
			_ = s.store.Delete(deviceAuthGrantsBucket, da.DeviceCode)
			return nil, status.Error(codes.InvalidArgument, "device auth expiration time is in the past or invalid")
		}
	} // else use default store TTL

	err = s.store.Set(deviceAuthUserCodeBucket, da.UserCode, []byte(da.DeviceCode), ttl)
	if err != nil {
		// Attempt to clean up the primary record if this secondary part fails
		_ = s.store.Delete(deviceAuthGrantsBucket, da.DeviceCode)
		return nil, fmt.Errorf("storing device auth user code mapping: %w", err)
	}
	return &emptypb.Empty{}, nil
}

func (s *DTSService) GetDeviceAuthByDeviceCode(ctx context.Context, req *dtsv1.GetDeviceAuthByDeviceCodeRequest) (*dtsv1.DeviceAuth, error) {
	if req.DeviceCode == "" { return nil, status.Error(codes.InvalidArgument, "device code is missing") }
	da := &dtsv1.DeviceAuth{}
	res, found, err := getProtoMessage(s.store, deviceAuthGrantsBucket, req.DeviceCode, da)
	if err != nil { return nil, err }
	if !found { return nil, status.Errorf(codes.NotFound, "device auth grant for device code %s not found", req.DeviceCode) }
	return res, nil
}

func (s *DTSService) GetDeviceAuthByUserCode(ctx context.Context, req *dtsv1.GetDeviceAuthByUserCodeRequest) (*dtsv1.DeviceAuth, error) {
	if req.UserCode == "" { return nil, status.Error(codes.InvalidArgument, "user code is missing") }

	// 1. Look up device_code using user_code
	deviceCodeBytes, _, found, err := s.store.Get(deviceAuthUserCodeBucket, req.UserCode)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get device code mapping for user code %s: %v", req.UserCode, err)
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "no device auth grant found for user code %s (mapping expired or invalid)", req.UserCode)
	}
	deviceCode := string(deviceCodeBytes)

	// 2. Look up the actual grant using the device_code
	da := &dtsv1.DeviceAuth{}
	res, found, err := getProtoMessage(s.store, deviceAuthGrantsBucket, deviceCode, da)
	if err != nil { return nil, err } // error from getProtoMessage already has status
	if !found {
		// This case implies inconsistency: mapping exists but primary record doesn't.
		// Could be due to partial deletion or timing. Treat as not found.
		log.Printf("Device auth inconsistency: user_code %s mapping to device_code %s exists, but primary record not found.", req.UserCode, deviceCode)
		return nil, status.Errorf(codes.NotFound, "device auth grant for user code %s not found (data inconsistency)", req.UserCode)
	}
	return res, nil
}

func (s *DTSService) UpdateDeviceAuth(ctx context.Context, req *dtsv1.UpdateDeviceAuthRequest) (*emptypb.Empty, error) {
	da := req.DeviceAuth
	if da == nil || da.DeviceCode == "" {
		return nil, status.Error(codes.InvalidArgument, "device auth grant or its device code is missing for update")
	}
	// Update is an overwrite. Ensure user_code mapping is consistent if user_code could change (it shouldn't typically).
	// The current StoreDeviceAuth handles creating/updating both records.
	// If user_code is guaranteed not to change, we only need to update the main record.
	// However, the spec implies the whole DeviceAuth object is provided, so we can just re-store.

	// For safety, if the user_code could potentially change (though unlikely for a DeviceAuth update),
	// we might need to delete the old user_code mapping first.
	// Assuming user_code is immutable for an existing grant, we only need to update the main grant.
	// If user_code could change, a more complex update logic is needed (get old, delete old mapping, store new).

	// Re-storing the main grant by device code with new data.
	err := storeProtoMessage(s.store, deviceAuthGrantsBucket, da.DeviceCode, da, da.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("updating device auth by device code: %w", err)
	}

	// If user code is present and could have changed, ensure its mapping is also updated.
	// Typically, user code is fixed once generated. If it *can* change, this needs more care.
	// For now, assume user_code is stable for a given device_code after initial StoreDeviceAuth.
	// If the update involves changing status (e.g. to 'approved') and user_id, the main record update is sufficient.
	// The user_code to device_code mapping should remain valid.

	return &emptypb.Empty{}, nil
}

func (s *DTSService) DeleteDeviceAuth(ctx context.Context, req *dtsv1.DeleteDeviceAuthRequest) (*emptypb.Empty, error) {
	if req.DeviceCode == "" {
		return nil, status.Error(codes.InvalidArgument, "device code is missing for deletion")
	}

	// To fully delete, we need to find the user_code associated with this device_code to delete the mapping.
	// This requires a Get first, or assumes the user_code is also provided (it's not in DeleteDeviceAuthRequest).
	// For simplicity, if we only have device_code, we can delete the main grant.
	// The user_code mapping will then point to a non-existent grant and eventually expire.
	// A more thorough delete would:
	// 1. GetDeviceAuthByDeviceCode to retrieve the user_code.
	// 2. Delete from deviceAuthGrantsBucket using device_code.
	// 3. Delete from deviceAuthUserCodeBucket using the retrieved user_code.

	// Simple deletion (main grant only):
	err := s.store.Delete(deviceAuthGrantsBucket, req.DeviceCode)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete device auth grant for device code %s: %v", req.DeviceCode, err)
	}

	// To also delete user_code mapping (more complex, needs a read first or redesign of DeleteDeviceAuthRequest):
	// For now, we'll leave the user_code mapping to expire naturally or be overwritten.
	// This could be improved if direct deletion of the user_code mapping is critical without waiting for TTL.
	// One way: client could provide user_code to delete, or service fetches it first.
	// If Delete is called after user_code is used, then it might not be available.
	// The spec says "DeleteDeviceAuthRequest { string device_code = 1; // Or by user_code }"
	// Current proto only has device_code. If it could be by user_code, then:
	// if req.UserCode != "" { deviceCodeBytes, _, found, _ := s.store.Get(deviceAuthUserCodeBucket, req.UserCode) ... then delete both }

	log.Printf("Device auth grant for device_code %s deleted. Corresponding user_code mapping will expire naturally.", req.DeviceCode)

	return &emptypb.Empty{}, nil
}


// --- PKCE States ---
func (s *DTSService) StorePKCEState(ctx context.Context, req *dtsv1.StorePKCEStateRequest) (*emptypb.Empty, error) {
	if req.PkceState == nil || req.PkceState.CodeHash == "" {
		return nil, status.Error(codes.InvalidArgument, "PKCE state or its code hash is missing")
	}
	err := storeProtoMessage(s.store, pkceStatesBucket, req.PkceState.CodeHash, req.PkceState, req.PkceState.ExpiresAt)
	if err != nil { return nil, err }
	return &emptypb.Empty{}, nil
}

func (s *DTSService) GetPKCEState(ctx context.Context, req *dtsv1.GetPKCEStateRequest) (*dtsv1.PKCEState, error) {
	if req.CodeHash == "" { return nil, status.Error(codes.InvalidArgument, "PKCE code hash is missing") }
	pkce := &dtsv1.PKCEState{}
	res, found, err := getProtoMessage(s.store, pkceStatesBucket, req.CodeHash, pkce)
	if err != nil { return nil, err }
	if !found { return nil, status.Errorf(codes.NotFound, "PKCE state for code hash %s not found", req.CodeHash) }
	return res, nil
}

func (s *DTSService) DeletePKCEState(ctx context.Context, req *dtsv1.DeletePKCEStateRequest) (*emptypb.Empty, error) {
	if req.CodeHash == "" { return nil, status.Error(codes.InvalidArgument, "PKCE code hash is missing") }
	err := s.store.Delete(pkceStatesBucket, req.CodeHash)
	if err != nil { return nil, status.Errorf(codes.Internal, "failed to delete PKCE state: %v", err) }
	return &emptypb.Empty{}, nil
}

// Helper to convert durationpb.Duration to time.Duration for TTL.
// Returns 0 if input is nil.
func durationpbToTimeDuration(d *durationpb.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return d.AsDuration()
}
