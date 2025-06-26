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
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// dtsDeviceAuthRepository implements domain.DeviceAuthorizationRepository
type dtsDeviceAuthRepository struct {
	client *Client
}

// NewDTSDeviceAuthorizationRepository creates a new DTS-backed DeviceAuthorizationRepository.
func NewDTSDeviceAuthorizationRepository(client *Client) domain.DeviceAuthorizationRepository {
	if client == nil {
		log.Fatal("DTS client cannot be nil for NewDTSDeviceAuthorizationRepository")
	}
	return &dtsDeviceAuthRepository{client: client}
}

func toProtoDeviceAuth(da *domain.DeviceCode) *dtsv1.DeviceAuth {
	if da == nil {
		return nil
	}
	return &dtsv1.DeviceAuth{
		DeviceCode:   da.DeviceCode,
		UserCode:     da.UserCode,
		ClientId:     da.ClientID,
		Scope:        da.Scope,
		ExpiresAt:    timestamppb.New(da.ExpiresAt),
		LastPolledAt: timestamppb.New(da.LastPolledAt),
		PollInterval: durationpb.New(time.Duration(da.Interval) * time.Second), // domain.DeviceCode.Interval is int, matching mongo, converting to duration
		Status:       string(da.Status),
		UserId:       da.UserID,
		SessionId:    da.DeviceCodeData.SessionID,
		Claims:       da.DeviceCodeData.Claims,
	}
}

func fromProtoDeviceAuth(pda *dtsv1.DeviceAuth) *domain.DeviceCode {
	if pda == nil {
		return nil
	}
	var lastPolledAt time.Time
	if pda.LastPolledAt != nil && pda.LastPolledAt.IsValid() {
		lastPolledAt = pda.LastPolledAt.AsTime()
	}

	// domain.DeviceCode.Interval is int (seconds)
	intervalSeconds := 0
	if pda.PollInterval != nil && pda.PollInterval.IsValid() {
		intervalSeconds = int(pda.PollInterval.AsDuration().Seconds())
	}

	return &domain.DeviceCode{
		// ID: not stored/retrieved from DTS directly if device_code is key
		DeviceCode:   pda.DeviceCode,
		UserCode:     pda.UserCode,
		ClientID:     pda.ClientId,
		Scope:        pda.Scope,
		Status:       domain.DeviceCodeStatus(pda.Status),
		UserID:       pda.UserId,
		ExpiresAt:    pda.ExpiresAt.AsTime(),
		Interval:     intervalSeconds,
		LastPolledAt: lastPolledAt,
		// CreatedAt: not stored in dtsv1.DeviceAuth
		DeviceCodeData: domain.DeviceCodeData{
			SessionID: pda.SessionId,
			Claims:    pda.Claims,
		},
	}
}

func (r *dtsDeviceAuthRepository) SaveDeviceAuth(ctx context.Context, auth *domain.DeviceCode) error {
	if auth == nil {
		return status.Error(codes.InvalidArgument, "device code auth cannot be nil")
	}

	protoDA := toProtoDeviceAuth(auth)
	if protoDA.ExpiresAt.AsTime().Before(time.Now()) || protoDA.ExpiresAt.AsTime().IsZero() {
		return status.Error(codes.InvalidArgument, "device auth is already expired or has invalid expiration")
	}

	req := connect.NewRequest(&dtsv1.StoreDeviceAuthRequest{DeviceAuth: protoDA})
	_, err := r.client.DTS.StoreDeviceAuth(ctx, req)
	if err != nil {
		log.Printf("Error storing device auth for device code %s to DTS: %v", auth.DeviceCode, err)

		return status.Errorf(codes.Internal, "failed to store device auth: %v", err)
	}

	log.Printf("Device auth for device code %s stored in DTS.", auth.DeviceCode)

	return nil
}

func (r *dtsDeviceAuthRepository) GetDeviceAuthByDeviceCode(ctx context.Context, deviceCodeStr string) (*domain.DeviceCode, error) {
	if deviceCodeStr == "" {
		return nil, status.Error(codes.InvalidArgument, "device code string cannot be empty")
	}

	req := connect.NewRequest(&dtsv1.GetDeviceAuthByDeviceCodeRequest{
		DeviceCode: deviceCodeStr,
	})

	protoDA, err := r.client.DTS.GetDeviceAuthByDeviceCode(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("Device auth for device code %s not found in DTS.", deviceCodeStr)

			return nil, nil // As per typical repository behavior for not found
		}
		log.Printf("Error getting device auth for device code %s from DTS: %v", deviceCodeStr, err)

		return nil, status.Errorf(codes.Internal, "failed to get device auth by device code: %v", err)
	}

	domainDA := fromProtoDeviceAuth(protoDA.Msg)
	if domainDA.ExpiresAt.Before(time.Now()) {
		log.Printf("Device auth for device code %s retrieved but is expired.", deviceCodeStr)

		return nil, nil // Treat as not found if expired
	}

	return domainDA, nil
}

func (r *dtsDeviceAuthRepository) GetDeviceAuthByUserCode(ctx context.Context, userCodeStr string) (*domain.DeviceCode, error) {
	if userCodeStr == "" {
		return nil, status.Error(codes.InvalidArgument, "user code string cannot be empty")
	}

	req := connect.NewRequest(&dtsv1.GetDeviceAuthByUserCodeRequest{
		UserCode: userCodeStr,
	})

	protoDA, err := r.client.DTS.GetDeviceAuthByUserCode(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("Device auth for user code %s not found in DTS.", userCodeStr)
			return nil, nil
		}
		log.Printf("Error getting device auth for user code %s from DTS: %v", userCodeStr, err)

		return nil, status.Errorf(codes.Internal, "failed to get device auth by user code: %v", err)
	}

	domainDA := fromProtoDeviceAuth(protoDA.Msg)
	if domainDA.ExpiresAt.Before(time.Now()) {
		log.Printf("Device auth for user code %s retrieved but is expired (device code %s).", userCodeStr, domainDA.DeviceCode)

		return nil, nil // Treat as not found if expired
	}

	return domainDA, nil
}

// Internal helper for Get-Modify-Save pattern
func (r *dtsDeviceAuthRepository) getAndUpdateDeviceAuth(ctx context.Context, deviceCodeStr string, updateFunc func(*domain.DeviceCode) error) (*domain.DeviceCode, error) {
	da, err := r.GetDeviceAuthByDeviceCode(ctx, deviceCodeStr)
	if err != nil {
		return nil, err // Error from GetDeviceAuthByDeviceCode already logged and formatted
	}
	if da == nil {
		log.Printf("Device auth not found for update: %s", deviceCodeStr)
		return nil, status.Errorf(codes.NotFound, "device auth %s not found for update", deviceCodeStr)
	}

	if err := updateFunc(da); err != nil {
		return nil, err // Error from the update function itself
	}

	// Save the modified device auth object
	protoDA := toProtoDeviceAuth(da)
	// The DTS service's UpdateDeviceAuth is an upsert, suitable here.
	// Or we can use StoreDeviceAuth if that's how updates are handled (overwrite)
	updateReq := connect.NewRequest(&dtsv1.UpdateDeviceAuthRequest{
		DeviceAuth: protoDA,
	})

	_, err = r.client.DTS.UpdateDeviceAuth(ctx, updateReq)
	if err != nil {
		log.Printf("Error updating device auth %s in DTS: %v", deviceCodeStr, err)

		return nil, status.Errorf(codes.Internal, "failed to save updated device auth: %v", err)
	}

	log.Printf("Device auth %s updated successfully in DTS.", deviceCodeStr)

	return da, nil
}

func (r *dtsDeviceAuthRepository) ApproveDeviceAuth(ctx context.Context, userCodeStr string, userID string) (*domain.DeviceCode, error) {
	if userCodeStr == "" || userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user code and user ID must be provided for approval")
	}

	// First, get by user code to find the device code and current state
	da, err := r.GetDeviceAuthByUserCode(ctx, userCodeStr)
	if err != nil {
		return nil, err // Already logged and formatted
	}
	if da == nil {
		return nil, status.Errorf(codes.NotFound, "device auth for user code %s not found for approval", userCodeStr)
	}

	if da.Status != domain.DeviceCodeStatusPending {
		log.Printf("Device auth for user code %s (device code %s) is not pending, current status: %s", userCodeStr, da.DeviceCode, da.Status)
		return nil, status.Errorf(codes.FailedPrecondition, "device auth is not in pending state (status: %s)", da.Status)
	}

	// Now update using the deviceCode
	return r.getAndUpdateDeviceAuth(ctx, da.DeviceCode, func(d *domain.DeviceCode) error {
		d.UserID = userID
		d.Status = domain.DeviceCodeStatusAuthorized
		// Note: The spec for domain.DeviceCode doesn't mention updating LastPolledAt here,
		// but it might be logical. DTS service handles what fields are updated based on UpdateDeviceAuthRequest.
		return nil
	})
}

func (r *dtsDeviceAuthRepository) UpdateDeviceAuthStatus(ctx context.Context, deviceCodeStr string, newStatus domain.DeviceCodeStatus) error {
	if deviceCodeStr == "" {
		return status.Error(codes.InvalidArgument, "device code must be provided")
	}
	_, err := r.getAndUpdateDeviceAuth(ctx, deviceCodeStr, func(d *domain.DeviceCode) error {
		d.Status = newStatus
		return nil
	})
	return err
}

func (r *dtsDeviceAuthRepository) UpdateDeviceAuthLastPolledAt(ctx context.Context, deviceCodeStr string) error {
	if deviceCodeStr == "" {
		return status.Error(codes.InvalidArgument, "device code must be provided")
	}

	_, err := r.getAndUpdateDeviceAuth(ctx, deviceCodeStr, func(d *domain.DeviceCode) error {
		d.LastPolledAt = time.Now()
		return nil
	})

	return err
}

func (r *dtsDeviceAuthRepository) DeleteExpiredDeviceAuths(ctx context.Context) error {
	log.Println("DeleteExpiredDeviceAuths is a no-op for DTS-backed repository; DTS handles TTL cleanup automatically.")
	return nil
}
