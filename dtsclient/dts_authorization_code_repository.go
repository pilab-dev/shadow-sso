package dtsclient

import (
	"context"
	"log"
	"time"

	"github.com/pilab-dev/ssso/domain"
	dtsv1 "github.com/pilab-dev/ssso/gen/proto/dts/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// dtsAuthCodeRepository implements the domain.AuthorizationCodeRepository interface using a DTS client.
type dtsAuthCodeRepository struct {
	client *Client
}

// NewDTSAuthorizationCodeRepository creates a new DTS-backed AuthorizationCodeRepository.
func NewDTSAuthorizationCodeRepository(client *Client) domain.AuthorizationCodeRepository {
	if client == nil {
		log.Fatal("DTS client cannot be nil for NewDTSAuthorizationCodeRepository")
	}
	return &dtsAuthCodeRepository{client: client}
}

func toProtoAuthCode(domainAC *domain.AuthCode) *dtsv1.AuthCode {
	if domainAC == nil {
		return nil
	}
	// Note: domain.AuthCode.Used and domain.AuthCode.CreatedAt are not directly mapped to dtsv1.AuthCode.
	// 'Used' status is handled by deleting the code in DTS after use.
	// 'CreatedAt' is not stored in DTS by default with this mapping.
	// Additional fields in dtsv1.AuthCode (session_id, claims, auth_time_iat) are not populated from domain.AuthCode here.
	return &dtsv1.AuthCode{
		Code:                domainAC.Code,
		ClientId:            domainAC.ClientID,
		UserId:              domainAC.UserID,
		RedirectUri:         domainAC.RedirectURI,
		Scope:               domainAC.Scope,
		CodeChallenge:       domainAC.CodeChallenge,
		CodeChallengeMethod: domainAC.CodeChallengeMethod,
		ExpiresAt:           timestamppb.New(domainAC.ExpiresAt),
		// SessionId: // Not in domain.AuthCode
		// Claims:    // Not in domain.AuthCode
		// AuthTimeIat: // Not in domain.AuthCode
	}
}

func fromProtoAuthCode(protoAC *dtsv1.AuthCode) *domain.AuthCode {
	if protoAC == nil {
		return nil
	}
	// 'Used' field in domain.AuthCode defaults to false.
	// If a code is retrieved, it's considered not used yet from DTS perspective.
	// If it's not found, it might have been used (deleted) or expired.
	return &domain.AuthCode{
		Code:                protoAC.Code,
		ClientID:            protoAC.ClientId,
		UserID:              protoAC.UserId,
		RedirectURI:         protoAC.RedirectUri,
		Scope:               protoAC.Scope,
		ExpiresAt:           protoAC.ExpiresAt.AsTime(),
		Used:                false, // If found in DTS, it's not marked 'Used' in DTS sense.
		CodeChallenge:       protoAC.CodeChallenge,
		CodeChallengeMethod: protoAC.CodeChallengeMethod,
		// CreatedAt: // Not available from dtsv1.AuthCode, will be zero time.
	}
}

// SaveAuthCode stores an authorization code in DTS.
func (r *dtsAuthCodeRepository) SaveAuthCode(ctx context.Context, code *domain.AuthCode) error {
	if code == nil {
		return status.Error(codes.InvalidArgument, "auth code cannot be nil")
	}
	protoAC := toProtoAuthCode(code)
	if protoAC.ExpiresAt.AsTime().Before(time.Now()) || protoAC.ExpiresAt.AsTime().IsZero() {
		log.Printf("Attempted to save already expired or zero-expiry auth code: %s", code.Code)
		return status.Error(codes.InvalidArgument, "auth code is already expired or has invalid expiration")
	}

	req := &dtsv1.StoreAuthCodeRequest{AuthCode: protoAC}
	_, err := r.client.DTS.StoreAuthCode(ctx, req)
	if err != nil {
		log.Printf("Error storing auth code %s to DTS: %v", code.Code, err)
		return status.Errorf(codes.Internal, "failed to store auth code in DTS: %v", err)
	}
	log.Printf("Auth code %s stored in DTS.", code.Code)
	return nil
}

// GetAuthCode retrieves an authorization code from DTS.
// If the code is not found, it could mean it's expired (and cleaned up by DTS) or already used (deleted).
func (r *dtsAuthCodeRepository) GetAuthCode(ctx context.Context, codeStr string) (*domain.AuthCode, error) {
	if codeStr == "" {
		return nil, status.Error(codes.InvalidArgument, "auth code string cannot be empty")
	}
	req := &dtsv1.GetAuthCodeRequest{Code: codeStr}
	protoAC, err := r.client.DTS.GetAuthCode(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("Auth code %s not found in DTS.", codeStr)
			return nil, nil // Per interface, return nil, nil if not found (or specific error if preferred by caller)
		}
		log.Printf("Error getting auth code %s from DTS: %v", codeStr, err)
		return nil, status.Errorf(codes.Internal, "failed to get auth code from DTS: %v", err)
	}

	domainAC := fromProtoAuthCode(protoAC)
	// Check for expiration again, as DTS Get might not delete on read if TTL check is slightly off
	if domainAC.ExpiresAt.Before(time.Now()) {
		log.Printf("Auth code %s retrieved from DTS but is expired.", codeStr)
		// Optionally delete it here proactively
		// r.MarkAuthCodeAsUsed(ctx, codeStr) // This would delete it
		return nil, nil // Treat as not found if expired
	}

	log.Printf("Auth code %s retrieved from DTS.", codeStr)
	return domainAC, nil
}

// MarkAuthCodeAsUsed deletes the authorization code from DTS, effectively marking it as used.
func (r *dtsAuthCodeRepository) MarkAuthCodeAsUsed(ctx context.Context, codeStr string) error {
	if codeStr == "" {
		return status.Error(codes.InvalidArgument, "auth code string cannot be empty")
	}
	// To truly mark as used, we should first verify it exists and is not expired.
	// However, the interface doesn't require returning the code.
	// Deleting it is the simplest way to make it unusable.
	// If it doesn't exist, Delete is usually a no-op.

	// Optional: Get it first to ensure it's valid before "using" (deleting)
	// _, err := r.GetAuthCode(ctx, codeStr)
	// if err != nil {
	// return err // Could be internal error from Get
	// }
	// if existingCode == nil {
	// return fmt.Errorf("auth code %s not found or expired, cannot mark as used", codeStr) // Or specific error
	// }

	req := &dtsv1.DeleteAuthCodeRequest{Code: codeStr}
	_, err := r.client.DTS.DeleteAuthCode(ctx, req)
	if err != nil {
		log.Printf("Error deleting (marking as used) auth code %s from DTS: %v", codeStr, err)
		return status.Errorf(codes.Internal, "failed to delete auth code from DTS: %v", err)
	}
	log.Printf("Auth code %s marked as used (deleted) in DTS.", codeStr)
	return nil
}

// DeleteExpiredAuthCodes is a no-op for the DTS implementation because DTS handles TTL internally.
// The background cleanup routine in the DTS service removes expired items.
func (r *dtsAuthCodeRepository) DeleteExpiredAuthCodes(ctx context.Context) error {
	log.Println("DeleteExpiredAuthCodes is a no-op for DTS-backed repository; DTS handles TTL cleanup automatically.")
	return nil
}
