package dtsclient

import (
	"context"
	"log"
	"time"
	"strings"

	"github.com/pilab-dev/ssso/domain"
	dtsv1 "github.com/pilab-dev/ssso/gen/proto/dts/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// dtsTokenRepository implements parts of domain.TokenRepository, focusing on refresh tokens stored in DTS.
// Other token types (like access tokens if they are self-contained JWTs) might not be handled by this specific repository.
type dtsTokenRepository struct {
	client *Client
	// Other repositories like AuthorizationCodeRepository, PkceRepository, DeviceAuthorizationRepository
	// are expected to be separate and injected where needed. This struct focuses on TokenRepository aspects.
}

// NewDTSTokenRepository creates a new DTS-backed TokenRepository.
// Note: This repository primarily handles refresh tokens via DTS.
// Access tokens are generally not stored in DTS if they are self-contained (e.g., JWTs).
func NewDTSTokenRepository(client *Client) domain.TokenRepository {
	if client == nil {
		log.Fatal("DTS client cannot be nil for NewDTSTokenRepository")
	}
	return &dtsTokenRepository{client: client}
}

// --- Helper functions for conversion ---

func domainTokenToProtoRefreshToken(token *domain.Token) *dtsv1.RefreshToken {
	if token == nil || token.TokenType != domain.TokenTypeRefreshToken { // Ensure it's a refresh token
		return nil
	}
	// Extract claims and session_id if they are available in a structured way in domain.Token
	// For now, assuming they are not directly available or are part of a generic field not mapped.
	// Roles could be part of claims.
	return &dtsv1.RefreshToken{
		Token:     token.TokenValue,
		ClientId:  token.ClientID,
		UserId:    token.UserID,
		Scope:     token.Scope,
		ExpiresAt: timestamppb.New(token.ExpiresAt),
		// SessionId: // Needs mapping if available in domain.Token
		// Claims:    // Needs mapping if available in domain.Token
	}
}

func protoRefreshTokenToDomainToken(protoRT *dtsv1.RefreshToken) *domain.Token {
	if protoRT == nil {
		return nil
	}
	// CreatedAt, LastUsedAt, IsRevoked, Issuer, Roles are not directly in dtsv1.RefreshToken
	// IsRevoked is true if not found / deleted from DTS. If found, it's not revoked.
	return &domain.Token{
		// ID: // Not directly stored/retrieved unless token value is used as ID
		TokenValue: protoRT.Token,
		TokenType:  domain.TokenTypeRefreshToken,
		ClientID:   protoRT.ClientId,
		UserID:     protoRT.UserId,
		Scope:      protoRT.Scope,
		ExpiresAt:  protoRT.ExpiresAt.AsTime(),
		IsRevoked:  false, // If we get it from DTS, it's not revoked
		// CreatedAt, LastUsedAt, Issuer, Roles need to be sourced differently if required
	}
}

func protoRefreshTokenToDomainTokenInfo(protoRT *dtsv1.RefreshToken) *domain.TokenInfo {
	if protoRT == nil {
		return nil
	}
	// IssuedAt, Roles not directly in dtsv1.RefreshToken
	return &domain.TokenInfo{
		// ID: // Not directly stored/retrieved
		TokenType: domain.TokenTypeRefreshToken,
		ClientID:  protoRT.ClientId,
		UserID:    protoRT.UserId,
		Scope:     protoRT.Scope,
		ExpiresAt: protoRT.ExpiresAt.AsTime(),
		IsRevoked: false, // If we get it from DTS, it's not revoked
		// IssuedAt: // Needs to be sourced differently, perhaps from CreatedAt if that was stored
		// Roles:    // Could come from claims if claims were parsed
	}
}


// --- TokenRepository Interface Implementation ---

// StoreToken stores token details in DTS. This implementation primarily handles refresh tokens.
// If other token types need to be stored in DTS, this method would need extension,
// or separate repositories should be used.
func (r *dtsTokenRepository) StoreToken(ctx context.Context, token *domain.Token) error {
	if token == nil {
		return status.Error(codes.InvalidArgument, "token cannot be nil")
	}

	if token.TokenType == domain.TokenTypeRefreshToken {
		protoRT := domainTokenToProtoRefreshToken(token)
		if protoRT == nil {
			return status.Error(codes.InvalidArgument, "failed to convert domain.Token to dtsv1.RefreshToken, ensure TokenType is correct")
		}
		if protoRT.ExpiresAt.AsTime().Before(time.Now()) || protoRT.ExpiresAt.AsTime().IsZero() {
			return status.Error(codes.InvalidArgument, "refresh token is already expired or has invalid expiration")
		}

		req := &dtsv1.StoreRefreshTokenRequest{RefreshToken: protoRT}
		_, err := r.client.DTS.StoreRefreshToken(ctx, req)
		if err != nil {
			log.Printf("Error storing refresh token %s to DTS: %v", token.TokenValue, err)
			return status.Errorf(codes.Internal, "failed to store refresh token in DTS: %v", err)
		}
		log.Printf("Refresh token %s (details) stored in DTS.", token.TokenValue)
		return nil
	}

	log.Printf("StoreToken: Token type '%s' is not handled by this DTS repository. Token value: %s...", token.TokenType, token.TokenValue[:min(10, len(token.TokenValue))])
	return status.Errorf(codes.Unimplemented, "StoreToken for token type '%s' is not implemented by DTS token repository", token.TokenType)
}

// GetAccessToken retrieves access token details. Not typically stored in DTS if JWTs.
func (r *dtsTokenRepository) GetAccessToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	log.Printf("GetAccessToken for DTS: Access tokens are typically not stored in DTS. Token value: %s...", tokenValue[:min(10, len(tokenValue))])
	return nil, status.Error(codes.Unimplemented, "GetAccessToken is not implemented by DTS token repository as access tokens are not typically stored in DTS")
}

// GetRefreshToken retrieves refresh token details from DTS.
func (r *dtsTokenRepository) GetRefreshToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	if tokenValue == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token value cannot be empty")
	}
	req := &dtsv1.GetRefreshTokenRequest{Token: tokenValue}
	protoRT, err := r.client.DTS.GetRefreshToken(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("Refresh token %s not found in DTS.", tokenValue)
			return nil, nil // Standard behavior for not found
		}
		log.Printf("Error getting refresh token %s from DTS: %v", tokenValue, err)
		return nil, status.Errorf(codes.Internal, "failed to get refresh token from DTS: %v", err)
	}

	domainToken := protoRefreshTokenToDomainToken(protoRT)
	if domainToken.ExpiresAt.Before(time.Now()) {
		log.Printf("Refresh token %s retrieved from DTS but is expired.", tokenValue)
		return nil, nil // Treat as not found if expired
	}
	return domainToken, nil
}

// GetRefreshTokenInfo retrieves refresh token metadata from DTS.
func (r *dtsTokenRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) {
	if tokenValue == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token value cannot be empty")
	}
	// This is similar to GetRefreshToken, but returns TokenInfo
	req := &dtsv1.GetRefreshTokenRequest{Token: tokenValue}
	protoRT, err := r.client.DTS.GetRefreshToken(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Printf("Refresh token info for %s not found in DTS.", tokenValue)
			return nil, nil
		}
		log.Printf("Error getting refresh token info for %s from DTS: %v", tokenValue, err)
		return nil, status.Errorf(codes.Internal, "failed to get refresh token info: %v", err)
	}

	tokenInfo := protoRefreshTokenToDomainTokenInfo(protoRT)
	if tokenInfo.ExpiresAt.Before(time.Now()) {
		log.Printf("Refresh token info for %s retrieved from DTS but token is expired.", tokenValue)
		return nil, nil // Treat as not found if expired
	}
	return tokenInfo, nil
}

// GetAccessTokenInfo retrieves access token metadata. Not typically stored in DTS.
// If AccessTokenMetadata is stored in DTS for introspection, this method could be implemented.
func (r *dtsTokenRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) {
	// Check if tokenValue is a hash or the actual token based on how AccessTokenMetadata is stored
	// For now, assuming it's not implemented for DTS if access tokens are self-contained.
	// If AccessTokenMetadata from dts.proto is used, this would call GetAccessTokenMetadata.
	// The tokenValue here would likely be a hash of the access token.

	// Example if using AccessTokenMetadata store:
	// tokenHash := computeHash(tokenValue) // Or however the key is derived
	// req := &dtsv1.GetAccessTokenMetadataRequest{TokenHash: tokenHash}
	// metadata, err := r.client.DTS.GetAccessTokenMetadata(ctx, req)
	// if err != nil { ... handle not found ... }
	// return convertAccessTokenMetadataToTokenInfo(metadata), nil

	log.Printf("GetAccessTokenInfo for DTS: Access token metadata is not typically stored in DTS if tokens are self-contained. Token value: %s...", tokenValue[:min(10, len(tokenValue))])
	return nil, status.Error(codes.Unimplemented, "GetAccessTokenInfo for DTS not implemented by default")
}


// RevokeToken marks a token as revoked. For DTS, this usually means deleting it.
// This implementation would try to revoke based on token type if known, or use a generic delete.
func (r *dtsTokenRepository) RevokeToken(ctx context.Context, tokenValue string) error {
	// This is a generic revoke. If we knew the token type, we could be more specific.
	// For refresh tokens, we call DeleteRefreshToken.
	// For access tokens, if metadata is stored, we'd call DeleteAccessTokenMetadata.
	// Since this TokenRepository is primarily for refresh tokens via DTS, we assume it's a refresh token.
	log.Printf("RevokeToken called for token %s. Assuming it's a refresh token for DTS.", tokenValue)
	return r.RevokeRefreshToken(ctx, tokenValue)
}

// RevokeRefreshToken deletes a refresh token's details from DTS.
func (r *dtsTokenRepository) RevokeRefreshToken(ctx context.Context, tokenValue string) error {
	if tokenValue == "" {
		return status.Error(codes.InvalidArgument, "refresh token value cannot be empty for revocation")
	}
	req := &dtsv1.DeleteRefreshTokenRequest{Token: tokenValue}
	_, err := r.client.DTS.DeleteRefreshToken(ctx, req)
	if err != nil {
		// If already deleted (NotFound), it's effectively revoked.
		// However, DTS Delete RPCs return Empty, so we don't get NotFound status directly from the call's response.
		// The error here would be an actual communication or internal DTS error.
		log.Printf("Error revoking (deleting) refresh token %s from DTS: %v", tokenValue, err)
		return status.Errorf(codes.Internal, "failed to revoke refresh token from DTS: %v", err)
	}
	log.Printf("Refresh token %s revoked (deleted) from DTS.", tokenValue)
	return nil
}

// DeleteExpiredTokens is a no-op as DTS handles its own TTL cleanup.
func (r *dtsTokenRepository) DeleteExpiredTokens(ctx context.Context) error {
	log.Println("DeleteExpiredTokens is a no-op for DTS-backed token repository; DTS handles TTL cleanup.")
	return nil
}

// GetTokenInfo provides generic information about a token.
// This could try to guess the token type or try fetching from different DTS stores.
// For simplicity, this DTS adapter will assume it's for refresh tokens if not specified.
func (r *dtsTokenRepository) GetTokenInfo(ctx context.Context, tokenValue string) (*domain.Token, error) {
	// This method is underspecified for a multi-type token store.
	// Assuming it's asking for refresh token primarily for this DTS adapter.
	log.Printf("GetTokenInfo called for token %s. Assuming refresh token for DTS context.", tokenValue)
	return r.GetRefreshToken(ctx, tokenValue)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure dtsTokenRepository implements domain.TokenRepository
var _ domain.TokenRepository = (*dtsTokenRepository)(nil)
