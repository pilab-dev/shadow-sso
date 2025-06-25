package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/dto" // Added DTO import
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Implementation of the new ClientService ---
type ClientServiceImpl struct {
	oauthRepo    OAuthRepository // Contains client methods
	secretHasher PasswordHasher
}

// NewClientServiceImpl creates a new ClientServiceImpl.
func NewClientServiceImpl(oauthRepo OAuthRepository, hasher PasswordHasher) *ClientServiceImpl {
	return &ClientServiceImpl{
		oauthRepo:    oauthRepo,
		secretHasher: hasher,
	}
}

func (s *ClientServiceImpl) RegisterClient(ctx context.Context, req *dto.ClientCreateRequest) (*dto.ClientResponse, string, error) {
	domainClientType := client.ClientType(req.Type)
	if domainClientType != client.Confidential && domainClientType != client.Public {
		return nil, "", errors.New("invalid client type specified")
	}

	domainClient := dto.ToDomainClient(*req) // Mapper creates the base client.Client object
	domainClient.ID = uuid.NewString()       // Generate ID
	domainClient.IsActive = true
	// Timestamps will be set by the repository or before saving

	var plaintextSecretForResponse string
	if domainClient.Type == client.Confidential {
		if req.TokenEndpointAuth == "private_key_jwt" && req.JWKSUri == "" /* && req.JWKS == nil */ {
			// If private_key_jwt is used, a secret is not necessarily generated, unless also allowing client_secret_post etc.
			// For now, if confidential and not using JWT assertion for auth, generate a secret.
		} else if req.TokenEndpointAuth != "private_key_jwt" { // Generate secret if not using JWT auth primarily
			plaintextSecretForResponse = uuid.New().String() // More secure generation needed for production
			hashedSecret, err := s.secretHasher.Hash(plaintextSecretForResponse)
			if err != nil {
				log.Error().Err(err).Msg("Failed to hash client secret during registration")
				return nil, "", errors.New("error processing client secret")
			}
			domainClient.Secret = hashedSecret
		}
	} else { // Public client
		domainClient.Secret = "" // No secret for public clients
		if domainClient.TokenEndpointAuth == "" {
			domainClient.TokenEndpointAuth = "none"
		}
		domainClient.RequirePKCE = true // PKCE should be enforced for public clients
	}

	// Set defaults if not provided
	if len(domainClient.AllowedGrantTypes) == 0 {
		if domainClient.Type == client.Confidential {
			domainClient.AllowedGrantTypes = []string{"authorization_code", "client_credentials", "refresh_token"}
		} else {
			domainClient.AllowedGrantTypes = []string{"authorization_code", "refresh_token"}
		}
	}
	if domainClient.TokenEndpointAuth == "" && domainClient.Type == client.Confidential {
		// Default for confidential if not JWT auth and not explicitly set
		if domainClient.JWKSUri == "" { // Basic assumption
			domainClient.TokenEndpointAuth = "client_secret_basic"
		}
	}

	if err := s.oauthRepo.CreateClient(ctx, domainClient); err != nil {
		log.Error().Err(err).Msg("Service: Failed to create client")
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "E11000") {
			return nil, "", fmt.Errorf("client with this client_id already exists: %w", err)
		}
		return nil, "", fmt.Errorf("failed to register client: %w", err)
	}

	// The domainClient now has CreatedAt/UpdatedAt from the repo
	return dto.FromDomainClient(domainClient), plaintextSecretForResponse, nil
}

func (s *ClientServiceImpl) GetClientByID(ctx context.Context, clientID string) (*dto.ClientResponse, error) {
	domainClient, err := s.oauthRepo.GetClient(ctx, clientID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("client not found with ID %s: %w", clientID, err)
		}
		return nil, fmt.Errorf("failed to retrieve client: %w", err)
	}
	return dto.FromDomainClient(domainClient), nil
}

func (s *ClientServiceImpl) ListClients(ctx context.Context, pageSize int32, pageToken string) ([]*dto.ClientResponse, string, error) {
	domainClients, nextPageToken, err := s.oauthRepo.ListClients(ctx, pageSize, pageToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to list clients: %w", err)
	}
	return dto.FromDomainClients(domainClients), nextPageToken, nil
}

func (s *ClientServiceImpl) UpdateClient(ctx context.Context, clientID string, req *dto.ClientUpdateRequest) (*dto.ClientResponse, error) {
	existingClient, err := s.oauthRepo.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found for update with ID %s: %w", clientID, err)
	}

	// Apply updates from DTO
	if req.Name != nil {
		existingClient.Name = *req.Name
	}
	if req.Description != nil {
		existingClient.Description = *req.Description
	}
	if req.RedirectURIs != nil {
		existingClient.RedirectURIs = *req.RedirectURIs
	}
	if req.PostLogoutURIs != nil {
		existingClient.PostLogoutURIs = *req.PostLogoutURIs
	}
	if req.AllowedScopes != nil {
		existingClient.AllowedScopes = *req.AllowedScopes
	}
	if req.AllowedGrantTypes != nil { // Be careful updating grant types
		existingClient.AllowedGrantTypes = *req.AllowedGrantTypes
	}
	if req.TokenEndpointAuth != nil { // Be careful updating auth method
		existingClient.TokenEndpointAuth = *req.TokenEndpointAuth
	}
	if req.JWKSUri != nil {
		existingClient.JWKSUri = *req.JWKSUri
	}
	// JWKS content update would be more complex
	if req.Contacts != nil {
		existingClient.Contacts = *req.Contacts
	}
	if req.LogoURI != nil {
		existingClient.LogoURI = *req.LogoURI
	}
	if req.PolicyURI != nil {
		existingClient.PolicyURI = *req.PolicyURI
	}
	if req.TermsURI != nil {
		existingClient.TermsURI = *req.TermsURI
	}
	if req.RequireConsent != nil {
		existingClient.RequireConsent = *req.RequireConsent
	}
	if req.RequirePKCE != nil {
		existingClient.RequirePKCE = *req.RequirePKCE
	}
	if req.IsActive != nil {
		existingClient.IsActive = *req.IsActive
	}
	// existingClient.UpdatedAt will be set by repo

	if err := s.oauthRepo.UpdateClient(ctx, existingClient); err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}
	return dto.FromDomainClient(existingClient), nil
}

func (s *ClientServiceImpl) DeleteClient(ctx context.Context, clientID string) error {
	if err := s.oauthRepo.DeleteClient(ctx, clientID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("client not found for deletion ID %s: %w", clientID, err)
		}
		return fmt.Errorf("failed to delete client: %w", err)
	}
	return nil
}

// --- ClientManagementServer (RPC Handler) ---
type ClientManagementServer struct {
	ssov1connect.UnimplementedClientManagementServiceHandler
	service ClientServiceInternal // Use the new internal service
}

// NewClientManagementServer creates a new ClientManagementServer RPC handler.
func NewClientManagementServer(service ClientServiceInternal) *ClientManagementServer {
	return &ClientManagementServer{
		service: service,
	}
}

// Helper to map client.ClientType (string) to ssov1.ClientTypeProto
func domainToProtoClientType(domainType client.ClientType) ssov1.ClientTypeProto {
	switch domainType {
	case client.Confidential:
		return ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL
	case client.Public:
		return ssov1.ClientTypeProto_CLIENT_TYPE_PUBLIC
	default:
		return ssov1.ClientTypeProto_CLIENT_TYPE_UNSPECIFIED
	}
}

// Helper to map ssov1.ClientTypeProto to client.ClientType (string)
func protoToDomainClientType(protoType ssov1.ClientTypeProto) client.ClientType {
	switch protoType {
	case ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL:
		return client.Confidential
	case ssov1.ClientTypeProto_CLIENT_TYPE_PUBLIC:
		return client.Public
	default:
		return "" // Invalid or unspecified
	}
}

// Helper to convert *dto.ClientResponse to ssov1.ClientProto
func dtoClientResponseToProto(dtoResp *dto.ClientResponse) *ssov1.ClientProto {
	if dtoResp == nil {
		return nil
	}
	proto := &ssov1.ClientProto{
		ClientId:                dtoResp.ID, // Note field name change ClientId vs ID
		ClientType:              domainToProtoClientType(dtoResp.Type),
		ClientName:              dtoResp.Name,
		Description:             dtoResp.Description,
		RedirectUris:            dtoResp.RedirectURIs,
		PostLogoutRedirectUris:  dtoResp.PostLogoutURIs,
		AllowedScopes:           dtoResp.AllowedScopes,
		AllowedGrantTypes:       dtoResp.AllowedGrantTypes,
		TokenEndpointAuthMethod: dtoResp.TokenEndpointAuth,
		JwksUri:                 dtoResp.JWKSUri,
		Contacts:                dtoResp.Contacts,
		LogoUri:                 dtoResp.LogoURI,
		PolicyUri:               dtoResp.PolicyURI,
		TermsUri:                dtoResp.TermsURI,
		RequireConsent:          dtoResp.RequireConsent,
		RequirePkce:             dtoResp.RequirePKCE,
		IsActive:                dtoResp.IsActive,
		// ClientSecret is not part of ClientResponse DTO
	}
	// JWKS content omitted for brevity, similar to original toClientProto
	if !dtoResp.CreatedAt.IsZero() {
		proto.CreatedAt = timestamppb.New(dtoResp.CreatedAt)
	}
	if !dtoResp.UpdatedAt.IsZero() {
		proto.UpdatedAt = timestamppb.New(dtoResp.UpdatedAt)
	}
	// LastUsed is not in ssov1.ClientProto, but was in dtoClientResponse. Omit if not in proto.
	return proto
}

func (s *ClientManagementServer) RegisterClient(ctx context.Context, req *connect.Request[ssov1.RegisterClientRequest]) (*connect.Response[ssov1.RegisterClientResponse], error) {
	dtoReq := &dto.ClientCreateRequest{
		Name:              req.Msg.ClientName,
		Type:              string(protoToDomainClientType(req.Msg.ClientType)),
		Description:       req.Msg.Description,
		RedirectURIs:      req.Msg.RedirectUris,
		PostLogoutURIs:    req.Msg.PostLogoutRedirectUris,
		AllowedScopes:     req.Msg.AllowedScopes,
		AllowedGrantTypes: req.Msg.AllowedGrantTypes,
		TokenEndpointAuth: req.Msg.TokenEndpointAuthMethod,
		JWKSUri:           req.Msg.JwksUri,
		Contacts:          req.Msg.Contacts,
		LogoURI:           req.Msg.LogoUri,
		PolicyURI:         req.Msg.PolicyUri,
		TermsURI:          req.Msg.TermsUri,
		RequireConsent:    req.Msg.RequireConsent,
		RequirePKCE:       req.Msg.RequirePkce, // Added from Client structure
	}
	// JWKS content mapping from req.Msg.JwksContent to dtoReq would be here

	dtoResp, plaintextSecret, err := s.service.RegisterClient(ctx, dtoReq)
	if err != nil {
		// TODO: Map service errors to connect errors
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("client registration failed: %w", err))
	}

	responseProto := dtoClientResponseToProto(dtoResp)
	if plaintextSecret != "" { // Add plaintext secret to response if generated
		responseProto.ClientSecret = plaintextSecret
	}

	return connect.NewResponse(&ssov1.RegisterClientResponse{Client: responseProto}), nil
}

func (s *ClientManagementServer) GetClient(ctx context.Context, req *connect.Request[ssov1.GetClientRequest]) (*connect.Response[ssov1.GetClientResponse], error) {
	dtoResp, err := s.service.GetClientByID(ctx, req.Msg.ClientId)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ssov1.GetClientResponse{Client: dtoClientResponseToProto(dtoResp)}), nil
}

func (s *ClientManagementServer) ListClients(ctx context.Context, req *connect.Request[ssov1.ListClientsRequest]) (*connect.Response[ssov1.ListClientsResponse], error) {
	dtoResps, nextPageToken, err := s.service.ListClients(ctx, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	protoClients := make([]*ssov1.ClientProto, len(dtoResps))
	for i, dtoResp := range dtoResps {
		protoClients[i] = dtoClientResponseToProto(dtoResp)
	}
	return connect.NewResponse(&ssov1.ListClientsResponse{Clients: protoClients, NextPageToken: nextPageToken}), nil
}

func (s *ClientManagementServer) UpdateClient(ctx context.Context, req *connect.Request[ssov1.UpdateClientRequest]) (*connect.Response[ssov1.UpdateClientResponse], error) {
	if req.Msg.ClientId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("client_id is required for update"))
	}
	dtoUpdateReq := &dto.ClientUpdateRequest{
		// Simplified mapping for now. Production would use FieldMasks.
		// Assumes if a value is set in proto request, it's intended for update.
	}
	if req.Msg.ClientName != "" { // This check is problematic for clearing a name. FieldMask is better.
		dtoUpdateReq.Name = &req.Msg.ClientName
	}
	// Map other fields from req.Msg to dtoUpdateReq, using pointers for optionality
	// Example:
	// if req.Msg.Description != "" { dtoUpdateReq.Description = &req.Msg.Description }
	// if req.Msg.RedirectUris != nil { dtoUpdateReq.RedirectURIs = &req.Msg.RedirectUris} ... etc.
	// For this refactor, we'll assume the DTO is populated sufficiently for the service call.
	// The ssov1.UpdateClientRequest structure and how it indicates field presence is key here.
	// For now, this mapping remains conceptual for many fields.

	// A more complete mapping based on ssov1.UpdateClientRequest fields:
	dtoUpdateReq.Name = &req.Msg.ClientName
	dtoUpdateReq.Description = &req.Msg.Description
	dtoUpdateReq.RedirectURIs = &req.Msg.RedirectUris
	dtoUpdateReq.PostLogoutURIs = &req.Msg.PostLogoutRedirectUris
	dtoUpdateReq.AllowedScopes = &req.Msg.AllowedScopes
	dtoUpdateReq.JWKSUri = &req.Msg.JwksUri
	dtoUpdateReq.Contacts = &req.Msg.Contacts
	dtoUpdateReq.LogoURI = &req.Msg.LogoUri
	dtoUpdateReq.PolicyURI = &req.Msg.PolicyUri
	dtoUpdateReq.TermsURI = &req.Msg.TermsUri
	dtoUpdateReq.RequireConsent = &req.Msg.RequireConsent
	dtoUpdateReq.IsActive = &req.Msg.IsActive
	// Fields like ClientType, AllowedGrantTypes, TokenEndpointAuthMethod, RequirePKCE are typically not updated or handled with care.
	// ClientSecret is not updated here.

	dtoResp, err := s.service.UpdateClient(ctx, req.Msg.ClientId, dtoUpdateReq)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ssov1.UpdateClientResponse{Client: dtoClientResponseToProto(dtoResp)}), nil
}

func (s *ClientManagementServer) DeleteClient(ctx context.Context, req *connect.Request[ssov1.DeleteClientRequest]) (*connect.Response[emptypb.Empty], error) {
	if req.Msg.ClientId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("client_id is required"))
	}
	err := s.service.DeleteClient(ctx, req.Msg.ClientId)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// Ensure ClientManagementServer implements the handler interface
var _ ssov1connect.ClientManagementServiceHandler = (*ClientManagementServer)(nil)
