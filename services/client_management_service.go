package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/client" // Added domain import
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ClientManagementServer implements the ssov1connect.ClientManagementServiceHandler interface.
type ClientManagementServer struct {
	ssov1connect.UnimplementedClientManagementServiceHandler
	clientRepo   client.ClientStore // Changed to domain.OAuthRepository
	secretHasher PasswordHasher
}

// NewClientManagementServer creates a new ClientManagementServer.
func NewClientManagementServer(clientRepo client.ClientStore, hasher PasswordHasher) *ClientManagementServer { // Changed to domain.OAuthRepository
	return &ClientManagementServer{
		clientRepo:   clientRepo,
		secretHasher: hasher,
	}
}

// Helper to map ssov1.ClientTypeProto to client.ClientType (string)
func fromClientTypeProto(protoType ssov1.ClientTypeProto) client.ClientType {
	switch protoType {
	case ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL:
		return client.Confidential
	case ssov1.ClientTypeProto_CLIENT_TYPE_PUBLIC:
		return client.Public
	default:
		// Return an empty ClientType, let validation handle it if it's an issue.
		// Or, return an error if unspecified is not allowed.
		return ""
	}
}

// Helper to map client.ClientType (string) to ssov1.ClientTypeProto
func toClientTypeProto(domainType client.ClientType) ssov1.ClientTypeProto {
	switch domainType {
	case client.Confidential:
		return ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL
	case client.Public:
		return ssov1.ClientTypeProto_CLIENT_TYPE_PUBLIC
	default:
		return ssov1.ClientTypeProto_CLIENT_TYPE_UNSPECIFIED
	}
}

// Helper to convert *client.Client to ssov1.ClientProto
func toClientProto(c *client.Client, includeSecret bool) *ssov1.ClientProto {
	if c == nil {
		return nil
	}
	proto := &ssov1.ClientProto{
		ClientId:                c.ID,
		ClientType:              toClientTypeProto(c.Type),
		ClientName:              c.Name,
		Description:             c.Description,
		RedirectUris:            c.RedirectURIs,
		PostLogoutRedirectUris:  c.PostLogoutURIs,
		AllowedScopes:           c.AllowedScopes,
		AllowedGrantTypes:       c.AllowedGrantTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuth,
		JwksUri:                 c.JWKSUri,
		Contacts:                c.Contacts,
		LogoUri:                 c.LogoURI,
		PolicyUri:               c.PolicyURI,
		TermsUri:                c.TermsURI,
		RequireConsent:          c.RequireConsent,
		RequirePkce:             c.RequirePKCE,
		IsActive:                c.IsActive,

		// LDAP Attribute Mapping Fields (assuming they exist on ssov1.ClientProto)
		ClientLdapAttributeEmail:      c.ClientLDAPAttributeEmail,
		ClientLdapAttributeFirstName:  c.ClientLDAPAttributeFirstName,
		ClientLdapAttributeLastName:   c.ClientLDAPAttributeLastName,
		ClientLdapAttributeGroups:     c.ClientLDAPAttributeGroups,
		ClientLdapCustomClaimsMapping: c.ClientLDAPCustomClaimsMapping,
	}
	if c.JWKS != nil && len(c.JWKS.Keys) > 0 {
		proto.Jwks = &ssov1.JWKSProto{Keys: make([]*ssov1.JSONWebKeyProto, len(c.JWKS.Keys))}
		for i, key := range c.JWKS.Keys {
			proto.Jwks.Keys[i] = &ssov1.JSONWebKeyProto{
				Kid: key.Kid, Kty: key.Kty, Alg: key.Alg, Use: key.Use, N: key.N, E: key.E,
			}
		}
	}
	if includeSecret {
		proto.ClientSecret = c.Secret // This is the PLAINTEXT secret for RegisterClientResponse
	}
	if !c.CreatedAt.IsZero() {
		proto.CreatedAt = timestamppb.New(c.CreatedAt)
	}
	if !c.UpdatedAt.IsZero() {
		proto.UpdatedAt = timestamppb.New(c.UpdatedAt)
	}
	return proto
}

// RegisterClient registers a new OAuth2 client.
func (s *ClientManagementServer) RegisterClient(ctx context.Context, req *connect.Request[ssov1.RegisterClientRequest]) (*connect.Response[ssov1.RegisterClientResponse], error) {
	domainClientType := fromClientTypeProto(req.Msg.ClientType)
	if domainClientType == "" { // fromClientTypeProto returns empty string for unspecified/invalid
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid client type specified"))
	}

	newClient := &client.Client{ // Using the canonical client.Client
		ID:                uuid.NewString(),
		Type:              domainClientType,
		Name:              req.Msg.ClientName,
		Description:       req.Msg.Description,
		RedirectURIs:      req.Msg.RedirectUris,
		PostLogoutURIs:    req.Msg.PostLogoutRedirectUris,
		AllowedScopes:     req.Msg.AllowedScopes,
		AllowedGrantTypes: req.Msg.AllowedGrantTypes,
		TokenEndpointAuth: req.Msg.TokenEndpointAuthMethod,
		JWKSUri:           req.Msg.JwksUri,
		// TODO: Map req.Msg.JwksContent to newClient.JWKS if provided in proto
		Contacts:       req.Msg.Contacts,
		LogoURI:        req.Msg.LogoUri,
		PolicyURI:      req.Msg.PolicyUri,
		TermsURI:       req.Msg.TermsUri,
		RequireConsent: req.Msg.RequireConsent,
		IsActive:       true,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),

		// Populate LDAP mapping fields from request (assuming fields exist on req.Msg or req.Msg.Client)
		// Actual field names on req.Msg depend on protobuf definition.
		ClientLDAPAttributeEmail:      req.Msg.GetClientLdapAttributeEmail(),
		ClientLDAPAttributeFirstName:  req.Msg.GetClientLdapAttributeFirstName(),
		ClientLDAPAttributeLastName:   req.Msg.GetClientLdapAttributeLastName(),
		ClientLDAPAttributeGroups:     req.Msg.GetClientLdapAttributeGroups(),
		ClientLDAPCustomClaimsMapping: req.Msg.GetClientLdapCustomClaimsMapping(),
	}

	var plaintextSecretForResponse string
	if newClient.Type == client.Confidential {
		plaintextSecretForResponse = uuid.New().String()
		hashedSecret, err := s.secretHasher.Hash(plaintextSecretForResponse)
		if err != nil {
			log.Error().Err(err).Msg("Failed to hash client secret during registration")
			return nil, connect.NewError(connect.CodeInternal, errors.New("error processing client secret"))
		}
		newClient.Secret = hashedSecret
	} else {
		newClient.Secret = ""
		if newClient.TokenEndpointAuth == "" {
			newClient.TokenEndpointAuth = "none"
		}
		newClient.RequirePKCE = true
	}

	if len(newClient.AllowedGrantTypes) == 0 {
		if newClient.Type == client.Confidential {
			newClient.AllowedGrantTypes = []string{"authorization_code", "client_credentials", "refresh_token"}
		} else {
			newClient.AllowedGrantTypes = []string{"authorization_code", "refresh_token"}
		}
	}
	if newClient.TokenEndpointAuth == "" && newClient.Type == client.Confidential {
		newClient.TokenEndpointAuth = "client_secret_basic"
	}
	if newClient.Type == client.Public { // PKCE should be enforced for public clients
		newClient.RequirePKCE = true
	}

	if err := s.clientRepo.CreateClient(ctx, newClient); err != nil {
		log.Error().Err(err).Msg("Failed to create client in repository")
		// Check for mongo specific duplicate key error if possible, otherwise generic
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "E11000") {
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("client with this client_id already exists"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to register client"))
	}

	responseClientProto := toClientProto(newClient, false)
	if newClient.Type == client.Confidential {
		responseClientProto.ClientSecret = plaintextSecretForResponse
	}

	return connect.NewResponse(&ssov1.RegisterClientResponse{Client: responseClientProto}), nil
}

// GetClient retrieves an OAuth2 client by its ID.
func (s *ClientManagementServer) GetClient(ctx context.Context, req *connect.Request[ssov1.GetClientRequest]) (*connect.Response[ssov1.GetClientResponse], error) {
	dbClient, err := s.clientRepo.GetClient(ctx, req.Msg.ClientId)
	if err != nil {
		log.Warn().Err(err).Str("clientID", req.Msg.ClientId).Msg("Failed to get client from repository")
		if strings.Contains(err.Error(), "not found") { // Basic check
			return nil, connect.NewError(connect.CodeNotFound, errors.New("client not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve client"))
	}
	return connect.NewResponse(&ssov1.GetClientResponse{Client: toClientProto(dbClient, false)}), nil
}

// ListClients lists OAuth2 clients.
func (s *ClientManagementServer) ListClients(ctx context.Context, req *connect.Request[ssov1.ListClientsRequest]) (*connect.Response[ssov1.ListClientsResponse], error) {
	dbClients, err := s.clientRepo.ListClients(ctx, client.ClientFilter{
		Type:     client.Confidential,
		IsActive: false,
		Search:   "",
	})
	if err != nil {
		log.Error().Err(err).Msg("ListClients: repository error")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list clients: %w", err))
	}

	clientProtos := make([]*ssov1.ClientProto, len(dbClients))
	for i, dbClient := range dbClients {
		clientProtos[i] = toClientProto(dbClient, false)
	}

	return connect.NewResponse(&ssov1.ListClientsResponse{
		Clients:       clientProtos,
		NextPageToken: "", // FIXME: implement next page token for pagination
	}), nil
}

// UpdateClient updates an existing OAuth2 client.
func (s *ClientManagementServer) UpdateClient(ctx context.Context, req *connect.Request[ssov1.UpdateClientRequest]) (*connect.Response[ssov1.UpdateClientResponse], error) {
	dbClient, err := s.clientRepo.GetClient(ctx, req.Msg.ClientId)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("client not found for update"))
		}
		log.Error().Err(err).Str("clientID", req.Msg.ClientId).Msg("Failed to retrieve client for update")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve client for update"))
	}

	// Update fields from request.
	// Note: This is a full update of mutable fields based on request.
	// Use google.protobuf.FieldMask for partial updates in a production system.
	dbClient.Name = req.Msg.ClientName
	dbClient.Description = req.Msg.Description
	dbClient.RedirectURIs = req.Msg.RedirectUris
	dbClient.PostLogoutURIs = req.Msg.PostLogoutRedirectUris
	dbClient.AllowedScopes = req.Msg.AllowedScopes
	dbClient.JWKSUri = req.Msg.JwksUri
	// TODO: Update JWKS content if req.Msg.JwksContent is provided
	dbClient.Contacts = req.Msg.Contacts
	dbClient.LogoURI = req.Msg.LogoUri
	dbClient.PolicyURI = req.Msg.PolicyUri
	dbClient.TermsURI = req.Msg.TermsUri
	dbClient.RequireConsent = req.Msg.RequireConsent
	dbClient.IsActive = req.Msg.IsActive

	// Update LDAP attribute mapping fields
	// Assumes proto fields are optional (e.g. using wrapperspb or `optional` keyword)
	// or that providing an empty string means "clear this mapping field".
	// The GetXxx() methods on req.Msg would correspond to fields on ssov1.UpdateClientRequest.
	// If the proto uses primitive types directly, we'd need to check if the flag was set on the CLI
	// and transmit that information, or use FieldMasks.
	// For simplicity, assuming if a field is in the proto for UpdateClientRequest, its value is used.
	// If proto fields for these are pointers (*string, *map[string]string), check for nil.
	// If they are value types, they will always be present; to "unset", they'd be set to empty string/nil map.

	// Example assuming direct value types in proto (or wrappers that default to empty if not set)
	// These Getters might need to be adapted if the fields are nested within an client_config object in the proto.
	if req.Msg.ClientLdapAttributeEmail != "" || (req.Msg.ClientLdapAttributeEmail == "") { // Simplified: assumes direct field or use fieldmask
		dbClient.ClientLDAPAttributeEmail = req.Msg.GetClientLdapAttributeEmail()
	}
	if req.Msg.ClientLdapAttributeFirstName != "" || (req.Msg.ClientLdapAttributeFirstName == "") {
		dbClient.ClientLDAPAttributeFirstName = req.Msg.GetClientLdapAttributeFirstName()
	}
	if req.Msg.ClientLdapAttributeLastName != "" || (req.Msg.ClientLdapAttributeLastName == "") {
		dbClient.ClientLDAPAttributeLastName = req.Msg.GetClientLdapAttributeLastName()
	}
	if req.Msg.ClientLdapAttributeGroups != "" || (req.Msg.ClientLdapAttributeGroups == "") {
		dbClient.ClientLDAPAttributeGroups = req.Msg.GetClientLdapAttributeGroups()
	}
	// For map, if the field is present in proto, it means replace.
	// If ClientLdapCustomClaimsMapping is a field in UpdateClientRequest.
	if req.Msg.ClientLdapCustomClaimsMapping != nil { // Check if the map field itself is provided for update
		dbClient.ClientLDAPCustomClaimsMapping = req.Msg.GetClientLdapCustomClaimsMapping()
	}

	// ClientType, AllowedGrantTypes, TokenEndpointAuthMethod, RequirePKCE are generally not updated post-creation or require careful handling.
	// ClientSecret is not updated here; requires a separate "reset secret" flow.
	dbClient.UpdatedAt = time.Now().UTC()

	if err := s.clientRepo.UpdateClient(ctx, dbClient); err != nil {
		log.Error().Err(err).Str("clientID", dbClient.ID).Msg("Failed to update client in repository")
		// Check for mongo specific duplicate key error if Name was made unique and conflicts
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "E11000") {
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("client with this name or other unique attributes already exists"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update client"))
	}
	return connect.NewResponse(&ssov1.UpdateClientResponse{Client: toClientProto(dbClient, false)}), nil
}

// DeleteClient deletes an OAuth2 client.
func (s *ClientManagementServer) DeleteClient(ctx context.Context, req *connect.Request[ssov1.DeleteClientRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.clientRepo.DeleteClient(ctx, req.Msg.ClientId); err != nil {
		log.Warn().Err(err).Str("clientID", req.Msg.ClientId).Msg("Failed to delete client from repository")
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("client not found for deletion"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete client"))
	}
	log.Info().Str("clientID", req.Msg.ClientId).Msg("Client deleted successfully")
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// Ensure ClientManagementServer implements the handler interface
var _ ssov1connect.ClientManagementServiceHandler = (*ClientManagementServer)(nil)
