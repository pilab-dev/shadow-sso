package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// IdPManagementServer implements the ssov1connect.IdPManagementServiceHandler interface.
type IdPManagementServer struct {
	ssov1connect.UnimplementedIdPManagementServiceHandler
	idpRepo domain.IdPRepository
	// secretEncrypterDecrypter tool // For oidc_client_secret
}

// NewIdPManagementServer creates a new IdPManagementServer.
func NewIdPManagementServer(idpRepo domain.IdPRepository) *IdPManagementServer {
	return &IdPManagementServer{
		idpRepo: idpRepo,
	}
}

// Helper to convert domain.IdentityProvider to ssov1.IdentityProviderProto
func toIdPProto(idp *domain.IdentityProvider, includeSecret bool) *ssov1.IdentityProviderProto {
	if idp == nil {
		return nil
	}
	proto := &ssov1.IdentityProviderProto{
		Id:        idp.ID,
		Name:      idp.Name,
		IsEnabled: idp.IsEnabled,

		OidcClientId:  idp.OIDCClientID,
		OidcIssuerUrl: idp.OIDCIssuerURL,
		OidcScopes:    idp.OIDCScopes,

		AttributeMappings: make([]*ssov1.AttributeMappingProto, len(idp.AttributeMappings)),
	}

	// Map domain.IdPType (string) to ssov1.IdPTypeProto (enum)
	switch idp.Type {
	case domain.IdPTypeOIDC:
		proto.Type = ssov1.IdPTypeProto_IDP_TYPE_OIDC
	case domain.IdPTypeSAML:
		proto.Type = ssov1.IdPTypeProto_IDP_TYPE_SAML
	default:
		proto.Type = ssov1.IdPTypeProto_IDP_TYPE_UNSPECIFIED
	}

	if includeSecret { // Only used if caller explicitly needs to show a newly set plain secret
		proto.OidcClientSecret = idp.OIDCClientSecret
	} else {
		// Ensure secret is never sent in GET/LIST responses, even if it's accidentally in the domain model passed.
		// The domain model itself has json:"-" for OIDCClientSecret, so it wouldn't be marshalled to JSON,
		// but for proto conversion, we explicitly omit it unless includeSecret is true.
		// For Add/Update response, the secret is typically not returned, or a message saying "secret set/updated".
		// The IdentityProviderProto field definition has `oidc_client_secret` but it's a server responsibility
		// to not populate it in read operations.
		proto.OidcClientSecret = "" // Always omit unless specifically requested (which is rare for reads)
	}

	for i, am := range idp.AttributeMappings {
		proto.AttributeMappings[i] = &ssov1.AttributeMappingProto{
			ExternalAttributeName: am.ExternalAttributeName,
			LocalUserAttribute:    am.LocalUserAttribute,
		}
	}
	if !idp.CreatedAt.IsZero() {
		proto.CreatedAt = timestamppb.New(idp.CreatedAt)
	}
	if !idp.UpdatedAt.IsZero() {
		proto.UpdatedAt = timestamppb.New(idp.UpdatedAt)
	}
	return proto
}

// Helper to convert ssov1.IdPTypeProto to domain.IdPType string
func fromIdPTypeProto(pt ssov1.IdPTypeProto) domain.IdPType {
	valStr, ok := ssov1.IdPTypeProto_name[int32(pt)]
	if ok && strings.HasPrefix(valStr, "IDP_TYPE_") {
		// Extracts "OIDC" from "IDP_TYPE_OIDC"
		return domain.IdPType(strings.TrimPrefix(valStr, "IDP_TYPE_"))
	}
	return domain.IdPType("") // Invalid or unspecified
}

// AddIdP adds a new IdP configuration.
func (s *IdPManagementServer) AddIdP(ctx context.Context, req *connect.Request[ssov1.AddIdPRequest]) (*connect.Response[ssov1.AddIdPResponse], error) {
	domainIdPType := fromIdPTypeProto(req.Msg.Type)
	if domainIdPType == "" && req.Msg.Type != ssov1.IdPTypeProto_IDP_TYPE_UNSPECIFIED {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid IdP type provided: %s", req.Msg.Type.String()))
	}
	if domainIdPType == "" && req.Msg.Type == ssov1.IdPTypeProto_IDP_TYPE_UNSPECIFIED {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("IdP type must be specified (e.g., OIDC)"))
	}

	domainIdP := &domain.IdentityProvider{
		Name:      req.Msg.Name,
		Type:      domainIdPType,
		IsEnabled: req.Msg.IsEnabled,

		OIDCClientID:     req.Msg.GetOidcClientId(),
		OIDCClientSecret: req.Msg.GetOidcClientSecret(), // Store as provided; encryption should ideally happen here
		OIDCIssuerURL:    req.Msg.GetOidcIssuerUrl(),
		OIDCScopes:       req.Msg.OidcScopes,

		AttributeMappings: make([]domain.AttributeMapping, len(req.Msg.AttributeMappings)),
	}

	for i, amp := range req.Msg.AttributeMappings {
		domainIdP.AttributeMappings[i] = domain.AttributeMapping{
			ExternalAttributeName: amp.ExternalAttributeName,
			LocalUserAttribute:    amp.LocalUserAttribute,
		}
	}

	// TODO: Encrypt OIDCClientSecret before storing if an encryption mechanism is in place.
	// For example:
	// if domainIdP.OIDCClientSecret != "" && s.secretEncrypter != nil {
	//     encryptedSecret, err := s.secretEncrypter.Encrypt(domainIdP.OIDCClientSecret)
	//     if err != nil { /* handle error */ }
	//     domainIdP.OIDCClientSecret = encryptedSecret
	// }

	if err := s.idpRepo.AddIdP(ctx, domainIdP); err != nil {
		log.Error().Err(err).Msg("Failed to add IdP configuration")
		if strings.Contains(err.Error(), "already exists") { // From repo's duplicate check
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("IdP with name '%s' or generated ID already exists", domainIdP.Name))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to add IdP configuration"))
	}

	// Important: Do NOT return the secret in the response after creation.
	return connect.NewResponse(&ssov1.AddIdPResponse{Idp: toIdPProto(domainIdP, false)}), nil
}

// GetIdP retrieves an IdP configuration by its ID.
func (s *IdPManagementServer) GetIdP(ctx context.Context, req *connect.Request[ssov1.GetIdPRequest]) (*connect.Response[ssov1.GetIdPResponse], error) {
	idp, err := s.idpRepo.GetIdPByID(ctx, req.Msg.Id)
	if err != nil {
		log.Warn().Err(err).Str("idpID", req.Msg.Id).Msg("Failed to get IdP by ID")
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("IdP configuration not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve IdP configuration"))
	}
	// TODO: Decrypt OIDCClientSecret if it was encrypted if needed for server logic, but NOT for client response.
	return connect.NewResponse(&ssov1.GetIdPResponse{Idp: toIdPProto(idp, false)}), nil
}

// ListIdPs lists all configured IdPs.
func (s *IdPManagementServer) ListIdPs(ctx context.Context, req *connect.Request[ssov1.ListIdPsRequest]) (*connect.Response[ssov1.ListIdPsResponse], error) {
	dbIdPs, err := s.idpRepo.ListIdPs(ctx, req.Msg.OnlyEnabled)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list IdP configurations")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list IdP configurations"))
	}

	protoIdPs := make([]*ssov1.IdentityProviderProto, len(dbIdPs))
	for i, dbIdP := range dbIdPs {
		protoIdPs[i] = toIdPProto(dbIdP, false) // No secrets in list
	}

	return connect.NewResponse(&ssov1.ListIdPsResponse{Idps: protoIdPs}), nil
}

// UpdateIdP updates an existing IdP configuration.
func (s *IdPManagementServer) UpdateIdP(ctx context.Context, req *connect.Request[ssov1.UpdateIdPRequest]) (*connect.Response[ssov1.UpdateIdPResponse], error) {
	idp, err := s.idpRepo.GetIdPByID(ctx, req.Msg.Id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("IdP configuration not found for update"))
		}
		log.Error().Err(err).Str("idpID", req.Msg.Id).Msg("Failed to retrieve IdP for update")
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to retrieve IdP for update: %w", err))
	}

	// Update fields from request.
	if req.Msg.Name != "" {
		idp.Name = req.Msg.Name
	}
	idp.IsEnabled = req.Msg.IsEnabled // bool is always present, effectively a required field for update

	if req.Msg.OidcClientId != nil {
		idp.OIDCClientID = req.Msg.GetOidcClientId()
	}
	if req.Msg.OidcClientSecret != nil { // If secret is in request, update it
		// TODO: Encrypt OIDCClientSecret if implementing encryption
		idp.OIDCClientSecret = req.Msg.GetOidcClientSecret()
	}
	if req.Msg.OidcIssuerUrl != nil {
		idp.OIDCIssuerURL = req.Msg.GetOidcIssuerUrl()
	}
	if req.Msg.OidcScopes != nil { // Check for presence of field itself for repeated types
		idp.OIDCScopes = req.Msg.OidcScopes // Full replace
	}
	if req.Msg.AttributeMappings != nil {
		idp.AttributeMappings = make([]domain.AttributeMapping, len(req.Msg.AttributeMappings))
		for i, amp := range req.Msg.AttributeMappings {
			idp.AttributeMappings[i] = domain.AttributeMapping{
				ExternalAttributeName: amp.ExternalAttributeName,
				LocalUserAttribute:    amp.LocalUserAttribute,
			}
		}
	}
	// Type is generally not updatable once created.

	// idp.UpdatedAt will be set by the repository method UpdateIdP.

	if err := s.idpRepo.UpdateIdP(ctx, idp); err != nil {
		log.Error().Err(err).Str("idpID", idp.ID).Msg("Failed to update IdP configuration")
		if strings.Contains(err.Error(), "already exists") { // e.g., unique name collision
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("IdP with name '%s' already exists", idp.Name))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update IdP configuration"))
	}
	// Secret should not be in this response.
	return connect.NewResponse(&ssov1.UpdateIdPResponse{Idp: toIdPProto(idp, false)}), nil
}

// DeleteIdP deletes an IdP configuration.
func (s *IdPManagementServer) DeleteIdP(ctx context.Context, req *connect.Request[ssov1.DeleteIdPRequest]) (*connect.Response[emptypb.Empty], error) {
	if err := s.idpRepo.DeleteIdP(ctx, req.Msg.Id); err != nil {
		log.Warn().Err(err).Str("idpID", req.Msg.Id).Msg("Failed to delete IdP configuration")
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("IdP configuration not found for deletion"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete IdP configuration"))
	}
	log.Info().Str("idpID", req.Msg.Id).Msg("IdP configuration deleted successfully")
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// Ensure IdPManagementServer implements the handler interface
var _ ssov1connect.IdPManagementServiceHandler = (*IdPManagementServer)(nil)
