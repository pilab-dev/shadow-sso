package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	// Added for domain to DTO conversion if needed
	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/dto" // Added DTO import
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Implementation of the new IdPService ---
type IdPService struct {
	idpRepo domain.IdPRepository
	// secretEncrypterDecrypter tool // For oidc_client_secret
}

// NewIdPService creates a new IdPServiceImpl.
func NewIdPService(idpRepo domain.IdPRepository) *IdPService {
	return &IdPService{
		idpRepo: idpRepo,
	}
}

func (s *IdPService) AddIdP(ctx context.Context, req *dto.IdentityProviderCreateRequest) (*dto.IdentityProviderResponse, error) {
	domainIdP := dto.ToDomainIdentityProvider(*req)

	// TODO: Encrypt OIDCClientSecret before storing if an encryption mechanism is in place.
	// For example:
	// if domainIdP.OIDCClientSecret != "" && s.secretEncrypter != nil {
	//     encryptedSecret, err := s.secretEncrypter.Encrypt(domainIdP.OIDCClientSecret)
	//     if err != nil { /* handle error */ return nil, fmt.Errorf("failed to encrypt secret: %w", err)}
	//     domainIdP.OIDCClientSecret = encryptedSecret
	// }

	// The repository's AddIdP method is expected to set the ID, CreatedAt, UpdatedAt.
	if err := s.idpRepo.AddIdP(ctx, domainIdP); err != nil {
		log.Error().Err(err).Msg("Failed to add IdP configuration in service")
		if strings.Contains(err.Error(), "already exists") {
			return nil, fmt.Errorf("IdP with name '%s' already exists: %w", domainIdP.Name, err) // Consider custom error type
		}

		return nil, fmt.Errorf("failed to add IdP configuration: %w", err)
	}

	// domainIdP now contains ID, CreatedAt, UpdatedAt from the repo.
	return dto.FromDomainIdentityProvider(domainIdP), nil
}

func (s *IdPService) GetIdPByID(ctx context.Context, idpID string) (*dto.IdentityProviderResponse, error) {
	domainIdP, err := s.idpRepo.GetIdPByID(ctx, idpID)
	if err != nil {
		log.Warn().Err(err).Str("idpID", idpID).Msg("Service: Failed to get IdP by ID")
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("IdP configuration not found with ID %s: %w", idpID, err) // Consider custom error type
		}

		return nil, fmt.Errorf("failed to retrieve IdP configuration: %w", err)
	}

	// TODO: Decrypt OIDCClientSecret if needed for internal logic, but it's omitted in DTO response anyway.
	return dto.FromDomainIdentityProvider(domainIdP), nil
}

func (s *IdPService) GetIdPByName(ctx context.Context, name string) (*dto.IdentityProviderResponse, error) {
	domainIdP, err := s.idpRepo.GetIdPByName(ctx, name) // Assumes repo has this method
	if err != nil {
		log.Warn().Err(err).Str("name", name).Msg("Service: Failed to get IdP by Name")
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("IdP configuration not found with name %s: %w", name, err)
		}

		return nil, fmt.Errorf("failed to retrieve IdP configuration by name: %w", err)
	}

	return dto.FromDomainIdentityProvider(domainIdP), nil
}

func (s *IdPService) ListIdPs(ctx context.Context, onlyEnabled bool) ([]*dto.IdentityProviderResponse, error) {
	domainIdPs, err := s.idpRepo.ListIdPs(ctx, onlyEnabled)
	if err != nil {
		log.Error().Err(err).Msg("Service: Failed to list IdP configurations")
		return nil, fmt.Errorf("failed to list IdP configurations: %w", err)
	}
	return dto.FromDomainIdentityProviders(domainIdPs), nil
}

func (s *IdPService) UpdateIdP(ctx context.Context, idpID string, req *dto.IdentityProviderUpdateRequest) (*dto.IdentityProviderResponse, error) {
	// First, get the existing IdP
	existingIdP, err := s.idpRepo.GetIdPByID(ctx, idpID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("IdP configuration not found for update with ID %s: %w", idpID, err)
		}
		log.Error().Err(err).Str("idpID", idpID).Msg("Service: Failed to retrieve IdP for update")

		return nil, fmt.Errorf("failed to retrieve IdP for update: %w", err)
	}

	// Apply changes from DTO to the domain object
	// The ToDomainIdentityProviderUpdate DTO mapper is a bit simplistic; a more robust approach:
	if req.Name != nil {
		existingIdP.Name = *req.Name
	}

	if req.IsEnabled != nil {
		existingIdP.IsEnabled = *req.IsEnabled
	}

	if req.OIDCClientID != nil {
		existingIdP.OIDCClientID = *req.OIDCClientID
	}

	if req.OIDCClientSecret != nil {
		// TODO: Encrypt OIDCClientSecret if implementing encryption
		existingIdP.OIDCClientSecret = *req.OIDCClientSecret
	} else if req.OIDCClientSecret == nil && existingIdP.OIDCClientSecret != "" {
		// If the request explicitly wants to clear the secret, allow it.
		// However, typically secrets are only updated, not cleared via general update.
		// This depends on desired API behavior. For now, if nil in request, it's not touched.
		// If an empty string is passed, it would be set.
	}

	if req.OIDCIssuerURL != nil {
		existingIdP.OIDCIssuerURL = *req.OIDCIssuerURL
	}

	if req.OIDCScopes != nil {
		existingIdP.OIDCScopes = *req.OIDCScopes
	}

	if req.AttributeMappings != nil {
		existingIdP.AttributeMappings = *req.AttributeMappings
	}
	// Type is generally not updatable.
	// existingIdP.UpdatedAt will be set by the repository method UpdateIdP.

	if err := s.idpRepo.UpdateIdP(ctx, existingIdP); err != nil {
		log.Error().Err(err).Str("idpID", existingIdP.ID).Msg("Service: Failed to update IdP configuration")
		if strings.Contains(err.Error(), "already exists") { // e.g., unique name collision
			return nil, fmt.Errorf("IdP with name '%s' already exists: %w", existingIdP.Name, err)
		}

		return nil, fmt.Errorf("failed to update IdP configuration: %w", err)
	}

	return dto.FromDomainIdentityProvider(existingIdP), nil
}

func (s *IdPService) DeleteIdP(ctx context.Context, idpID string) error {
	if err := s.idpRepo.DeleteIdP(ctx, idpID); err != nil {
		log.Warn().Err(err).Str("idpID", idpID).Msg("Service: Failed to delete IdP configuration")
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("IdP configuration not found for deletion with ID %s: %w", idpID, err)
		}

		return fmt.Errorf("failed to delete IdP configuration: %w", err)
	}
	log.Info().Str("idpID", idpID).Msg("Service: IdP configuration deleted successfully")

	return nil
}

// --- IdPManagementServer (RPC Handler) ---
// It now uses IdPServiceImpl internally.
type IdPManagementServer struct {
	ssov1connect.UnimplementedIdPManagementServiceHandler
	service IdPService // Use the new internal service
}

// NewIdPManagementServer creates a new IdPManagementServer.
// It now expects an IdPServiceInternal implementation.
func NewIdPManagementServer(service IdPService) *IdPManagementServer {
	return &IdPManagementServer{
		service: service,
	}
}

// Helper to convert domain.IdPType (string) to ssov1.IdPTypeProto (enum)
func domainToProtoIdPType(domainType domain.IdPType) ssov1.IdPTypeProto {
	switch domainType {
	case domain.IdPTypeOIDC:
		return ssov1.IdPTypeProto_IDP_TYPE_OIDC
	case domain.IdPTypeSAML:
		return ssov1.IdPTypeProto_IDP_TYPE_SAML
	default:
		return ssov1.IdPTypeProto_IDP_TYPE_UNSPECIFIED
	}
}

// Helper to convert dto.IdentityProviderResponse to ssov1.IdentityProviderProto
func dtoResponseToIdPProto(dtoResp *dto.IdentityProviderResponse) *ssov1.IdentityProviderProto {
	if dtoResp == nil {
		return nil
	}

	proto := &ssov1.IdentityProviderProto{
		Id:                dtoResp.ID,
		Name:              dtoResp.Name,
		Type:              domainToProtoIdPType(dtoResp.Type),
		IsEnabled:         dtoResp.IsEnabled,
		OidcClientId:      dtoResp.OIDCClientID,
		OidcIssuerUrl:     dtoResp.OIDCIssuerURL,
		OidcScopes:        dtoResp.OIDCScopes,
		AttributeMappings: make([]*ssov1.AttributeMappingProto, len(dtoResp.AttributeMappings)),
		// OIDCClientSecret is correctly omitted in IdentityProviderResponse DTO
	}

	for i, am := range dtoResp.AttributeMappings {
		proto.AttributeMappings[i] = &ssov1.AttributeMappingProto{
			ExternalAttributeName: am.ExternalAttributeName,
			LocalUserAttribute:    am.LocalUserAttribute,
		}
	}

	if !dtoResp.CreatedAt.IsZero() {
		proto.CreatedAt = timestamppb.New(dtoResp.CreatedAt)
	}

	if !dtoResp.UpdatedAt.IsZero() {
		proto.UpdatedAt = timestamppb.New(dtoResp.UpdatedAt)
	}

	return proto
}

// Helper to convert ssov1.IdPTypeProto to domain.IdPType string
func protoToDomainIdPType(pt ssov1.IdPTypeProto) domain.IdPType {
	valStr, ok := ssov1.IdPTypeProto_name[int32(pt)]
	if ok && strings.HasPrefix(valStr, "IDP_TYPE_") {
		return domain.IdPType(strings.TrimPrefix(valStr, "IDP_TYPE_"))
	}

	return domain.IdPType("") // Invalid or unspecified
}

// AddIdP RPC handler
func (s *IdPManagementServer) AddIdP(ctx context.Context, req *connect.Request[ssov1.AddIdPRequest]) (*connect.Response[ssov1.AddIdPResponse], error) {
	domainIdPType := protoToDomainIdPType(req.Msg.Type)
	if domainIdPType == "" && req.Msg.Type != ssov1.IdPTypeProto_IDP_TYPE_UNSPECIFIED {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid IdP type provided: %s", req.Msg.Type.String()))
	}

	if domainIdPType == "" && req.Msg.Type == ssov1.IdPTypeProto_IDP_TYPE_UNSPECIFIED {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("IdP type must be specified (e.g., OIDC)"))
	}

	dtoReq := &dto.IdentityProviderCreateRequest{
		Name:              req.Msg.Name,
		Type:              domainIdPType,
		IsEnabled:         req.Msg.IsEnabled,
		OIDCClientID:      req.Msg.GetOidcClientId(),
		OIDCClientSecret:  req.Msg.GetOidcClientSecret(),
		OIDCIssuerURL:     req.Msg.GetOidcIssuerUrl(),
		OIDCScopes:        req.Msg.OidcScopes,
		AttributeMappings: make([]domain.AttributeMapping, len(req.Msg.AttributeMappings)),
	}
	for i, amp := range req.Msg.AttributeMappings {
		dtoReq.AttributeMappings[i] = domain.AttributeMapping{
			ExternalAttributeName: amp.ExternalAttributeName,
			LocalUserAttribute:    amp.LocalUserAttribute,
		}
	}

	dtoResp, err := s.service.AddIdP(ctx, dtoReq)
	if err != nil {
		// TODO: Map service errors to connect errors more granularly
		if strings.Contains(err.Error(), "already exists") {
			return nil, connect.NewError(connect.CodeAlreadyExists, err)
		}

		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&ssov1.AddIdPResponse{Idp: dtoResponseToIdPProto(dtoResp)}), nil
}

// GetIdP RPC handler
func (s *IdPManagementServer) GetIdP(ctx context.Context, req *connect.Request[ssov1.GetIdPRequest]) (*connect.Response[ssov1.GetIdPResponse], error) {
	dtoResp, err := s.service.GetIdPByID(ctx, req.Msg.Id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}

		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&ssov1.GetIdPResponse{Idp: dtoResponseToIdPProto(dtoResp)}), nil
}

// ListIdPs RPC handler
func (s *IdPManagementServer) ListIdPs(ctx context.Context, req *connect.Request[ssov1.ListIdPsRequest]) (*connect.Response[ssov1.ListIdPsResponse], error) {
	dtoResps, err := s.service.ListIdPs(ctx, req.Msg.OnlyEnabled)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	protoIdPs := make([]*ssov1.IdentityProviderProto, len(dtoResps))
	for i, dtoResp := range dtoResps {
		protoIdPs[i] = dtoResponseToIdPProto(dtoResp)
	}

	return connect.NewResponse(&ssov1.ListIdPsResponse{Idps: protoIdPs}), nil
}

// UpdateIdP RPC handler
func (s *IdPManagementServer) UpdateIdP(ctx context.Context, req *connect.Request[ssov1.UpdateIdPRequest]) (*connect.Response[ssov1.UpdateIdPResponse], error) {
	dtoUpdateReq := &dto.IdentityProviderUpdateRequest{}
	// Note: For optional fields in proto3, presence is checked via wrapper types or `has` methods if generated.
	// Here, we assume direct fields; if a field is set (e.g. string not empty, or if proto has optionals), then set pointer in DTO.
	// This mapping from proto update request to DTO update request needs care.
	// If proto fields are not pointers/wrappers, we can't distinguish between empty/default and not set.
	// Assuming for now that if a field is part of ssov1.UpdateIdPRequest, it's intended for update.
	// A better proto design uses field_mask.

	// Simplified mapping:
	if req.Msg.Name != "" { // Assuming empty string means "don't update name" if proto field isn't optional
		dtoUpdateReq.Name = &req.Msg.Name
	}
	// IsEnabled is a bool, always present in proto. Pass as is.
	dtoUpdateReq.IsEnabled = &req.Msg.IsEnabled

	if req.Msg.OidcClientId != nil { // Assumes GetOidcClientId returns value and presence can be checked if it's a wrapper
		val := req.Msg.GetOidcClientId()
		dtoUpdateReq.OIDCClientID = &val
	}

	if req.Msg.OidcClientSecret != nil {
		val := req.Msg.GetOidcClientSecret()
		dtoUpdateReq.OIDCClientSecret = &val
	}

	if req.Msg.OidcIssuerUrl != nil {
		val := req.Msg.GetOidcIssuerUrl()
		dtoUpdateReq.OIDCIssuerURL = &val
	}

	if req.Msg.OidcScopes != nil { // Slices are pointers in Go DTO, check for nil in proto if possible
		// This direct assignment might be problematic if req.Msg.OidcScopes is empty but not nil,
		// vs. nil meaning "don't update".
		// For simplicity, if it's in the request, we assume it's an intended update.
		scopes := req.Msg.OidcScopes
		dtoUpdateReq.OIDCScopes = &scopes
	}

	if req.Msg.AttributeMappings != nil {
		mappings := make([]domain.AttributeMapping, len(req.Msg.AttributeMappings))
		for i, amp := range req.Msg.AttributeMappings {
			mappings[i] = domain.AttributeMapping{
				ExternalAttributeName: amp.ExternalAttributeName,
				LocalUserAttribute:    amp.LocalUserAttribute,
			}
		}

		dtoUpdateReq.AttributeMappings = &mappings
	}

	dtoResp, err := s.service.UpdateIdP(ctx, req.Msg.Id, dtoUpdateReq)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}

		if strings.Contains(err.Error(), "already exists") {
			return nil, connect.NewError(connect.CodeAlreadyExists, err)
		}

		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&ssov1.UpdateIdPResponse{Idp: dtoResponseToIdPProto(dtoResp)}), nil
}

// DeleteIdP RPC handler
func (s *IdPManagementServer) DeleteIdP(ctx context.Context, req *connect.Request[ssov1.DeleteIdPRequest]) (*connect.Response[emptypb.Empty], error) {
	err := s.service.DeleteIdP(ctx, req.Msg.Id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}

		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&emptypb.Empty{}), nil
}

// Ensure IdPManagementServer implements the handler interface
var _ ssov1connect.IdPManagementServiceHandler = (*IdPManagementServer)(nil)
