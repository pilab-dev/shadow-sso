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
	case domain.IdPTypeLDAP: // Added LDAP
		proto.Type = ssov1.IdPTypeProto_IDP_TYPE_LDAP // Assumes this enum value exists in proto
	default:
		proto.Type = ssov1.IdPTypeProto_IDP_TYPE_UNSPECIFIED
	}

	// LDAP specific fields for proto
	// These depend on ssov1.IdentityProviderProto being updated with these fields.
	proto.LdapServerUrl = idp.LDAP.ServerURL
	proto.LdapBindDn = idp.LDAP.BindDN
	// proto.LdapBindPassword is intentionally omitted (secret)
	proto.LdapUserBaseDn = idp.LDAP.UserBaseDN
	proto.LdapUserFilter = idp.LDAP.UserFilter
	proto.LdapAttrUsername = idp.LDAP.AttributeUsername
	proto.LdapAttrEmail = idp.LDAP.AttributeEmail
	proto.LdapAttrFirstname = idp.LDAP.AttributeFirstName
	proto.LdapAttrLastname = idp.LDAP.AttributeLastName
	proto.LdapAttrGroups = idp.LDAP.AttributeGroups
	proto.LdapStarttls = idp.LDAP.StartTLS
	proto.LdapSkipTlsVerify = idp.LDAP.SkipTLSVerify

	if includeSecret { // Only used if caller explicitly needs to show a newly set plain secret
		proto.OidcClientSecret = idp.OIDCClientSecret
		// We generally don't return LDAP bind password even with includeSecret,
		// but if ever needed for a specific flow (unlikely for client response):
		// proto.LdapBindPassword = idp.LDAPBindPassword
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
		typeName := strings.TrimPrefix(valStr, "IDP_TYPE_")
		// Ensure consistent casing with domain.IdPType constants
		switch strings.ToUpper(typeName) {
		case "OIDC":
			return domain.IdPTypeOIDC
		case "SAML":
			return domain.IdPTypeSAML
		case "LDAP":
			return domain.IdPTypeLDAP // Assumes domain.IdPTypeLDAP is "ldap"
		}
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

		// LDAP Fields from proto (names depend on actual proto definition)
		LDAP: domain.LDAPConfig{
			ServerURL:          req.Msg.GetLdapServerUrl(),
			BindDN:             req.Msg.GetLdapBindDn(),
			BindPassword:       req.Msg.GetLdapBindPassword(), // Store as provided; encryption needed
			UserBaseDN:         req.Msg.GetLdapUserBaseDn(),
			UserFilter:         req.Msg.GetLdapUserFilter(),
			AttributeUsername:  req.Msg.GetLdapAttrUsername(),
			AttributeEmail:     req.Msg.GetLdapAttrEmail(),
			AttributeFirstName: req.Msg.GetLdapAttrFirstname(),
			AttributeLastName:  req.Msg.GetLdapAttrLastname(),
			AttributeGroups:    req.Msg.GetLdapAttrGroups(),
			StartTLS:           req.Msg.GetLdapStarttls(),
			SkipTLSVerify:      req.Msg.GetLdapSkipTlsVerify(),
		},

		AttributeMappings: make([]domain.AttributeMapping, len(req.Msg.AttributeMappings)),
	}

	// Validation specific to IdP type
	if domainIdP.Type == domain.IdPTypeOIDC {
		if domainIdP.OIDCClientID == "" || domainIdP.OIDCIssuerURL == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("OIDC ClientID and IssuerURL are required for OIDC IdP"))
		}
	} else if domainIdP.Type == domain.IdPTypeLDAP {
		if domainIdP.LDAP.ServerURL == "" || domainIdP.LDAP.UserBaseDN == "" || domainIdP.LDAP.UserFilter == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("LDAP ServerURL, UserBaseDN, and UserFilter are required for LDAP IdP"))
		}
		// LDAPAttributeUsername, Email, etc., might also be considered essential.
		if domainIdP.LDAP.AttributeUsername == "" {
			log.Warn().Str("idpName", domainIdP.Name).Msg("LDAP IdP configured without LDAPAttributeUsername, 'preferred_username' claim might be unpredictable.")
		}
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

	// Update LDAP fields if present in the request
	// These GetLdap... methods and checks for presence (e.g., using HasXxx or pointers in proto)
	// depend on how the ssov1.UpdateIdPRequest and ssov1.IdentityProviderProto are defined.
	// Assuming direct field access for now, which means if a field is in the proto, it's considered for update.
	// For optional fields in proto, one would check if the field is set.
	if req.Msg.LdapServerUrl != nil { // Example: if proto uses *string for optional fields
		idp.LDAP.ServerURL = req.Msg.GetLdapServerUrl()
	}
	if req.Msg.LdapBindDn != nil {
		idp.LDAP.BindDN = req.Msg.GetLdapBindDn()
	}
	if req.Msg.LdapBindPassword != nil { // Handle secret update
		idp.LDAP.BindPassword = req.Msg.GetLdapBindPassword() // TODO: Encrypt if needed
	}
	if req.Msg.LdapUserBaseDn != nil {
		idp.LDAP.UserBaseDN = req.Msg.GetLdapUserBaseDn()
	}
	if req.Msg.LdapUserFilter != nil {
		idp.LDAP.UserFilter = req.Msg.GetLdapUserFilter()
	}
	if req.Msg.LdapAttrUsername != nil {
		idp.LDAP.AttributeUsername = req.Msg.GetLdapAttrUsername()
	}
	if req.Msg.LdapAttrEmail != nil {
		idp.LDAP.AttributeEmail = req.Msg.GetLdapAttrEmail()
	}
	if req.Msg.LdapAttrFirstname != nil {
		idp.LDAP.AttributeFirstName = req.Msg.GetLdapAttrFirstname()
	}
	if req.Msg.LdapAttrLastname != nil {
		idp.LDAP.AttributeLastName = req.Msg.GetLdapAttrLastname()
	}
	if req.Msg.LdapAttrGroups != nil {
		idp.LDAP.AttributeGroups = req.Msg.GetLdapAttrGroups()
	}
	if req.Msg.LdapStarttls != nil {
		idp.LDAP.StartTLS = req.Msg.GetLdapStarttls()
	}
	if req.Msg.LdapSkipTlsVerify != nil {
		idp.LDAP.SkipTLSVerify = req.Msg.GetLdapSkipTlsVerify()
	}

	// Validation after attempting to merge updates
	if idp.Type == domain.IdPTypeLDAP {
		if idp.LDAP.ServerURL == "" || idp.LDAP.UserBaseDN == "" || idp.LDAP.UserFilter == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("LDAP ServerURL, UserBaseDN, and UserFilter are required for LDAP IdP"))
		}
	}

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
