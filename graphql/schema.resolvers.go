package graphql

// THIS CODE WILL BE UPDATED WITH SCHEMA CHANGES. PREVIOUS IMPLEMENTATION FOR SCHEMA CHANGES WILL BE KEPT IN THE COMMENT SECTION. IMPLEMENTATION FOR UNCHANGED SCHEMA WILL BE KEPT.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
)

type Resolver struct {
	UserRepo                 domain.UserRepository
	UserAttributeRepo        domain.UserAttributeRepository
	UserAttributeMapperRepo   domain.UserAttributeMapperRepository
	ClientRepo               domain.ClientRepository
	SessionRepo             domain.SessionRepository
	IdPRepo                 domain.IdPRepository
	GroupRepo               domain.GroupRepository
	RoleRepo                 domain.RoleRepository
	ProtocolMapperRepo      domain.ProtocolMapperRepository
	AuthFlowRepo            domain.AuthenticationFlowRepository
	ClientScopeRepo         domain.ClientScopeRepository
	RealmSettingsRepo       domain.RealmSettingsRepository
	RealmKeysRepo           domain.RealmKeysRepository
	EmailService           domain.EmailService
	PasswordHasher        domain.PasswordHasher
}

// Executions is the resolver for the executions field.
func (r *authenticationFlowResolver) Executions(ctx context.Context, obj *domain.AuthenticationFlow) ([]domain.AuthenticationExecution, error) {
	return nil, nil
}

// ClientID is the resolver for the clientId field.
func (r *clientResolver) ClientID(ctx context.Context, obj *domain.Client) (string, error) {
	return obj.ID, nil
}

// ClientName is the resolver for the clientName field.
func (r *clientResolver) ClientName(ctx context.Context, obj *domain.Client) (string, error) {
	return obj.Name, nil
}

// Enabled is the resolver for the enabled field.
func (r *clientResolver) Enabled(ctx context.Context, obj *domain.Client) (bool, error) {
	return obj.IsActive, nil
}

// CreatedTimestamp is the resolver for the createdTimestamp field.
func (r *clientResolver) CreatedTimestamp(ctx context.Context, obj *domain.Client) (*time.Time, error) {
	if obj.CreatedAt.IsZero() {
		return nil, nil
	}
	return &obj.CreatedAt, nil
}

// RootURL is the resolver for the rootUrl field.
func (r *clientResolver) RootURL(ctx context.Context, obj *domain.Client) (*string, error) {
	return nil, nil // Domain client doesn't have rootUrl
}

// BaseURL is the resolver for the baseUrl field.
func (r *clientResolver) BaseURL(ctx context.Context, obj *domain.Client) (*string, error) {
	return nil, nil // Domain client doesn't have baseUrl
}

// PostLogoutRedirectUris is the resolver for the postLogoutRedirectUris field.
func (r *clientResolver) PostLogoutRedirectUris(ctx context.Context, obj *domain.Client) ([]string, error) {
	return obj.PostLogoutURIs, nil
}

// WebOrigins is the resolver for the webOrigins field.
func (r *clientResolver) WebOrigins(ctx context.Context, obj *domain.Client) ([]string, error) {
	return nil, nil // Domain client doesn't have web origins
}

// StandardFlowEnabled is the resolver for the standardFlowEnabled field.
func (r *clientResolver) StandardFlowEnabled(ctx context.Context, obj *domain.Client) (bool, error) {
	return contains(obj.AllowedGrantTypes, "authorization_code"), nil
}

// ImplicitFlowEnabled is the resolver for the implicitFlowEnabled field.
func (r *clientResolver) ImplicitFlowEnabled(ctx context.Context, obj *domain.Client) (bool, error) {
	return contains(obj.AllowedGrantTypes, "implicit"), nil
}

// DirectAccessGrantsEnabled is the resolver for the directAccessGrantsEnabled field.
func (r *clientResolver) DirectAccessGrantsEnabled(ctx context.Context, obj *domain.Client) (bool, error) {
	return contains(obj.AllowedGrantTypes, "password"), nil
}

// ServiceAccountsEnabled is the resolver for the serviceAccountsEnabled field.
func (r *clientResolver) ServiceAccountsEnabled(ctx context.Context, obj *domain.Client) (bool, error) {
	return false, nil // Domain client doesn't have this field
}

// PublicClient is the resolver for the publicClient field.
func (r *clientResolver) PublicClient(ctx context.Context, obj *domain.Client) (bool, error) {
	return obj.Type == domain.ClientTypePublic, nil
}

// FrontchannelLogout is the resolver for the frontchannelLogout field.
func (r *clientResolver) FrontchannelLogout(ctx context.Context, obj *domain.Client) (bool, error) {
	return false, nil
}

// FullScopeAllowed is the resolver for the fullScopeAllowed field.
func (r *clientResolver) FullScopeAllowed(ctx context.Context, obj *domain.Client) (bool, error) {
	return true, nil
}

// TokenEndpointAuthMethod is the resolver for the tokenEndpointAuthMethod field.
func (r *clientResolver) TokenEndpointAuthMethod(ctx context.Context, obj *domain.Client) (string, error) {
	return obj.TokenEndpointAuth, nil
}

// ClientType is the resolver for the clientType field.
func (r *clientResolver) ClientType(ctx context.Context, obj *domain.Client) (*string, error) {
	panic("not implemented")
}

// Jwks is the resolver for the jwks field.
func (r *clientResolver) Jwks(ctx context.Context, obj *domain.Client) (*string, error) {
	panic("not implemented")
}

// Roles is the resolver for the roles field.
func (r *clientResolver) Roles(ctx context.Context, obj *domain.Client) ([]domain.Role, error) {
	// Get client roles from the role repository
	roles, err := r.RoleRepo.ListClientRoles(ctx, obj.ID)
	if err != nil {
		return nil, err
	}
	// Convert []*domain.Role to []domain.Role
	result := make([]domain.Role, len(roles))
	for i, role := range roles {
		result[i] = *role
	}
	return result, nil
}

// DefaultRoles is the resolver for the defaultRoles field.
func (r *clientResolver) DefaultRoles(ctx context.Context, obj *domain.Client) ([]domain.Role, error) {
	return nil, nil // Client doesn't have default roles stored
}

// Scope is the resolver for the scope field.
func (r *clientResolver) Scope(ctx context.Context, obj *domain.Client) ([]domain.ClientScope, error) {
	// This would need to list client scopes - not implemented in domain yet
	return nil, nil
}

// OptionalClaims is the resolver for the optionalClaims field.
func (r *clientResolver) OptionalClaims(ctx context.Context, obj *domain.Client) ([]ClaimMapping, error) {
	return nil, nil
}

// Attributes is the resolver for the attributes field.
func (r *clientResolver) Attributes(ctx context.Context, obj *domain.Client) (map[string]any, error) {
	return map[string]any{
		"client_ldap_attribute_email":      obj.ClientLDAPAttributeEmail,
		"client_ldap_attribute_first_name": obj.ClientLDAPAttributeFirstName,
		"client_ldap_attribute_last_name":  obj.ClientLDAPAttributeLastName,
		"client_ldap_attribute_groups":     obj.ClientLDAPAttributeGroups,
	}, nil
}

// RealmRoles is the resolver for the realmRoles field.
func (r *groupResolver) RealmRoles(ctx context.Context, obj *domain.Group) ([]domain.Role, error) {
	// Get roles assigned to this group
	var roles []domain.Role
	for _, roleID := range obj.RealmRoles {
		role, err := r.RoleRepo.GetRoleByID(ctx, roleID)
		if err != nil {
			continue
		}
		roles = append(roles, *role)
	}
	if roles == nil {
		roles = []domain.Role{}
	}
	return roles, nil
}

// ClientRoles is the resolver for the clientRoles field.
func (r *groupResolver) ClientRoles(ctx context.Context, obj *domain.Group, clientID string) ([]domain.Role, error) {
	// Get client roles assigned to this group
	clientRoles, ok := obj.ClientRoles[clientID]
	if !ok {
		return []domain.Role{}, nil
	}
	var roles []domain.Role
	for _, roleID := range clientRoles {
		role, err := r.RoleRepo.GetRoleByID(ctx, roleID)
		if err != nil {
			continue
		}
		roles = append(roles, *role)
	}
	if roles == nil {
		roles = []domain.Role{}
	}
	return roles, nil
}

// Members is the resolver for the members field.
func (r *groupResolver) Members(ctx context.Context, obj *domain.Group) ([]domain.User, error) {
	// Get all members of the group
	var members []domain.User
	for _, memberID := range obj.MemberIDs {
		user, err := r.UserRepo.GetUserByID(ctx, memberID)
		if err != nil {
			continue
		}
		members = append(members, *user)
	}
	if members == nil {
		members = []domain.User{}
	}
	return members, nil
}

// MemberCount is the resolver for the memberCount field.
func (r *groupResolver) MemberCount(ctx context.Context, obj *domain.Group) (int, error) {
	return len(obj.MemberIDs), nil
}

// Subgroups is the resolver for the subgroups field.
func (r *groupResolver) Subgroups(ctx context.Context, obj *domain.Group) ([]domain.Group, error) {
	// Would need to look up subgroups by parent group ID
	return []domain.Group{}, nil
}

// Attributes is the resolver for the attributes field.
func (r *groupResolver) Attributes(ctx context.Context, obj *domain.Group) (map[string]any, error) {
	return map[string]any{
		"path":            obj.Path,
		"parent_group_id": obj.ParentGroupID,
	}, nil
}

// Alias is the resolver for the alias field.
func (r *identityProviderResolver) Alias(ctx context.Context, obj *domain.IdentityProvider) (string, error) {
	return obj.Name, nil
}

// DisplayName is the resolver for the displayName field.
func (r *identityProviderResolver) DisplayName(ctx context.Context, obj *domain.IdentityProvider) (string, error) {
	return obj.Name, nil
}

// ProviderID is the resolver for the providerId field.
func (r *identityProviderResolver) ProviderID(ctx context.Context, obj *domain.IdentityProvider) (string, error) {
	return string(obj.Type), nil
}

// Enabled is the resolver for the enabled field.
func (r *identityProviderResolver) Enabled(ctx context.Context, obj *domain.IdentityProvider) (bool, error) {
	return obj.IsEnabled, nil
}

// TrustEmail is the resolver for the trustEmail field.
func (r *identityProviderResolver) TrustEmail(ctx context.Context, obj *domain.IdentityProvider) (bool, error) {
	return false, nil
}

// StoreToken is the resolver for the storeToken field.
func (r *identityProviderResolver) StoreToken(ctx context.Context, obj *domain.IdentityProvider) (bool, error) {
	return false, nil
}

// AddReadTokenRoleOnCreate is the resolver for the addReadTokenRoleOnCreate field.
func (r *identityProviderResolver) AddReadTokenRoleOnCreate(ctx context.Context, obj *domain.IdentityProvider) (bool, error) {
	return false, nil
}

// AuthenticateDefaultAction is the resolver for the authenticateDefaultAction field.
func (r *identityProviderResolver) AuthenticateDefaultAction(ctx context.Context, obj *domain.IdentityProvider) (bool, error) {
	return false, nil
}

// Config is the resolver for the config field.
func (r *identityProviderResolver) Config(ctx context.Context, obj *domain.IdentityProvider) (map[string]any, error) {
	config := make(map[string]any)
	if obj.OIDCClientID != "" {
		config["clientId"] = obj.OIDCClientID
	}
	if obj.OIDCIssuerURL != "" {
		config["issuerUrl"] = obj.OIDCIssuerURL
	}
	if len(obj.OIDCScopes) > 0 {
		config["scopes"] = obj.OIDCScopes
	}
	// Add LDAP config if present
	if obj.LDAP.ServerURL != "" {
		config["serverUrl"] = obj.LDAP.ServerURL
		config["baseDn"] = obj.LDAP.BaseDN
	}
	return config, nil
}

// SsoEndpoint is the resolver for the ssoEndpoint field.
func (r *identityProviderResolver) SsoEndpoint(ctx context.Context, obj *domain.IdentityProvider) (*string, error) {
	if obj.OIDCIssuerURL != "" {
		return &obj.OIDCIssuerURL, nil
	}
	return nil, nil
}

// CreateUser is the resolver for the createUser field.
func (r *mutationResolver) CreateUser(ctx context.Context, input CreateUserInput) (*domain.User, error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	user := &domain.User{
		Email: input.Email,
	}

	if err := r.UserRepo.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateUser is the resolver for the updateUser field.
func (r *mutationResolver) UpdateUser(ctx context.Context, id string, input UpdateUserInput) (*domain.User, error) {
	user, err := r.UserRepo.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Username != nil {
		// Domain user uses email as username
	}
	if input.Email != nil {
		user.Email = *input.Email
	}
	if input.FirstName != nil {
		user.FirstName = *input.FirstName
	}
	if input.LastName != nil {
		user.LastName = *input.LastName
	}
	if input.Enabled != nil {
		if *input.Enabled {
			user.Status = domain.UserStatusActive
		}
	}
	if input.EmailVerified != nil {
		user.IsEmailVerified = *input.EmailVerified
	}

	if err := r.UserRepo.UpdateUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// DeleteUser is the resolver for the deleteUser field.
func (r *mutationResolver) DeleteUser(ctx context.Context, id string) (bool, error) {
	if err := requireAdmin(ctx); err != nil {
		return false, err
	}

	err := r.UserRepo.DeleteUser(ctx, id)
	return err == nil, err
}

// SendVerificationEmail is the resolver for the sendVerificationEmail field.
func (r *mutationResolver) SendVerificationEmail(ctx context.Context, userID string) (bool, error) {
	user, err := r.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	// Generate verification token if not exists
	if user.EmailVerificationToken == "" {
		token := generateToken()
		user.EmailVerificationToken = token
		if err := r.UserRepo.StoreEmailVerificationToken(ctx, userID, token, time.Now().Add(24*time.Hour)); err != nil {
			return false, err
		}
	}
	verificationLink := "https://example.com/verify?token=" + user.EmailVerificationToken
	err = r.EmailService.SendVerificationEmail(user.Email, user.FirstName, verificationLink)
	return err == nil, err
}

// SendPasswordResetEmail is the resolver for the sendPasswordResetEmail field.
func (r *mutationResolver) SendPasswordResetEmail(ctx context.Context, userID string) (bool, error) {
	user, err := r.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	// Generate password reset token if not exists
	if user.PasswordResetToken == "" {
		token := generateToken()
		user.PasswordResetToken = token
		if err := r.UserRepo.StorePasswordResetToken(ctx, userID, token, time.Now().Add(1*time.Hour)); err != nil {
			return false, err
		}
	}
	resetLink := "https://example.com/reset-password?token=" + user.PasswordResetToken
	err = r.EmailService.SendPasswordResetEmail(user.Email, user.FirstName, resetLink)
	return err == nil, err
}

// ResetPassword is the resolver for the resetPassword field.
func (r *mutationResolver) ResetPassword(ctx context.Context, userID string, newPassword string) (bool, error) {
	if err := requireAdmin(ctx); err != nil {
		return false, err
	}

	user, err := r.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	// Hash the new password
	hashedPassword, err := r.PasswordHasher.Hash(newPassword)
	if err != nil {
		return false, err
	}
	user.PasswordHash = hashedPassword
	// Clear password reset token
	user.PasswordResetToken = ""
	if err := r.UserRepo.UpdateUser(ctx, user); err != nil {
		return false, err
	}
	return true, nil
}

// ExecuteActions is the resolver for the executeActions field.
func (r *mutationResolver) ExecuteActions(ctx context.Context, userID string, actions []string) (bool, error) {
	// Complex action execution - would need implementation
	return false, nil
}

// CreateClient is the resolver for the createClient field.
func (r *mutationResolver) CreateClient(ctx context.Context, input CreateClientInput) (*domain.Client, error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	client := &domain.Client{
		ID:                input.ClientID,
		Name:              input.ClientName,
		RedirectURIs:      input.RedirectUris,
		AllowedScopes:     input.Scope,
		AllowedGrantTypes: input.AllowedGrantTypes,
		IsActive:          input.Enabled != nil && *input.Enabled,
	}

	if err := r.ClientRepo.CreateClient(ctx, client); err != nil {
		return nil, err
	}
	return client, nil
}

// UpdateClient is the resolver for the updateClient field.
func (r *mutationResolver) UpdateClient(ctx context.Context, id string, input UpdateClientInput) (*domain.Client, error) {
	client, err := r.ClientRepo.GetClient(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.ClientName != nil {
		client.Name = *input.ClientName
	}
	if input.Description != nil {
		client.Description = *input.Description
	}
	if input.Enabled != nil {
		client.IsActive = *input.Enabled
	}
	if input.RedirectUris != nil {
		client.RedirectURIs = input.RedirectUris
	}
	if input.AllowedGrantTypes != nil {
		client.AllowedGrantTypes = input.AllowedGrantTypes
	}

	if err := r.ClientRepo.UpdateClient(ctx, client); err != nil {
		return nil, err
	}
	return client, nil
}

// DeleteClient is the resolver for the deleteClient field.
func (r *mutationResolver) DeleteClient(ctx context.Context, id string) (bool, error) {
	if err := requireAdmin(ctx); err != nil {
		return false, err
	}

	err := r.ClientRepo.DeleteClient(ctx, id)
	return err == nil, err
}

// GenerateClientSecret is the resolver for the generateClientSecret field.
func (r *mutationResolver) GenerateClientSecret(ctx context.Context, clientID string) (string, error) {
	if err := requireAdmin(ctx); err != nil {
		return "", err
	}

	client, err := r.ClientRepo.GetClient(ctx, clientID)
	if err != nil {
		return "", err
	}
	secret := generateRandomSecret()
	client.Secret = secret
	if err := r.ClientRepo.UpdateClient(ctx, client); err != nil {
		return "", err
	}
	return secret, nil
}

// GenerateClientKeys is the resolver for the generateClientKeys field.
func (r *mutationResolver) GenerateClientKeys(ctx context.Context, clientID string, keyType *string, keyBits *int) (string, error) {
	client, err := r.ClientRepo.GetClient(ctx, clientID)
	if err != nil {
		return "", err
	}

	kt := "RSA"
	if keyType != nil {
		kt = *keyType
	}
	_ = kt
	bits := 2048
	if keyBits != nil {
		bits = *keyBits
	}

	gen := domain.NewClientKeyGenerator()
	key, err := gen.GenerateRSAKey(bits)
	if err != nil {
		return "", err
	}

	kid := clientID + "-" + generateRandomSecret()[:8]
	jwks := gen.GenerateJWKS(key, kid)

	client.JWKS = jwks
	if err := r.ClientRepo.UpdateClient(ctx, client); err != nil {
		return "", err
	}

	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		return "", err
	}
	return string(jwksJSON), nil
}

// CreateRole is the resolver for the createRole field.
func (r *mutationResolver) CreateRole(ctx context.Context, input CreateRoleInput) (*domain.Role, error) {
	role := &domain.Role{
		Name:       input.Name,
		ClientRole: input.ClientRole != nil && *input.ClientRole,
	}

	if input.Description != nil {
		role.Description = *input.Description
	}
	if input.Composite != nil {
		role.Composite = *input.Composite
	}
	if input.ClientID != nil {
		role.ContainerID = *input.ClientID
	}

	if err := r.RoleRepo.CreateRole(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

// UpdateRole is the resolver for the updateRole field.
func (r *mutationResolver) UpdateRole(ctx context.Context, id string, input UpdateRoleInput) (*domain.Role, error) {
	role, err := r.RoleRepo.GetRoleByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		role.Name = *input.Name
	}
	if input.Description != nil {
		role.Description = *input.Description
	}
	if input.Composite != nil {
		role.Composite = *input.Composite
	}

	if err := r.RoleRepo.UpdateRole(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

// DeleteRole is the resolver for the deleteRole field.
func (r *mutationResolver) DeleteRole(ctx context.Context, id string) (bool, error) {
	err := r.RoleRepo.DeleteRole(ctx, id)
	return err == nil, err
}

// AddRealmRoleToUser is the resolver for the addRealmRoleToUser field.
func (r *mutationResolver) AddRealmRoleToUser(ctx context.Context, userID string, roleID string) (bool, error) {
	user, err := r.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	user.Roles = append(user.Roles, roleID)
	err = r.UserRepo.UpdateUser(ctx, user)
	return err == nil, err
}

// RemoveRealmRoleFromUser is the resolver for the removeRealmRoleFromUser field.
func (r *mutationResolver) RemoveRealmRoleFromUser(ctx context.Context, userID string, roleID string) (bool, error) {
	user, err := r.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	for i, r := range user.Roles {
		if r == roleID {
			user.Roles = append(user.Roles[:i], user.Roles[i+1:]...)
			break
		}
	}
	err = r.UserRepo.UpdateUser(ctx, user)
	return err == nil, err
}

// AddClientRoleToUser is the resolver for the addClientRoleToUser field.
func (r *mutationResolver) AddClientRoleToUser(ctx context.Context, userID string, clientID string, roleID string) (bool, error) {
	// Would need client role storage - not implemented
	return false, nil
}

// RemoveClientRoleFromUser is the resolver for the removeClientRoleFromUser field.
func (r *mutationResolver) RemoveClientRoleFromUser(ctx context.Context, userID string, clientID string, roleID string) (bool, error) {
	// Would need client role storage - not implemented
	return false, nil
}

// AddRealmRoleToGroup is the resolver for the addRealmRoleToGroup field.
func (r *mutationResolver) AddRealmRoleToGroup(ctx context.Context, groupID string, roleID string) (bool, error) {
	err := r.GroupRepo.AddRealmRole(ctx, groupID, roleID)
	return err == nil, err
}

// RemoveRealmRoleFromGroup is the resolver for the removeRealmRoleFromGroup field.
func (r *mutationResolver) RemoveRealmRoleFromGroup(ctx context.Context, groupID string, roleID string) (bool, error) {
	err := r.GroupRepo.RemoveRealmRole(ctx, groupID, roleID)
	return err == nil, err
}

// AddClientRoleToGroup is the resolver for the addClientRoleToGroup field.
func (r *mutationResolver) AddClientRoleToGroup(ctx context.Context, groupID string, clientID string, roleID string) (bool, error) {
	err := r.GroupRepo.AddClientRole(ctx, groupID, clientID, roleID)
	return err == nil, err
}

// RemoveClientRoleFromGroup is the resolver for the removeClientRoleFromGroup field.
func (r *mutationResolver) RemoveClientRoleFromGroup(ctx context.Context, groupID string, clientID string, roleID string) (bool, error) {
	err := r.GroupRepo.RemoveClientRole(ctx, groupID, clientID, roleID)
	return err == nil, err
}

// CreateGroup is the resolver for the createGroup field.
func (r *mutationResolver) CreateGroup(ctx context.Context, input CreateGroupInput) (*domain.Group, error) {
	group := &domain.Group{
		Name: input.Name,
		Path: "/" + input.Name,
	}

	if input.Path != nil {
		group.Path = *input.Path
	}

	if err := r.GroupRepo.CreateGroup(ctx, group); err != nil {
		return nil, err
	}
	return group, nil
}

// UpdateGroup is the resolver for the updateGroup field.
func (r *mutationResolver) UpdateGroup(ctx context.Context, id string, input UpdateGroupInput) (*domain.Group, error) {
	group, err := r.GroupRepo.GetGroupByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		group.Name = *input.Name
	}
	if input.Path != nil {
		group.Path = *input.Path
	}

	if err := r.GroupRepo.UpdateGroup(ctx, group); err != nil {
		return nil, err
	}
	return group, nil
}

// DeleteGroup is the resolver for the deleteGroup field.
func (r *mutationResolver) DeleteGroup(ctx context.Context, id string) (bool, error) {
	if err := requireAdmin(ctx); err != nil {
		return false, err
	}

	err := r.GroupRepo.DeleteGroup(ctx, id)
	return err == nil, err
}

// AddUserToGroup is the resolver for the addUserToGroup field.
func (r *mutationResolver) AddUserToGroup(ctx context.Context, userID string, groupID string) (bool, error) {
	err := r.GroupRepo.AddMember(ctx, groupID, userID)
	return err == nil, err
}

// RemoveUserFromGroup is the resolver for the removeUserFromGroup field.
func (r *mutationResolver) RemoveUserFromGroup(ctx context.Context, userID string, groupID string) (bool, error) {
	err := r.GroupRepo.RemoveMember(ctx, groupID, userID)
	return err == nil, err
}

// CreateIdentityProvider is the resolver for the createIdentityProvider field.
func (r *mutationResolver) CreateIdentityProvider(ctx context.Context, input CreateIdentityProviderInput) (*domain.IdentityProvider, error) {
	idp := &domain.IdentityProvider{
		Name: input.Alias,
	}

	if input.DisplayName != "" {
		idp.Name = input.DisplayName
	}
	if input.ProviderID != "" {
		idp.Type = domain.IdPType(input.ProviderID)
	}
	if input.Enabled != nil {
		idp.IsEnabled = *input.Enabled
	}
	if input.Config != nil {
		// Parse config map for OIDC settings
		if clientID, ok := input.Config["clientId"].(string); ok {
			idp.OIDCClientID = clientID
		}
		if issuerURL, ok := input.Config["issuerUrl"].(string); ok {
			idp.OIDCIssuerURL = issuerURL
		}
	}

	if err := r.IdPRepo.AddIdP(ctx, idp); err != nil {
		return nil, err
	}
	return idp, nil
}

// UpdateIdentityProvider is the resolver for the updateIdentityProvider field.
func (r *mutationResolver) UpdateIdentityProvider(ctx context.Context, id string, input UpdateIdentityProviderInput) (*domain.IdentityProvider, error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	idp, err := r.IdPRepo.GetIdPByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.DisplayName != nil {
		idp.Name = *input.DisplayName
	}
	if input.Enabled != nil {
		idp.IsEnabled = *input.Enabled
	}

	if err := r.IdPRepo.UpdateIdP(ctx, idp); err != nil {
		return nil, err
	}
	return idp, nil
}

// DeleteIdentityProvider is the resolver for the deleteIdentityProvider field.
func (r *mutationResolver) DeleteIdentityProvider(ctx context.Context, id string) (bool, error) {
	if err := requireAdmin(ctx); err != nil {
		return false, err
	}

	err := r.IdPRepo.DeleteIdP(ctx, id)
	return err == nil, err
}

// RevokeSession is the resolver for the revokeSession field.
func (r *mutationResolver) RevokeSession(ctx context.Context, sessionID string) (bool, error) {
	session, err := r.SessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return false, err
	}
	session.IsRevoked = true
	err = r.SessionRepo.UpdateSession(ctx, session)
	return err == nil, err
}

// RevokeAllSessions is the resolver for the revokeAllSessions field.
func (r *mutationResolver) RevokeAllSessions(ctx context.Context, userID string) (bool, error) {
	if err := requireAdmin(ctx); err != nil {
		return false, err
	}

	_, err := r.SessionRepo.DeleteSessionsByUserID(ctx, userID)
	return err == nil, err
}

// LogoutUser is the resolver for the logoutUser field.
func (r *mutationResolver) LogoutUser(ctx context.Context, userID string) (bool, error) {
	_, err := r.SessionRepo.DeleteSessionsByUserID(ctx, userID)
	return err == nil, err
}

// UpdateRealm is the resolver for the updateRealm field.
func (r *mutationResolver) UpdateRealm(ctx context.Context, input UpdateRealmInput) (*domain.RealmSettings, error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}

	settings, err := r.RealmSettingsRepo.GetRealmSettings(ctx)
	if err != nil {
		return nil, err
	}

	if input.DisplayName != nil {
		settings.DisplayName = *input.DisplayName
	}
	if input.Enabled != nil {
		settings.Enabled = *input.Enabled
	}
	if input.RegistrationAllowed != nil {
		settings.RegistrationAllowed = *input.RegistrationAllowed
	}
	if input.LoginWithEmailAllowed != nil {
		settings.LoginWithEmailAllowed = *input.LoginWithEmailAllowed
	}
	if input.ResetPasswordAllowed != nil {
		settings.ResetPasswordAllowed = *input.ResetPasswordAllowed
	}
	if input.BruteForceProtected != nil {
		settings.BruteForceProtected = *input.BruteForceProtected
	}
	if input.SslRequired != nil {
		settings.SSLRequired = *input.SslRequired
	}

	if err := r.RealmSettingsRepo.UpdateRealmSettings(ctx, settings); err != nil {
		return nil, err
	}
	return settings, nil
}

// CreateProtocolMapper is the resolver for the createProtocolMapper field.
func (r *mutationResolver) CreateProtocolMapper(ctx context.Context, input CreateProtocolMapperInput) (*domain.ProtocolMapper, error) {
	mapper := &domain.ProtocolMapper{
		Name:           input.Name,
		Protocol:       input.Protocol,
		ProtocolMapper: input.ProtocolMapper,
		Config:         input.Config,
	}

	if err := r.ProtocolMapperRepo.CreateProtocolMapper(ctx, mapper); err != nil {
		return nil, err
	}
	return mapper, nil
}

// UpdateProtocolMapper is the resolver for the updateProtocolMapper field.
func (r *mutationResolver) UpdateProtocolMapper(ctx context.Context, id string, input UpdateProtocolMapperInput) (*domain.ProtocolMapper, error) {
	mapper, err := r.ProtocolMapperRepo.GetProtocolMapperByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		mapper.Name = *input.Name
	}
	if input.Protocol != nil {
		mapper.Protocol = *input.Protocol
	}
	if input.ProtocolMapper != nil {
		mapper.ProtocolMapper = *input.ProtocolMapper
	}
	if input.Config != nil {
		mapper.Config = input.Config
	}

	if err := r.ProtocolMapperRepo.UpdateProtocolMapper(ctx, mapper); err != nil {
		return nil, err
	}
	return mapper, nil
}

// DeleteProtocolMapper is the resolver for the deleteProtocolMapper field.
func (r *mutationResolver) DeleteProtocolMapper(ctx context.Context, id string) (bool, error) {
	err := r.ProtocolMapperRepo.DeleteProtocolMapper(ctx, id)
	return err == nil, err
}

// CreateUserAttribute is the resolver for the createUserAttribute field.
func (r *mutationResolver) CreateUserAttribute(ctx context.Context, input CreateUserAttributeInput) (*domain.UserAttribute, error) {
	attr := &domain.UserAttribute{
		Name:   input.Name,
		Value:  input.Value,
		UserID: input.UserID,
	}
	if err := r.UserAttributeRepo.CreateAttribute(ctx, attr); err != nil {
		return nil, err
	}
	return attr, nil
}

// UpdateUserAttribute is the resolver for the updateUserAttribute field.
func (r *mutationResolver) UpdateUserAttribute(ctx context.Context, id string, input UpdateUserAttributeInput) (*domain.UserAttribute, error) {
	attr, err := r.UserAttributeRepo.GetAttributeByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		attr.Name = *input.Name
	}
	if input.Value != nil {
		attr.Value = *input.Value
	}

	if err := r.UserAttributeRepo.UpdateAttribute(ctx, attr); err != nil {
		return nil, err
	}
	return attr, nil
}

// DeleteUserAttribute is the resolver for the deleteUserAttribute field.
func (r *mutationResolver) DeleteUserAttribute(ctx context.Context, id string) (bool, error) {
	err := r.UserAttributeRepo.DeleteAttribute(ctx, id)
	return err == nil, err
}

// DeleteUserAttributesByUserID is the resolver for the deleteUserAttributesByUserId field.
func (r *mutationResolver) DeleteUserAttributesByUserID(ctx context.Context, userID string) (bool, error) {
	panic("not implemented")
}

// CreateUserAttributeMapper is the resolver for the createUserAttributeMapper field.
func (r *mutationResolver) CreateUserAttributeMapper(ctx context.Context, input CreateUserAttributeMapperInput) (*domain.UserAttributeMapper, error) {
	mapper := &domain.UserAttributeMapper{
		Name:           input.Name,
		UserAttribute: input.UserAttribute,
		TokenClaimName: input.TokenClaimName,
		TokenType:     input.TokenType,
		MultiValued:   input.MultiValued != nil && *input.MultiValued,
	}
	if input.Protocol != nil {
		mapper.Protocol = *input.Protocol
	}
	if input.ClientID != nil {
		mapper.ClientID = *input.ClientID
	}

	if err := r.UserAttributeMapperRepo.CreateMapper(ctx, mapper); err != nil {
		return nil, err
	}
	return mapper, nil
}

// UpdateUserAttributeMapper is the resolver for the updateUserAttributeMapper field.
func (r *mutationResolver) UpdateUserAttributeMapper(ctx context.Context, id string, input UpdateUserAttributeMapperInput) (*domain.UserAttributeMapper, error) {
	mapper, err := r.UserAttributeMapperRepo.GetMapperByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		mapper.Name = *input.Name
	}
	if input.UserAttribute != nil {
		mapper.UserAttribute = *input.UserAttribute
	}
	if input.TokenClaimName != nil {
		mapper.TokenClaimName = *input.TokenClaimName
	}
	if input.TokenType != nil {
		mapper.TokenType = *input.TokenType
	}
	if input.MultiValued != nil {
		mapper.MultiValued = *input.MultiValued
	}
	if input.Protocol != nil {
		mapper.Protocol = *input.Protocol
	}
	if input.ClientID != nil {
		mapper.ClientID = *input.ClientID
	}

	if err := r.UserAttributeMapperRepo.UpdateMapper(ctx, mapper); err != nil {
		return nil, err
	}
	return mapper, nil
}

// DeleteUserAttributeMapper is the resolver for the deleteUserAttributeMapper field.
func (r *mutationResolver) DeleteUserAttributeMapper(ctx context.Context, id string) (bool, error) {
	err := r.UserAttributeMapperRepo.DeleteMapper(ctx, id)
	return err == nil, err
}

// CreateAuthenticationFlow is the resolver for the createAuthenticationFlow field.
func (r *mutationResolver) CreateAuthenticationFlow(ctx context.Context, input CreateAuthenticationFlowInput) (*domain.AuthenticationFlow, error) {
	flow := &domain.AuthenticationFlow{
		Alias:       input.Alias,
		DisplayName: input.DisplayName,
		BuiltIn:     input.BuiltIn != nil && *input.BuiltIn,
		TopLevel:    input.TopLevel != nil && *input.TopLevel,
	}

	if input.Description != nil {
		flow.Description = *input.Description
	}

	if err := r.AuthFlowRepo.CreateFlow(ctx, flow); err != nil {
		return nil, err
	}
	return flow, nil
}

// UpdateAuthenticationFlow is the resolver for the updateAuthenticationFlow field.
func (r *mutationResolver) UpdateAuthenticationFlow(ctx context.Context, id string, input UpdateAuthenticationFlowInput) (*domain.AuthenticationFlow, error) {
	flow, err := r.AuthFlowRepo.GetFlowByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Alias != nil {
		flow.Alias = *input.Alias
	}
	if input.DisplayName != nil {
		flow.DisplayName = *input.DisplayName
	}
	if input.Description != nil {
		flow.Description = *input.Description
	}

	if err := r.AuthFlowRepo.UpdateFlow(ctx, flow); err != nil {
		return nil, err
	}
	return flow, nil
}

// DeleteAuthenticationFlow is the resolver for the deleteAuthenticationFlow field.
func (r *mutationResolver) DeleteAuthenticationFlow(ctx context.Context, id string) (bool, error) {
	err := r.AuthFlowRepo.DeleteFlow(ctx, id)
	return err == nil, err
}

// UpdateAuthenticationExecutions is the resolver for the updateAuthenticationExecutions field.
func (r *mutationResolver) UpdateAuthenticationExecutions(ctx context.Context, flowID string, executions []AuthenticationExecutionInput) (bool, error) {
	for _, execInput := range executions {
		exec := &domain.AuthenticationExecution{
			FlowID:      flowID,
			Execution:   execInput.Execution,
			Requirement: execInput.Requirement,
		}
		if execInput.ID != nil {
			exec.ID = *execInput.ID
		}
		if err := r.AuthFlowRepo.UpsertExecution(ctx, exec); err != nil {
			return false, err
		}
	}
	return true, nil
}

// SetUserPassword is the resolver for the setUserPassword field.
func (r *mutationResolver) SetUserPassword(ctx context.Context, userID string, password string, temporary bool) (bool, error) {
	if err := requireAdmin(ctx); err != nil {
		return false, err
	}

	user, err := r.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	// Hash the password
	hashedPassword, err := r.PasswordHasher.Hash(password)
	if err != nil {
		return false, err
	}
	user.PasswordHash = hashedPassword
	if err := r.UserRepo.UpdateUser(ctx, user); err != nil {
		return false, err
	}
	return true, nil
}

// DeleteUserCredentials is the resolver for the deleteUserCredentials field.
func (r *mutationResolver) DeleteUserCredentials(ctx context.Context, userID string, credentialID string) (bool, error) {
	// Delete the specified MFA method
	err := r.UserRepo.RemoveMfaMethod(ctx, userID, credentialID)
	return err == nil, err
}

// ResetUserTwoFactor is the resolver for the resetUserTwoFactor field.
func (r *mutationResolver) ResetUserTwoFactor(ctx context.Context, userID string) (bool, error) {
	user, err := r.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	user.IsTwoFactorEnabled = false
	user.EmailMFAEnabled = false
	user.PushMFAEnabled = false
	user.MfaMethods = nil
	return true, r.UserRepo.UpdateUser(ctx, user)
}

// CreateClientScope is the resolver for the createClientScope field.
func (r *mutationResolver) CreateClientScope(ctx context.Context, input CreateClientScopeInput) (*domain.ClientScope, error) {
	scope := &domain.ClientScope{
		Name: input.Name,
	}
	if input.Description != nil {
		scope.Description = *input.Description
	}
	if input.Protocol != nil {
		scope.Protocol = *input.Protocol
	}
	if input.DisplayOrder != nil {
		scope.DisplayOrder = *input.DisplayOrder
	}
	if input.ConsentScreenText != nil {
		scope.ConsentScreenText = *input.ConsentScreenText
	}

	if err := r.ClientScopeRepo.CreateClientScope(ctx, scope); err != nil {
		return nil, err
	}
	return scope, nil
}

// DeleteClientScope is the resolver for the deleteClientScope field.
func (r *mutationResolver) DeleteClientScope(ctx context.Context, id string) (bool, error) {
	err := r.ClientScopeRepo.DeleteClientScope(ctx, id)
	return err == nil, err
}

// UpdateRealmKeys is the resolver for the updateRealmKeys field.
func (r *mutationResolver) UpdateRealmKeys(ctx context.Context, input UpdateRealmKeysInput) ([]domain.RealmKey, error) {
	keys := make([]*domain.RealmKey, len(input.Keys))
	for i, keyInput := range input.Keys {
		key := &domain.RealmKey{
			Name:       keyInput.Name,
			Type:       keyInput.Type,
			ProviderID: keyInput.ProviderID,
			Active:     keyInput.Active != nil && *keyInput.Active,
		}
		if keyInput.Priority != nil {
			key.Priority = *keyInput.Priority
		}
		keys[i] = key
	}

	if err := r.RealmKeysRepo.UpdateRealmKeys(ctx, keys); err != nil {
		return nil, err
	}

	result := make([]domain.RealmKey, len(keys))
	for i, k := range keys {
		result[i] = *k
	}
	return result, nil
}

// CreateCompositeRole is the resolver for the createCompositeRole field.
func (r *mutationResolver) CreateCompositeRole(ctx context.Context, input CreateCompositeRoleInput) (*domain.Role, error) {
	role := &domain.Role{
		Name:      input.Name,
		Composite: true,
	}
	if input.Description != nil {
		role.Description = *input.Description
	}

	// Add realm role children
	for _, roleID := range input.RealmRoles {
		role.ChildRoles = append(role.ChildRoles, roleID)
		if err := r.RoleRepo.AddChildRole(ctx, role.ID, roleID); err != nil {
			return nil, err
		}
	}

	// Add client role children
	for _, clientRole := range input.ClientRoles {
		if err := r.RoleRepo.AddChildRole(ctx, role.ID, clientRole.RoleID); err != nil {
			return nil, err
		}
	}

	if err := r.RoleRepo.CreateRole(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

// Client is the resolver for the client field.
func (r *protocolMapperResolver) Client(ctx context.Context, obj *domain.ProtocolMapper) (*domain.Client, error) {
	if obj.ClientID == "" {
		return nil, nil
	}
	return r.ClientRepo.GetClient(ctx, obj.ClientID)
}

// Users is the resolver for the users field.
func (r *queryResolver) Users(ctx context.Context, filter *UserFilter, first *int, after *int) (*UserConnection, error) {
	if r.UserRepo == nil {
		return &UserConnection{
			Edges:      []UserEdge{},
			TotalCount: 0,
			PageInfo:   &PageInfo{},
		}, nil
	}

	users, _, err := r.UserRepo.ListUsers(ctx, "", 100)
	if err != nil {
		return nil, err
	}

	// Convert to edges
	edges := make([]UserEdge, len(users))
	for i, u := range users {
		edges[i] = UserEdge{
			Node:   u,
			Cursor: u.ID,
		}
	}

	totalCount, _ := r.UserRepo.CountUsers(ctx)

	return &UserConnection{
		Edges:      edges,
		TotalCount: int(totalCount),
		PageInfo: &PageInfo{
			HasNextPage:     false,
			HasPreviousPage: false,
		},
	}, nil
}

// User is the resolver for the user field.
func (r *queryResolver) User(ctx context.Context, id string) (*domain.User, error) {
	return r.UserRepo.GetUserByID(ctx, id)
}

// Clients is the resolver for the clients field.
func (r *queryResolver) Clients(ctx context.Context, filter *domain.ClientFilter, first *int, after *int) (*ClientConnection, error) {
	var clients []*domain.Client
	var err error
	if filter != nil {
		clients, err = r.ClientRepo.ListClients(ctx, *filter)
	} else {
		clients, err = r.ClientRepo.ListClients(ctx, domain.ClientFilter{})
	}
	if err != nil {
		return nil, err
	}

	edges := make([]ClientEdge, len(clients))
	for i, c := range clients {
		edges[i] = ClientEdge{
			Node:   c,
			Cursor: c.ID,
		}
	}

	return &ClientConnection{
		Edges:      edges,
		TotalCount: len(clients),
		PageInfo: &PageInfo{
			HasNextPage:     false,
			HasPreviousPage: false,
		},
	}, nil
}

// Client is the resolver for the client field.
func (r *queryResolver) Client(ctx context.Context, id string) (*domain.Client, error) {
	return r.ClientRepo.GetClient(ctx, id)
}

// ClientByClientID is the resolver for the clientByClientId field.
func (r *queryResolver) ClientByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	return r.ClientRepo.GetClient(ctx, clientID)
}

// Roles is the resolver for the roles field.
func (r *queryResolver) Roles(ctx context.Context) ([]domain.Role, error) {
	roles, err := r.RoleRepo.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domain.Role, len(roles))
	for i, role := range roles {
		result[i] = *role
	}
	return result, nil
}

// Role is the resolver for the role field.
func (r *queryResolver) Role(ctx context.Context, id string) (*domain.Role, error) {
	return r.RoleRepo.GetRoleByID(ctx, id)
}

// RealmRoles is the resolver for the realmRoles field.
func (r *queryResolver) RealmRoles(ctx context.Context) ([]domain.Role, error) {
	roles, err := r.RoleRepo.ListRealmRoles(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domain.Role, len(roles))
	for i, role := range roles {
		result[i] = *role
	}
	return result, nil
}

// ClientRoles is the resolver for the clientRoles field.
func (r *queryResolver) ClientRoles(ctx context.Context, clientID string) ([]domain.Role, error) {
	roles, err := r.RoleRepo.ListClientRoles(ctx, clientID)
	if err != nil {
		return nil, err
	}
	result := make([]domain.Role, len(roles))
	for i, role := range roles {
		result[i] = *role
	}
	return result, nil
}

// Groups is the resolver for the groups field.
func (r *queryResolver) Groups(ctx context.Context) ([]domain.Group, error) {
	groups, err := r.GroupRepo.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domain.Group, len(groups))
	for i, g := range groups {
		result[i] = *g
	}
	return result, nil
}

// Group is the resolver for the group field.
func (r *queryResolver) Group(ctx context.Context, id string) (*domain.Group, error) {
	return r.GroupRepo.GetGroupByID(ctx, id)
}

// Sessions is the resolver for the sessions field.
func (r *queryResolver) Sessions(ctx context.Context, userID *string, first *int, after *int) (*SessionConnection, error) {
	var filter domain.SessionFilter
	if userID != nil {
		filter.UserID = *userID
	}
	sessions, err := r.SessionRepo.ListSessionsByUserID(ctx, filter.UserID, filter)
	if err != nil {
		return nil, err
	}

	edges := make([]SessionEdge, len(sessions))
	for i, s := range sessions {
		edges[i] = SessionEdge{
			Node:   s,
			Cursor: s.ID,
		}
	}

	return &SessionConnection{
		Edges:      edges,
		TotalCount: len(sessions),
		PageInfo: &PageInfo{
			HasNextPage:     false,
			HasPreviousPage: false,
		},
	}, nil
}

// Session is the resolver for the session field.
func (r *queryResolver) Session(ctx context.Context, id string) (*domain.Session, error) {
	return r.SessionRepo.GetSessionByID(ctx, id)
}

// IdentityProviders is the resolver for the identityProviders field.
func (r *queryResolver) IdentityProviders(ctx context.Context) ([]domain.IdentityProvider, error) {
	idps, err := r.IdPRepo.ListIdPs(ctx, false)
	if err != nil {
		return nil, err
	}
	result := make([]domain.IdentityProvider, len(idps))
	for i, idp := range idps {
		result[i] = *idp
	}
	return result, nil
}

// IdentityProvider is the resolver for the identityProvider field.
func (r *queryResolver) IdentityProvider(ctx context.Context, id string) (*domain.IdentityProvider, error) {
	return r.IdPRepo.GetIdPByID(ctx, id)
}

// Realm is the resolver for the realm field.
func (r *queryResolver) Realm(ctx context.Context) (*domain.RealmSettings, error) {
	return r.RealmSettingsRepo.GetRealmSettings(ctx)
}

// IntrospectToken is the resolver for the introspectToken field.
func (r *queryResolver) IntrospectToken(ctx context.Context, token string) (*domain.TokenIntrospection, error) {
	// This would typically validate the token using TokenService
	// For now, return a placeholder - this needs the token service
	return &domain.TokenIntrospection{Active: false}, nil
}

// AuthenticationExecutions is the resolver for the authenticationExecutions field.
func (r *queryResolver) AuthenticationExecutions(ctx context.Context, flowID string) ([]domain.AuthenticationExecution, error) {
	execs, err := r.AuthFlowRepo.GetExecutions(ctx, flowID)
	if err != nil {
		return nil, err
	}
	result := make([]domain.AuthenticationExecution, len(execs))
	for i, e := range execs {
		result[i] = *e
	}
	return result, nil
}

// AuthenticationFlows is the resolver for the authenticationFlows field.
func (r *queryResolver) AuthenticationFlows(ctx context.Context) ([]domain.AuthenticationFlow, error) {
	flows, err := r.AuthFlowRepo.ListFlows(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domain.AuthenticationFlow, len(flows))
	for i, f := range flows {
		result[i] = *f
	}
	return result, nil
}

// GroupMembers is the resolver for the groupMembers field.
func (r *queryResolver) GroupMembers(ctx context.Context, groupID string, first *int, after *int) (*UserConnection, error) {
	group, err := r.GroupRepo.GetGroupByID(ctx, groupID)
	if err != nil {
		return nil, err
	}

	// Get all members of the group
	members := make([]UserEdge, len(group.MemberIDs))
	for i, memberID := range group.MemberIDs {
		user, err := r.UserRepo.GetUserByID(ctx, memberID)
		if err != nil {
			continue // Skip users that couldn't be found
		}
		members[i] = UserEdge{
			Node:   user,
			Cursor: user.ID,
		}
	}

	return &UserConnection{
		Edges:      members,
		TotalCount: len(members),
		PageInfo: &PageInfo{
			HasNextPage:     false,
			HasPreviousPage: false,
		},
	}, nil
}

// RoleMappings is the resolver for the roleMappings field.
func (r *queryResolver) RoleMappings(ctx context.Context, userID string) (*RoleMapping, error) {
	// Get user's realm roles - would need to look up from user record
	return &RoleMapping{
		RealmMappings:  nil,
		ClientMappings: nil,
	}, nil
}

// ClientRoleMappings is the resolver for the clientRoleMappings field.
func (r *queryResolver) ClientRoleMappings(ctx context.Context, userID string, clientID string) ([]domain.Role, error) {
	// Get client roles for user - would need role assignment storage
	return nil, nil
}

// TokenMappers is the resolver for the tokenMappers field.
func (r *queryResolver) TokenMappers(ctx context.Context) ([]domain.ProtocolMapper, error) {
	mappers, err := r.ProtocolMapperRepo.ListProtocolMappers(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domain.ProtocolMapper, len(mappers))
	for i, m := range mappers {
		result[i] = *m
	}
	return result, nil
}

// ClientTokenMappers is the resolver for the clientTokenMappers field.
func (r *queryResolver) ClientTokenMappers(ctx context.Context, clientID string) ([]domain.ProtocolMapper, error) {
	mappers, err := r.ProtocolMapperRepo.ListClientProtocolMappers(ctx, clientID)
	if err != nil {
		return nil, err
	}
	result := make([]domain.ProtocolMapper, len(mappers))
	for i, m := range mappers {
		result[i] = *m
	}
	return result, nil
}

// UserGroups is the resolver for the userGroups field.
func (r *queryResolver) UserGroups(ctx context.Context, userID string) ([]domain.Group, error) {
	// Would need to look up groups where user is a member - not implemented
	return nil, nil
}

// UserSessions is the resolver for the userSessions field.
func (r *queryResolver) UserSessions(ctx context.Context, userID string) ([]domain.Session, error) {
	sessions, err := r.SessionRepo.ListSessionsByUserID(ctx, userID, domain.SessionFilter{})
	if err != nil {
		return nil, err
	}
	result := make([]domain.Session, len(sessions))
	for i, s := range sessions {
		result[i] = *s
	}
	return result, nil
}

// ClientUserSessions is the resolver for the clientUserSessions field.
func (r *queryResolver) ClientUserSessions(ctx context.Context, userID string, clientID string) ([]domain.Session, error) {
	// Would need to filter sessions by client ID - not currently possible
	return nil, nil
}

// RealmKeys is the resolver for the realmKeys field.
func (r *queryResolver) RealmKeys(ctx context.Context) ([]domain.RealmKey, error) {
	keys, err := r.RealmKeysRepo.ListRealmKeys(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domain.RealmKey, len(keys))
	for i, k := range keys {
		result[i] = *k
	}
	return result, nil
}

// UserAttributes is the resolver for the userAttributes field.
func (r *queryResolver) UserAttributes(ctx context.Context, userID string) ([]domain.UserAttribute, error) {
	attrs, err := r.UserAttributeRepo.GetAttributesByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]domain.UserAttribute, len(attrs))
	for i, a := range attrs {
		result[i] = *a
	}
	return result, nil
}

// UserAttributeMappers is the resolver for the userAttributeMappers field.
func (r *queryResolver) UserAttributeMappers(ctx context.Context) ([]domain.UserAttributeMapper, error) {
	mappers, err := r.UserAttributeMapperRepo.GetMappersByTokenType(ctx, "id_token")
	if err != nil {
		return nil, err
	}
	result := make([]domain.UserAttributeMapper, len(mappers))
	for i, m := range mappers {
		result[i] = *m
	}
	return result, nil
}

// ClientUserAttributeMappers is the resolver for the clientUserAttributeMappers field.
func (r *queryResolver) ClientUserAttributeMappers(ctx context.Context, clientID string) ([]domain.UserAttributeMapper, error) {
	mappers, err := r.UserAttributeMapperRepo.GetClientMappers(ctx, clientID)
	if err != nil {
		return nil, err
	}
	result := make([]domain.UserAttributeMapper, len(mappers))
	for i, m := range mappers {
		result[i] = *m
	}
	return result, nil
}

// PasswordPolicy is the resolver for the passwordPolicy field.
func (r *realmSettingsResolver) PasswordPolicy(ctx context.Context, obj *domain.RealmSettings) (*PasswordPolicy, error) {
	return &PasswordPolicy{
		MinLength:    ptrInt(obj.PasswordMinLength),
		MaxLength:    ptrInt(obj.PasswordMaxLength),
		LowerCase:    ptrInt(obj.PasswordLowerCase),
		UpperCase:    ptrInt(obj.PasswordUpperCase),
		Digits:       ptrInt(obj.PasswordDigits),
		SpecialChars: ptrInt(obj.PasswordSpecialChars),
	}, nil
}

// TokenEndpoint is the resolver for the tokenEndpoint field.
func (r *realmSettingsResolver) TokenEndpoint(ctx context.Context, obj *domain.RealmSettings) (*string, error) {
	// Would need to be configured or derived from server config
	endpoint := "/oauth/token"
	return &endpoint, nil
}

// AuthorizationEndpoint is the resolver for the authorizationEndpoint field.
func (r *realmSettingsResolver) AuthorizationEndpoint(ctx context.Context, obj *domain.RealmSettings) (*string, error) {
	endpoint := "/oauth/authorize"
	return &endpoint, nil
}

// IssuanceEndpoint is the resolver for the issuanceEndpoint field.
func (r *realmSettingsResolver) IssuanceEndpoint(ctx context.Context, obj *domain.RealmSettings) (*string, error) {
	endpoint := "/oauth/token"
	return &endpoint, nil
}

// RealmRoles is the resolver for the realmRoles field.
func (r *roleResolver) RealmRoles(ctx context.Context, obj *domain.Role) ([]domain.Role, error) {
	// Get child roles of a composite role
	var roles []domain.Role
	for _, childID := range obj.ChildRoles {
		role, err := r.RoleRepo.GetRoleByID(ctx, childID)
		if err != nil {
			continue
		}
		roles = append(roles, *role)
	}
	if roles == nil {
		roles = []domain.Role{}
	}
	return roles, nil
}

// ClientRoles is the resolver for the clientRoles field.
func (r *roleResolver) ClientRoles(ctx context.Context, obj *domain.Role, clientID string) ([]domain.Role, error) {
	// Get child client roles of a composite role
	var roles []domain.Role
	for _, childID := range obj.ChildRoles {
		role, err := r.RoleRepo.GetRoleByID(ctx, childID)
		if err != nil {
			continue
		}
		if role.ClientRole && role.ContainerID == clientID {
			roles = append(roles, *role)
		}
	}
	if roles == nil {
		roles = []domain.Role{}
	}
	return roles, nil
}

// Username is the resolver for the username field.
func (r *sessionResolver) Username(ctx context.Context, obj *domain.Session) (*string, error) {
	// We need to look up the user to get their username/email
	user, err := r.UserRepo.GetUserByID(ctx, obj.UserID)
	if err != nil {
		return nil, nil
	}
	return &user.Email, nil
}

// CreatedTime is the resolver for the createdTime field.
func (r *sessionResolver) CreatedTime(ctx context.Context, obj *domain.Session) (*time.Time, error) {
	if obj.CreatedAt.IsZero() {
		return nil, nil
	}
	return &obj.CreatedAt, nil
}

// LastAccessedTime is the resolver for the lastAccessedTime field.
func (r *sessionResolver) LastAccessedTime(ctx context.Context, obj *domain.Session) (*time.Time, error) {
	if obj.LastUsedAt.IsZero() {
		return nil, nil
	}
	return &obj.LastUsedAt, nil
}

// Expires is the resolver for the expires field.
func (r *sessionResolver) Expires(ctx context.Context, obj *domain.Session) (*time.Time, error) {
	if obj.ExpiresAt.IsZero() {
		return nil, nil
	}
	return &obj.ExpiresAt, nil
}

// State is the resolver for the state field.
func (r *sessionResolver) State(ctx context.Context, obj *domain.Session) (*string, error) {
	if obj.IsRevoked {
		state := "REVOKED"
		return &state, nil
	}
	state := "ACTIVE"
	return &state, nil
}

// ClientID is the resolver for the clientId field.
func (r *sessionResolver) ClientID(ctx context.Context, obj *domain.Session) (*string, error) {
	// Session doesn't track client ID in domain model
	return nil, nil
}

// ClientName is the resolver for the clientName field.
func (r *sessionResolver) ClientName(ctx context.Context, obj *domain.Session) (*string, error) {
	// Session doesn't track client name in domain model
	return nil, nil
}

// Azp is the resolver for the azp field.
func (r *tokenIntrospectionResolver) Azp(ctx context.Context, obj *domain.TokenIntrospection) (*string, error) {
	// azp (authorized party) is not currently stored in TokenIntrospection
	return nil, nil
}

// AuthTime is the resolver for the authTime field.
func (r *tokenIntrospectionResolver) AuthTime(ctx context.Context, obj *domain.TokenIntrospection) (*int, error) {
	// auth_time is not currently stored in TokenIntrospection
	return nil, nil
}

// Nonce is the resolver for the nonce field.
func (r *tokenIntrospectionResolver) Nonce(ctx context.Context, obj *domain.TokenIntrospection) (*string, error) {
	// nonce is not currently stored in TokenIntrospection
	return nil, nil
}

// Username is the resolver for the username field.
func (r *userResolver) Username(ctx context.Context, obj *domain.User) (string, error) {
	// Domain user uses Email as username
	return obj.Email, nil
}

// Enabled is the resolver for the enabled field.
func (r *userResolver) Enabled(ctx context.Context, obj *domain.User) (bool, error) {
	return obj.Status == domain.UserStatusActive, nil
}

// EmailVerified is the resolver for the emailVerified field.
func (r *userResolver) EmailVerified(ctx context.Context, obj *domain.User) (bool, error) {
	return obj.IsEmailVerified, nil
}

// CreatedTimestamp is the resolver for the createdTimestamp field.
func (r *userResolver) CreatedTimestamp(ctx context.Context, obj *domain.User) (*time.Time, error) {
	if obj.CreatedAt.IsZero() {
		return nil, nil
	}
	return &obj.CreatedAt, nil
}

// LastAccess is the resolver for the lastAccess field.
func (r *userResolver) LastAccess(ctx context.Context, obj *domain.User) (*time.Time, error) {
	return obj.LastLoginAt, nil
}

// Groups is the resolver for the groups field.
func (r *userResolver) Groups(ctx context.Context, obj *domain.User) ([]domain.Group, error) {
	// Would need to look up groups from group repository via member IDs
	return nil, nil
}

// FederatedIdentities is the resolver for the federatedIdentities field.
func (r *userResolver) FederatedIdentities(ctx context.Context, obj *domain.User) ([]FederatedIdentity, error) {
	// Would need to look up federated identities - not yet implemented
	return nil, nil
}

// Credentials is the resolver for the credentials field.
func (r *userResolver) Credentials(ctx context.Context, obj *domain.User) ([]UserCredential, error) {
	// Don't expose credentials for security reasons
	return nil, nil
}

// ClientRoles is the resolver for the clientRoles field.
func (r *userResolver) ClientRoles(ctx context.Context, obj *domain.User, clientID string) ([]domain.Role, error) {
	// Would need to look up client roles assigned to user
	return nil, nil
}

// Sessions is the resolver for the sessions field.
func (r *userResolver) Sessions(ctx context.Context, obj *domain.User) ([]domain.Session, error) {
	sessions, err := r.SessionRepo.ListSessionsByUserID(ctx, obj.ID, domain.SessionFilter{})
	if err != nil {
		return nil, err
	}
	result := make([]domain.Session, len(sessions))
	for i, s := range sessions {
		result[i] = *s
	}
	return result, nil
}

// Totp is the resolver for the totp field.
func (r *userResolver) Totp(ctx context.Context, obj *domain.User) (bool, error) {
	return obj.IsTwoFactorEnabled, nil
}

// Attributes is the resolver for the attributes field.
func (r *userResolver) Attributes(ctx context.Context, obj *domain.User) (map[string]any, error) {
	// Map user's custom fields to attributes
	attrs := make(map[string]any)
	if obj.FirstName != "" {
		attrs["firstName"] = obj.FirstName
	}
	if obj.LastName != "" {
		attrs["lastName"] = obj.LastName
	}
	if obj.PhoneNumber != "" {
		attrs["phoneNumber"] = obj.PhoneNumber
		attrs["phoneNumberVerified"] = obj.IsPhoneNumberVerified
	}
	attrs["mfaEnabled"] = obj.IsTwoFactorEnabled
	attrs["emailMfaEnabled"] = obj.EmailMFAEnabled
	attrs["pushMfaEnabled"] = obj.PushMFAEnabled
	return attrs, nil
}

// GroupIds is the resolver for the groupIds field.
func (r *userResolver) GroupIds(ctx context.Context, obj *domain.User) ([]string, error) {
	// Would need to look up group memberships - not yet implemented
	return nil, nil
}

// AuthenticationFlow returns AuthenticationFlowResolver implementation.
func (r *Resolver) AuthenticationFlow() AuthenticationFlowResolver {
	return &authenticationFlowResolver{r}
}

// Client returns ClientResolver implementation.
func (r *Resolver) Client() ClientResolver { return &clientResolver{r} }

// Group returns GroupResolver implementation.
func (r *Resolver) Group() GroupResolver { return &groupResolver{r} }

// IdentityProvider returns IdentityProviderResolver implementation.
func (r *Resolver) IdentityProvider() IdentityProviderResolver { return &identityProviderResolver{r} }

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// ProtocolMapper returns ProtocolMapperResolver implementation.
func (r *Resolver) ProtocolMapper() ProtocolMapperResolver { return &protocolMapperResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

// RealmSettings returns RealmSettingsResolver implementation.
func (r *Resolver) RealmSettings() RealmSettingsResolver { return &realmSettingsResolver{r} }

// Role returns RoleResolver implementation.
func (r *Resolver) Role() RoleResolver { return &roleResolver{r} }

// Session returns SessionResolver implementation.
func (r *Resolver) Session() SessionResolver { return &sessionResolver{r} }

// TokenIntrospection returns TokenIntrospectionResolver implementation.
func (r *Resolver) TokenIntrospection() TokenIntrospectionResolver {
	return &tokenIntrospectionResolver{r}
}

// User returns UserResolver implementation.
func (r *Resolver) User() UserResolver { return &userResolver{r} }

type authenticationFlowResolver struct{ *Resolver }
type clientResolver struct{ *Resolver }
type groupResolver struct{ *Resolver }
type identityProviderResolver struct{ *Resolver }
type mutationResolver struct{ *Resolver }
type protocolMapperResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
type realmSettingsResolver struct{ *Resolver }
type roleResolver struct{ *Resolver }
type sessionResolver struct{ *Resolver }
type tokenIntrospectionResolver struct{ *Resolver }
type userResolver struct{ *Resolver }

func requireAdmin(ctx context.Context) error {
	tokenInfo, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || tokenInfo == nil {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if !rbac.HasPermission(tokenInfo.Roles, rbac.PermUsersDeleteAll) {
		return connect.NewError(connect.CodePermissionDenied, errors.New("admin role required"))
	}
	return nil
}

func contains(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateRandomSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func ptrInt(i int) *int {
	return &i
}

type clientFilterResolver struct{ *Resolver }

func (r *clientFilterResolver) ClientID(ctx context.Context, obj *domain.ClientFilter, data *string) error { return nil }
func (r *clientFilterResolver) ClientName(ctx context.Context, obj *domain.ClientFilter, data *string) error { return nil }
func (r *clientFilterResolver) Enabled(ctx context.Context, obj *domain.ClientFilter, data *bool) error { return nil }

func (r *Resolver) ClientFilter() ClientFilterResolver {
	return &clientFilterResolver{r}
}
