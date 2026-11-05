package rbac

// Roles
const (
	RoleAdmin = "ROLE_ADMIN"
	RoleUser  = "ROLE_USER"
)

// Permissions
// User Management
const (
	PermUsersCreate             = "users:create"
	PermUsersReadAll            = "users:read_all"
	PermUsersReadSelf           = "users:read_self"
	PermUsersUpdateAll          = "users:update_all"
	PermUsersUpdateSelf         = "users:update_self"
	PermUsersDeleteAll          = "users:delete_all"
	PermUsersChangePasswordAll  = "users:change_password_all"
	PermUsersChangePasswordSelf = "users:change_password_self"
	PermUsersActivateAll        = "users:activate_all" // For admin activating user
	PermUsersLockAll            = "users:lock_all"     // For admin locking user
)

// OAuth Client Management (Admin only)
const (
	PermClientsCreate = "clients:create"
	PermClientsRead   = "clients:read"
	PermClientsUpdate = "clients:update"
	PermClientsDelete = "clients:delete"
)

// IdP Configuration Management (Admin only)
const (
	PermIdPsCreate = "idps:create"
	PermIdPsRead   = "idps:read"
	PermIdPsUpdate = "idps:update"
	PermIdPsDelete = "idps:delete"
)

// Two-Factor Authentication (2FA) Management
const (
	Perm2FASetupSelf            = "2fa:setup_self"
	Perm2FADisableSelf          = "2fa:disable_self"
	Perm2FAGenerateRecoverySelf = "2fa:generate_recovery_self"
	Perm2FAManageOthers         = "2fa:manage_others" // Admin views/disables 2FA, generates recovery for any user
)

// Session Management
const (
	PermSessionsListSelf    = "sessions:list_self"
	PermSessionsClearSelf   = "sessions:clear_self" // Clear own session(s)
	PermSessionsListOthers  = "sessions:list_others"
	PermSessionsClearOthers = "sessions:clear_others"
)

// CIBA (answering backchannel authentication requests on behalf of a user)
const PermCIBAResolve = "ciba:resolve"

// Service Account Management (Admin only)
const (
	PermServiceAccountsManage = "serviceaccounts:manage"
)

// User Attribute Management (Admin only)
const (
	PermUserAttributesManage = "user_attributes:manage"
	PermTokenMappersManage   = "token_mappers:manage"
)

// Audit Management (Admin only)
const (
	PermAuditRead = "audit:read"
)

// OIDC Discovery Configuration (Admin only)
const (
	PermOIDCConfigRead   = "oidc_config:read"
	PermOIDCConfigManage = "oidc_config:manage"
)

// Browser Baseline Policy (Admin only)
const (
	PermBrowserPolicyRead   = "browser_policy:read"
	PermBrowserPolicyManage = "browser_policy:manage"
)

// Role, Group, Realm and Authentication Flow Management (Admin only)
const (
	PermRolesRead       = "roles:read"
	PermRolesManage     = "roles:manage"
	PermGroupsRead      = "groups:read"
	PermGroupsManage    = "groups:manage"
	PermRealmRead       = "realm:read"
	PermRealmManage     = "realm:manage"
	PermAuthFlowsRead   = "auth_flows:read"
	PermAuthFlowsManage = "auth_flows:manage"
)

// RoleToPermissionsMap maps roles to their granted permissions.
// This can be used by the authorization interceptor.
var RoleToPermissionsMap = map[string][]string{
	RoleUser: {
		PermUsersReadSelf,
		PermUsersUpdateSelf,
		PermUsersChangePasswordSelf,
		Perm2FASetupSelf,
		Perm2FADisableSelf,
		Perm2FAGenerateRecoverySelf,
		PermSessionsListSelf,
		PermSessionsClearSelf,
	},
	RoleAdmin: {
		PermUsersCreate,
		PermUsersReadAll,
		PermUsersReadSelf, // Admin also has self permissions
		PermUsersUpdateAll,
		PermUsersUpdateSelf,
		PermUsersDeleteAll,
		PermUsersChangePasswordAll,
		PermUsersChangePasswordSelf,
		PermUsersActivateAll,
		PermUsersLockAll,

		PermClientsCreate,
		PermClientsRead,
		PermClientsUpdate,
		PermClientsDelete,

		PermIdPsCreate,
		PermIdPsRead,
		PermIdPsUpdate,
		PermIdPsDelete,

		Perm2FASetupSelf, // Admin can manage their own 2FA
		Perm2FADisableSelf,
		Perm2FAGenerateRecoverySelf,
		Perm2FAManageOthers, // And manage others'

		PermSessionsListSelf,
		PermSessionsClearSelf,
		PermSessionsListOthers,
		PermSessionsClearOthers,

		PermServiceAccountsManage,

		PermCIBAResolve,

		PermUserAttributesManage,
		PermTokenMappersManage,

		PermAuditRead,

		PermBrowserPolicyRead,
		PermBrowserPolicyManage,

		PermOIDCConfigRead,
		PermOIDCConfigManage,

		PermRolesRead,
		PermRolesManage,
		PermGroupsRead,
		PermGroupsManage,
		PermRealmRead,
		PermRealmManage,
		PermAuthFlowsRead,
		PermAuthFlowsManage,
	},
}

// HasPermission checks if a list of roles grants a specific permission.
func HasPermission(roles []string, requiredPermission string) bool {
	for _, role := range roles {
		if permissions, ok := RoleToPermissionsMap[role]; ok {
			for _, perm := range permissions {
				if perm == requiredPermission {
					return true
				}
			}
		}
	}
	return false
}

// MethodPermissions maps RPC method full path to the required permission.
// If a method is not in this map, it's considered public (after authentication)
// or its authorization is handled entirely within the service method.
// An empty string for permission means authz is intentionally deferred to service logic.
var MethodPermissions = map[string]string{
	// UserService
	"/sso.v1.UserService/RegisterUser":   PermUsersCreate,
	"/sso.v1.UserService/ActivateUser":   PermUsersActivateAll,
	"/sso.v1.UserService/LockUser":       PermUsersLockAll,
	"/sso.v1.UserService/ListUsers":      PermUsersReadAll,
	"/sso.v1.UserService/GetUser":        "", // AuthZ handled in service logic (user can read self, admin can read all)
	"/sso.v1.UserService/ChangePassword": "", // Complex: self (PermUsersChangePasswordSelf) vs admin (PermUsersChangePasswordAll) - handled in service

	// AuthService - Login is public (no entry). Logout is authenticated but simple (revokes own session).
	// ListUserSessions, ClearUserSessions need logic based on target user vs. authenticated user.
	"/sso.v1.AuthService/ListUserSessions":  "", // Complex: self (PermSessionsListSelf) vs admin (PermSessionsListOthers) - handled in service
	"/sso.v1.AuthService/ClearUserSessions": "", // Complex: self (PermSessionsClearSelf) vs admin (PermSessionsClearOthers) - handled in service

	// ServiceAccountService (All admin-level)
	"/sso.v1.ServiceAccountService/CreateServiceAccountKey": PermServiceAccountsManage,
	"/sso.v1.ServiceAccountService/ListServiceAccountKeys":  PermServiceAccountsManage,
	"/sso.v1.ServiceAccountService/DeleteServiceAccountKey": PermServiceAccountsManage,

	// IdPManagementService (All admin)
	"/sso.v1.IdPManagementService/AddIdP":    PermIdPsCreate,
	"/sso.v1.IdPManagementService/GetIdP":    PermIdPsRead,
	"/sso.v1.IdPManagementService/ListIdPs":  PermIdPsRead,
	"/sso.v1.IdPManagementService/UpdateIdP": PermIdPsUpdate,
	"/sso.v1.IdPManagementService/DeleteIdP": PermIdPsDelete,

	// UserAttributeService (All admin)
	"/sso.v1.UserAttributeService/CreateUserAttribute":          PermUserAttributesManage,
	"/sso.v1.UserAttributeService/GetUserAttribute":             PermUserAttributesManage,
	"/sso.v1.UserAttributeService/ListUserAttributes":           PermUserAttributesManage,
	"/sso.v1.UserAttributeService/UpdateUserAttribute":          PermUserAttributesManage,
	"/sso.v1.UserAttributeService/DeleteUserAttribute":          PermUserAttributesManage,
	"/sso.v1.UserAttributeService/DeleteUserAttributesByUserId": PermUserAttributesManage,

	// UserAttributeMapperService (All admin)
	"/sso.v1.UserAttributeMapperService/CreateUserAttributeMapper": PermTokenMappersManage,
	"/sso.v1.UserAttributeMapperService/GetUserAttributeMapper":    PermTokenMappersManage,
	"/sso.v1.UserAttributeMapperService/ListUserAttributeMappers":  PermTokenMappersManage,
	"/sso.v1.UserAttributeMapperService/UpdateUserAttributeMapper": PermTokenMappersManage,
	"/sso.v1.UserAttributeMapperService/DeleteUserAttributeMapper": PermTokenMappersManage,

	// AuditService (All admin)
	"/sso.v1.AuditService/ListAuditEvents":   PermAuditRead,
	"/sso.v1.AuditService/FollowAuditEvents": PermAuditRead,

	// TokenService — self vs other is resolved in the service.
	"/sso.v1.TokenService/ListUserTokens":  "",
	"/sso.v1.TokenService/GetToken":        "",
	"/sso.v1.TokenService/ListUserDevices": "",
	"/sso.v1.TokenService/RevokeToken":     "",

	// BrowserPolicyService
	"/sso.v1.BrowserPolicyService/GetBrowserPolicy":    PermBrowserPolicyRead,
	"/sso.v1.BrowserPolicyService/CheckBrowser":        PermBrowserPolicyRead,
	"/sso.v1.BrowserPolicyService/UpdateBrowserPolicy": PermBrowserPolicyManage,

	// ProtocolMapperService (All admin)
	"/sso.v1.ProtocolMapperService/CreateProtocolMapper": PermTokenMappersManage,
	"/sso.v1.ProtocolMapperService/GetProtocolMapper":    PermTokenMappersManage,
	"/sso.v1.ProtocolMapperService/ListProtocolMappers":  PermTokenMappersManage,
	"/sso.v1.ProtocolMapperService/UpdateProtocolMapper": PermTokenMappersManage,
	"/sso.v1.ProtocolMapperService/DeleteProtocolMapper": PermTokenMappersManage,

	// ClientScopeService (All admin)
	"/sso.v1.ClientScopeService/CreateClientScope": PermClientsCreate,
	"/sso.v1.ClientScopeService/GetClientScope":    PermClientsRead,
	"/sso.v1.ClientScopeService/ListClientScopes":  PermClientsRead,
	"/sso.v1.ClientScopeService/UpdateClientScope": PermClientsUpdate,
	"/sso.v1.ClientScopeService/DeleteClientScope": PermClientsDelete,

	// OIDCConfigurationService (All admin)
	"/sso.v1.OIDCConfigurationService/GetOIDCConfiguration":    PermOIDCConfigRead,
	"/sso.v1.OIDCConfigurationService/UpdateOIDCConfiguration": PermOIDCConfigManage,

	// RoleService
	"/sso.v1.RoleService/CreateRole":                PermRolesManage,
	"/sso.v1.RoleService/UpdateRole":                PermRolesManage,
	"/sso.v1.RoleService/DeleteRole":                PermRolesManage,
	"/sso.v1.RoleService/CreateCompositeRole":       PermRolesManage,
	"/sso.v1.RoleService/GetRole":                   PermRolesRead,
	"/sso.v1.RoleService/ListRoles":                 PermRolesRead,
	"/sso.v1.RoleService/ListRealmRoles":            PermRolesRead,
	"/sso.v1.RoleService/ListClientRoles":           PermRolesRead,
	"/sso.v1.RoleService/GetUserRoleMappings":       PermUsersReadAll,
	"/sso.v1.RoleService/GetUserClientRoleMappings": PermUsersReadAll,
	"/sso.v1.RoleService/AddRealmRoleToUser":        PermUsersUpdateAll,
	"/sso.v1.RoleService/RemoveRealmRoleFromUser":   PermUsersUpdateAll,
	"/sso.v1.RoleService/AddClientRoleToUser":       PermUsersUpdateAll,
	"/sso.v1.RoleService/RemoveClientRoleFromUser":  PermUsersUpdateAll,

	// GroupService
	"/sso.v1.GroupService/CreateGroup":               PermGroupsManage,
	"/sso.v1.GroupService/UpdateGroup":               PermGroupsManage,
	"/sso.v1.GroupService/DeleteGroup":               PermGroupsManage,
	"/sso.v1.GroupService/AddUserToGroup":            PermGroupsManage,
	"/sso.v1.GroupService/RemoveUserFromGroup":       PermGroupsManage,
	"/sso.v1.GroupService/AddRealmRoleToGroup":       PermGroupsManage,
	"/sso.v1.GroupService/RemoveRealmRoleFromGroup":  PermGroupsManage,
	"/sso.v1.GroupService/AddClientRoleToGroup":      PermGroupsManage,
	"/sso.v1.GroupService/RemoveClientRoleFromGroup": PermGroupsManage,
	"/sso.v1.GroupService/GetGroup":                  PermGroupsRead,
	"/sso.v1.GroupService/ListGroups":                PermGroupsRead,
	"/sso.v1.GroupService/ListGroupMembers":          PermGroupsRead,
	"/sso.v1.GroupService/GetGroupRoles":             PermGroupsRead,
	"/sso.v1.GroupService/ListUserGroups":            PermUsersReadAll,

	// SessionAdminService
	"/sso.v1.SessionAdminService/ListSessions":           PermSessionsListOthers,
	"/sso.v1.SessionAdminService/GetSession":             PermSessionsListOthers,
	"/sso.v1.SessionAdminService/ListSessionEvents":      PermSessionsListOthers,
	"/sso.v1.SessionAdminService/ListUserSessions":       PermSessionsListOthers,
	"/sso.v1.SessionAdminService/ListClientUserSessions": PermSessionsListOthers,
	"/sso.v1.SessionAdminService/RevokeSession":          PermSessionsClearOthers,
	"/sso.v1.SessionAdminService/RevokeOtherSessions":    PermSessionsClearOthers,
	"/sso.v1.SessionAdminService/RevokeAllSessions":      PermSessionsClearOthers,
	"/sso.v1.SessionAdminService/LogoutUser":             PermSessionsClearOthers,

	// RealmService
	"/sso.v1.RealmService/GetRealm":         PermRealmRead,
	"/sso.v1.RealmService/ListRealmKeys":    PermRealmRead,
	"/sso.v1.RealmService/UpdateRealm":      PermRealmManage,
	"/sso.v1.RealmService/UpdateRealmKeys":  PermRealmManage,
	"/sso.v1.RealmService/GenerateRealmKey": PermRealmManage,

	// TokenIntrospectionService
	"/sso.v1.TokenIntrospectionService/IntrospectToken": PermUsersDeleteAll,

	// AuthenticationFlowService
	"/sso.v1.AuthenticationFlowService/ListAuthenticationFlows":        PermAuthFlowsRead,
	"/sso.v1.AuthenticationFlowService/ListAuthenticationExecutions":   PermAuthFlowsRead,
	"/sso.v1.AuthenticationFlowService/CreateAuthenticationFlow":       PermAuthFlowsManage,
	"/sso.v1.AuthenticationFlowService/UpdateAuthenticationFlow":       PermAuthFlowsManage,
	"/sso.v1.AuthenticationFlowService/DeleteAuthenticationFlow":       PermAuthFlowsManage,
	"/sso.v1.AuthenticationFlowService/UpdateAuthenticationExecutions": PermAuthFlowsManage,

	// BackchannelAuthenticationService
	"/sso.v1.BackchannelAuthenticationService/GetBackchannelAuthentication":     PermCIBAResolve,
	"/sso.v1.BackchannelAuthenticationService/ResolveBackchannelAuthentication": PermCIBAResolve,

	// UserAdminService
	"/sso.v1.UserAdminService/SendVerificationEmail":  PermUsersUpdateAll,
	"/sso.v1.UserAdminService/SendPasswordResetEmail": PermUsersChangePasswordAll,
	"/sso.v1.UserAdminService/AdminResetPassword":     PermUsersChangePasswordAll,
	"/sso.v1.UserAdminService/SetUserPassword":        PermUsersChangePasswordAll,
	"/sso.v1.UserAdminService/ExecuteActions":         PermUsersUpdateAll,
	"/sso.v1.UserAdminService/AddRequiredAction":      PermUsersUpdateAll,
	"/sso.v1.UserAdminService/RemoveRequiredAction":   PermUsersUpdateAll,
	"/sso.v1.UserAdminService/DeleteUserCredential":   PermUsersUpdateAll,
}
