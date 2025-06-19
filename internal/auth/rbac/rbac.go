package rbac

import "github.com/pilab-dev/shadow-sso/domain"

// Roles - Constants are now defined in the domain package (domain.RoleAdmin, domain.RoleUser)
// const (
// 	RoleAdmin = "ROLE_ADMIN" // Now domain.RoleAdmin
// 	RoleUser  = "ROLE_USER"  // Now domain.RoleUser
// )

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

// Service Account Management (Admin only)
const (
	PermServiceAccountsManage = "serviceaccounts:manage"
)

// RoleToPermissionsMap maps roles to their granted permissions.
// This can be used by the authorization interceptor.
var RoleToPermissionsMap = map[string][]string{
	domain.RoleUser: { // Use domain.RoleUser
		PermUsersReadSelf,
		PermUsersUpdateSelf,
		PermUsersChangePasswordSelf,
		Perm2FASetupSelf,
		Perm2FADisableSelf,
		Perm2FAGenerateRecoverySelf,
		PermSessionsListSelf,
		PermSessionsClearSelf,
	},
	domain.RoleAdmin: { // Use domain.RoleAdmin
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
	"/sso.v1.UserService/RegisterUser":           PermUsersCreate,
	"/sso.v1.UserService/ActivateUser":           PermUsersActivateAll,
	"/sso.v1.UserService/LockUser":               PermUsersLockAll,
	"/sso.v1.UserService/ListUsers":              PermUsersReadAll,
	"/sso.v1.UserService/GetUser":                PermUsersReadAll, // Service logic could allow PermUsersReadSelf too
	"/sso.v1.UserService/ChangePassword":         "",               // Complex: self (PermUsersChangePasswordSelf) vs admin (PermUsersChangePasswordAll) - handled in service

	// AuthService - Login is public (no entry). Logout is authenticated but simple (revokes own session).
	// ListUserSessions, ClearUserSessions need logic based on target user vs. authenticated user.
	"/sso.v1.AuthService/ListUserSessions":       "", // Complex: self (PermSessionsListSelf) vs admin (PermSessionsListOthers) - handled in service
	"/sso.v1.AuthService/ClearUserSessions":      "", // Complex: self (PermSessionsClearSelf) vs admin (PermSessionsClearOthers) - handled in service

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
}
