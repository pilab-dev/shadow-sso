package domain

//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_keycloak_types.go -package=mock_domain GroupRepository,RoleRepository

import (
	"context"
	"time"
)

// Role represents a Keycloak-style role
type Role struct {
	ID          string     `bson:"_id,omitempty" json:"id"`
	Name        string     `bson:"name" json:"name"`
	Description string     `bson:"description,omitempty" json:"description,omitempty"`
	Composite   bool       `bson:"composite" json:"composite"`
	ClientRole  bool       `bson:"client_role" json:"clientRole"`
	ContainerID string     `bson:"container_id,omitempty" json:"containerId,omitempty"`
	CreatedAt   time.Time  `bson:"created_at" json:"createdAt,omitempty"`
	UpdatedAt   time.Time  `bson:"updated_at" json:"updatedAt,omitempty"`

	// For composite roles - references to child roles
	ChildRoles []string `bson:"child_roles,omitempty" json:"childRoles,omitempty"`
}

// RoleRepository defines methods for role persistence
type RoleRepository interface {
	CreateRole(ctx context.Context, role *Role) error
	GetRoleByID(ctx context.Context, id string) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id string) error
	ListRoles(ctx context.Context) ([]*Role, error)
	ListRealmRoles(ctx context.Context) ([]*Role, error)
	ListClientRoles(ctx context.Context, clientID string) ([]*Role, error)
	AddChildRole(ctx context.Context, parentID, childID string) error
	RemoveChildRole(ctx context.Context, parentID, childID string) error
}

// Group represents a Keycloak-style group
type Group struct {
	ID           string    `bson:"_id,omitempty" json:"id"`
	Name         string    `bson:"name" json:"name"`
	Path         string    `bson:"path" json:"path"`
	ParentGroupID string   `bson:"parent_group_id,omitempty" json:"parentGroupId,omitempty"`
	CreatedAt    time.Time `bson:"created_at" json:"createdAt"`
	UpdatedAt    time.Time `bson:"updated_at" json:"updatedAt"`

	// Roles assigned to this group
	RealmRoles []string            `bson:"realm_roles,omitempty" json:"realmRoles,omitempty"`
	ClientRoles map[string][]string `bson:"client_roles,omitempty" json:"clientRoles,omitempty"`

	// Keycloak-style custom attributes for this group
	Attributes map[string]any `bson:"attributes,omitempty" json:"attributes,omitempty"`

	// Member IDs (for quick lookup)
	MemberIDs []string `bson:"member_ids,omitempty" json:"memberIds,omitempty"`
}

// GroupRepository defines methods for group persistence
type GroupRepository interface {
	CreateGroup(ctx context.Context, group *Group) error
	GetGroupByID(ctx context.Context, id string) (*Group, error)
	GetGroupByPath(ctx context.Context, path string) (*Group, error)
	UpdateGroup(ctx context.Context, group *Group) error
	DeleteGroup(ctx context.Context, id string) error
	ListGroups(ctx context.Context) ([]*Group, error)
	// GetGroupsByUserID returns all groups the user is a member of (groups are
	// flat — membership is tracked via Group.MemberIDs).
	GetGroupsByUserID(ctx context.Context, userID string) ([]*Group, error)
	AddMember(ctx context.Context, groupID, userID string) error
	RemoveMember(ctx context.Context, groupID, userID string) error
	GetMemberCount(ctx context.Context, groupID string) (int64, error)
	AddRealmRole(ctx context.Context, groupID, roleID string) error
	RemoveRealmRole(ctx context.Context, groupID, roleID string) error
	AddClientRole(ctx context.Context, groupID, clientID, roleID string) error
	RemoveClientRole(ctx context.Context, groupID, clientID, roleID string) error
}

// ProtocolMapper represents a Keycloak-style protocol mapper
type ProtocolMapper struct {
	ID           string         `bson:"_id,omitempty" json:"id"`
	Name         string         `bson:"name" json:"name"`
	Protocol     string         `bson:"protocol" json:"protocol"` // "openid-connect", "saml", etc.
	ProtocolMapper string       `bson:"protocol_mapper" json:"protocolMapper"`
	Config       map[string]any `bson:"config,omitempty" json:"config,omitempty"`
	ClientID     string         `bson:"client_id,omitempty" json:"clientId,omitempty"`
	CreatedAt    time.Time      `bson:"created_at" json:"createdAt"`
	UpdatedAt    time.Time      `bson:"updated_at" json:"updatedAt"`
}

// ProtocolMapperRepository defines methods for protocol mapper persistence
type ProtocolMapperRepository interface {
	CreateProtocolMapper(ctx context.Context, mapper *ProtocolMapper) error
	GetProtocolMapperByID(ctx context.Context, id string) (*ProtocolMapper, error)
	UpdateProtocolMapper(ctx context.Context, mapper *ProtocolMapper) error
	DeleteProtocolMapper(ctx context.Context, id string) error
	ListProtocolMappers(ctx context.Context) ([]*ProtocolMapper, error)
	ListClientProtocolMappers(ctx context.Context, clientID string) ([]*ProtocolMapper, error)
}

// AuthenticationFlow represents a Keycloak-style authentication flow
type AuthenticationFlow struct {
	ID          string                  `bson:"_id,omitempty" json:"id"`
	Alias       string                  `bson:"alias" json:"alias"`
	DisplayName string                  `bson:"display_name" json:"displayName"`
	Description string                  `bson:"description,omitempty" json:"description,omitempty"`
	BuiltIn     bool                    `bson:"built_in" json:"builtIn"`
	TopLevel    bool                    `bson:"top_level" json:"topLevel"`
	CreatedAt   time.Time               `bson:"created_at" json:"createdAt"`
	UpdatedAt   time.Time               `bson:"updated_at" json:"updatedAt"`
}

// AuthenticationExecution represents an execution within an authentication flow
type AuthenticationExecution struct {
	ID                   string `bson:"_id,omitempty" json:"id"`
	FlowID               string `bson:"flow_id" json:"flowId"`
	Execution            string `bson:"execution" json:"execution"`
	Authenticator        string `bson:"authenticator" json:"authenticator"`
	Requirement          string `bson:"requirement" json:"requirement"` // REQUIRED, ALTERNATIVE, DISABLED
	Priority             int    `bson:"priority" json:"priority"`
	AuthenticationConfig string `bson:"auth_config,omitempty" json:"authenticationConfig,omitempty"`
}

// AuthenticationFlowRepository defines methods for authentication flow persistence
type AuthenticationFlowRepository interface {
	CreateFlow(ctx context.Context, flow *AuthenticationFlow) error
	GetFlowByID(ctx context.Context, id string) (*AuthenticationFlow, error)
	GetFlowByAlias(ctx context.Context, alias string) (*AuthenticationFlow, error)
	UpdateFlow(ctx context.Context, flow *AuthenticationFlow) error
	DeleteFlow(ctx context.Context, id string) error
	ListFlows(ctx context.Context) ([]*AuthenticationFlow, error)
	UpsertExecution(ctx context.Context, exec *AuthenticationExecution) error
	GetExecutions(ctx context.Context, flowID string) ([]*AuthenticationExecution, error)
	DeleteExecution(ctx context.Context, id string) error
}

// ClientScope represents a Keycloak-style client scope
type ClientScope struct {
	ID               string    `bson:"_id,omitempty" json:"id"`
	Name             string    `bson:"name" json:"name"`
	Description      string    `bson:"description,omitempty" json:"description,omitempty"`
	Protocol         string    `bson:"protocol" json:"protocol"`
	DisplayOrder     int       `bson:"display_order" json:"displayOrder"`
	ConsentScreenText string   `bson:"consent_screen_text,omitempty" json:"consentScreenText,omitempty"`
	CreatedAt        time.Time `bson:"created_at" json:"createdAt"`
}

// ClientScopeRepository defines methods for client scope persistence
type ClientScopeRepository interface {
	CreateClientScope(ctx context.Context, scope *ClientScope) error
	GetClientScopeByID(ctx context.Context, id string) (*ClientScope, error)
	UpdateClientScope(ctx context.Context, scope *ClientScope) error
	DeleteClientScope(ctx context.Context, id string) error
}

// RealmSettings represents the realm configuration
type RealmSettings struct {
	ID                    string    `bson:"_id,omitempty" json:"id,omitempty"`
	Realm                 string    `bson:"realm" json:"realm"`
	DisplayName           string    `bson:"display_name" json:"displayName"`
	Enabled               bool      `bson:"enabled" json:"enabled"`
	RegistrationAllowed   bool      `bson:"registration_allowed" json:"registrationAllowed"`
	LoginWithEmailAllowed bool      `bson:"login_with_email_allowed" json:"loginWithEmailAllowed"`
	DuplicateEmailsAllowed bool     `bson:"duplicate_emails_allowed" json:"duplicateEmailsAllowed"`
	ResetPasswordAllowed  bool      `bson:"reset_password_allowed" json:"resetPasswordAllowed"`
	EditUsernameAllowed   bool      `bson:"edit_username_allowed" json:"editUsernameAllowed"`
	BruteForceProtected   bool      `bson:"brute_force_protected" json:"bruteForceProtected"`
	SSLRequired           string    `bson:"ssl_required" json:"sslRequired"`

	// Password policy
	PasswordMinLength    int  `bson:"password_min_length,omitempty" json:"passwordMinLength,omitempty"`
	PasswordMaxLength    int  `bson:"password_max_length,omitempty" json:"passwordMaxLength,omitempty"`
	PasswordLowerCase    int  `bson:"password_lower_case,omitempty" json:"passwordLowerCase,omitempty"`
	PasswordUpperCase    int  `bson:"password_upper_case,omitempty" json:"passwordUpperCase,omitempty"`
	PasswordDigits       int  `bson:"password_digits,omitempty" json:"passwordDigits,omitempty"`
	PasswordSpecialChars int  `bson:"password_special_chars,omitempty" json:"passwordSpecialChars,omitempty"`

	// Token settings
	AccessTokenLifespan int `bson:"access_token_lifespan,omitempty" json:"accessTokenLifespan,omitempty"`
	AccessCodeLifespan  int `bson:"access_code_lifespan,omitempty" json:"accessCodeLifespan,omitempty"`

	CreatedAt time.Time `bson:"created_at" json:"createdAt"`
	UpdatedAt time.Time `bson:"updated_at" json:"updatedAt"`
}

// RealmSettingsRepository defines methods for realm settings persistence
type RealmSettingsRepository interface {
	GetRealmSettings(ctx context.Context) (*RealmSettings, error)
	UpdateRealmSettings(ctx context.Context, settings *RealmSettings) error
}

// RealmKey represents a signing key
type RealmKey struct {
	ID         string `bson:"_id,omitempty" json:"id"`
	Name       string `bson:"name" json:"name"`
	Type       string `bson:"type" json:"type"`         // RSA, EC, etc.
	ProviderID string `bson:"provider_id" json:"providerId"`
	Active     bool   `bson:"active" json:"active"`
	Priority   int    `bson:"priority" json:"priority"`
	PublicKey  string `bson:"public_key,omitempty" json:"publicKey,omitempty"`
	PrivateKey string `bson:"private_key,omitempty" json:"privateKey,omitempty"`
	Certificate string `bson:"certificate,omitempty" json:"certificate,omitempty"`
}

// RealmKeysRepository defines methods for realm keys persistence
type RealmKeysRepository interface {
	ListRealmKeys(ctx context.Context) ([]*RealmKey, error)
	UpdateRealmKeys(ctx context.Context, keys []*RealmKey) error
}