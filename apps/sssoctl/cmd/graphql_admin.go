package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	"github.com/spf13/cobra"
)

// gqlRun executes a GraphQL operation and prints the data as indented JSON.
func gqlRun(query string, vars map[string]any) error {
	currentCtx, err := config.GetCurrentContext()
	if err != nil {
		return err
	}
	data, err := graphqlRequest(context.Background(), currentCtx, query, vars)
	if err != nil {
		return err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		fmt.Println(string(data))
		return nil
	}
	fmt.Println(pretty.String())
	return nil
}

// stringSliceFlag returns the flag values only when the flag was changed.
func changedStringSlice(cmd *cobra.Command, name string) []string {
	if !cmd.Flags().Changed(name) {
		return nil
	}
	v, _ := cmd.Flags().GetStringSlice(name)
	return v
}

// --- realm ---

var realmCmd = &cobra.Command{Use: "realm", Short: "Read and update realm settings"}

var realmShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show realm settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query { realm {
			id realm displayName enabled registrationAllowed loginWithEmailAllowed
			duplicateEmailsAllowed resetPasswordAllowed editUsernameAllowed
			bruteForceProtected sslRequired accessTokenLifespan accessCodeLifespan
			passwordPolicy { minLength maxLength lowerCase upperCase digits specialChars }
		} }`, nil)
	},
}

var realmUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update realm settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		input := map[string]any{}
		for flag, field := range map[string]string{
			"display-name":          "displayName",
			"ssl-required":          "sslRequired",
			"registration-allowed":  "registrationAllowed",
			"login-with-email":      "loginWithEmailAllowed",
			"reset-password":        "resetPasswordAllowed",
			"brute-force":           "bruteForceProtected",
			"enabled":               "enabled",
			"access-token-lifespan": "accessTokenLifespan",
			"access-code-lifespan":  "accessCodeLifespan",
		} {
			if !cmd.Flags().Changed(flag) {
				continue
			}
			switch flag {
			case "display-name", "ssl-required":
				v, _ := cmd.Flags().GetString(flag)
				input[field] = v
			case "access-token-lifespan", "access-code-lifespan":
				v, _ := cmd.Flags().GetInt(flag)
				input[field] = v
			default:
				v, _ := cmd.Flags().GetBool(flag)
				input[field] = v
			}
		}
		if len(input) == 0 {
			return fmt.Errorf("no settings supplied; pass at least one flag")
		}
		return gqlRun(`mutation($input: UpdateRealmInput!) {
			updateRealm(input: $input) { id realm displayName enabled sslRequired }
		}`, map[string]any{"input": input})
	},
}

// --- roles ---

var roleCmd = &cobra.Command{Use: "role", Short: "Manage roles and role mappings", Aliases: []string{"roles"}}

var roleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List realm roles",
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query { roles { id name description composite clientRole containerId } }`, nil)
	},
}

var roleGetCmd = &cobra.Command{
	Use:   "get [ROLE_ID]",
	Short: "Get a role",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query($id: ID!) { role(id: $id) { id name description composite clientRole containerId } }`,
			map[string]any{"id": args[0]})
	},
}

var roleCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a realm or client role",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			return requireInteractive("role creation", "--name")
		}
		input := map[string]any{"name": name}
		if v, _ := cmd.Flags().GetString("description"); v != "" {
			input["description"] = v
		}
		if cmd.Flags().Changed("composite") {
			v, _ := cmd.Flags().GetBool("composite")
			input["composite"] = v
		}
		if cmd.Flags().Changed("client-role") {
			v, _ := cmd.Flags().GetBool("client-role")
			input["clientRole"] = v
		}
		if v, _ := cmd.Flags().GetString("client-id"); v != "" {
			input["clientId"] = v
		}
		return gqlRun(`mutation($input: CreateRoleInput!) { createRole(input: $input) { id name } }`,
			map[string]any{"input": input})
	},
}

var roleUpdateCmd = &cobra.Command{
	Use:   "update [ROLE_ID]",
	Short: "Update a role",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := map[string]any{}
		if v, _ := cmd.Flags().GetString("name"); v != "" {
			input["name"] = v
		}
		if v, _ := cmd.Flags().GetString("description"); v != "" {
			input["description"] = v
		}
		if cmd.Flags().Changed("composite") {
			v, _ := cmd.Flags().GetBool("composite")
			input["composite"] = v
		}
		if len(input) == 0 {
			return fmt.Errorf("no fields supplied; pass at least one flag")
		}
		return gqlRun(`mutation($id: ID!, $input: UpdateRoleInput!) { updateRole(id: $id, input: $input) { id name } }`,
			map[string]any{"id": args[0], "input": input})
	},
}

var roleDeleteCmd = &cobra.Command{
	Use:   "delete [ROLE_ID]",
	Short: "Delete a role",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($id: ID!) { deleteRole(id: $id) }`, map[string]any{"id": args[0]})
	},
}

var roleAssignUserCmd = &cobra.Command{
	Use:   "assign-user [USER_ID] [ROLE_ID]",
	Short: "Add a realm role to a user",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($userId: ID!, $roleId: ID!) { addRealmRoleToUser(userId: $userId, roleId: $roleId) }`,
			map[string]any{"userId": args[0], "roleId": args[1]})
	},
}

var roleUnassignUserCmd = &cobra.Command{
	Use:   "unassign-user [USER_ID] [ROLE_ID]",
	Short: "Remove a realm role from a user",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($userId: ID!, $roleId: ID!) { removeRealmRoleFromUser(userId: $userId, roleId: $roleId) }`,
			map[string]any{"userId": args[0], "roleId": args[1]})
	},
}

var roleAssignGroupCmd = &cobra.Command{
	Use:   "assign-group [GROUP_ID] [ROLE_ID]",
	Short: "Add a realm role to a group",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($groupId: ID!, $roleId: ID!) { addRealmRoleToGroup(groupId: $groupId, roleId: $roleId) }`,
			map[string]any{"groupId": args[0], "roleId": args[1]})
	},
}

var roleUnassignGroupCmd = &cobra.Command{
	Use:   "unassign-group [GROUP_ID] [ROLE_ID]",
	Short: "Remove a realm role from a group",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($groupId: ID!, $roleId: ID!) { removeRealmRoleFromGroup(groupId: $groupId, roleId: $roleId) }`,
			map[string]any{"groupId": args[0], "roleId": args[1]})
	},
}

var roleMappingsCmd = &cobra.Command{
	Use:   "mappings [USER_ID]",
	Short: "Show a user's role mappings",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query($userId: ID!) { roleMappings(userId: $userId) {
			realmMappings { id name }
			clientMappings { id name }
		} }`, map[string]any{"userId": args[0]})
	},
}

var roleCompositeCmd = &cobra.Command{
	Use:   "composite",
	Short: "Create a composite role",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			return requireInteractive("composite role creation", "--name")
		}
		input := map[string]any{"name": name}
		if v, _ := cmd.Flags().GetString("description"); v != "" {
			input["description"] = v
		}
		if realmRoles := changedStringSlice(cmd, "realm-role"); realmRoles != nil {
			input["realmRoles"] = realmRoles
		}
		return gqlRun(`mutation($input: CreateCompositeRoleInput!) { createCompositeRole(input: $input) { id name } }`,
			map[string]any{"input": input})
	},
}

// --- groups ---

var groupCmd = &cobra.Command{Use: "group", Short: "Manage groups and memberships", Aliases: []string{"groups"}}

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query { groups { id name path parentGroupId memberCount } }`, nil)
	},
}

var groupGetCmd = &cobra.Command{
	Use:   "get [GROUP_ID]",
	Short: "Get a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query($id: ID!) { group(id: $id) { id name path parentGroupId memberCount realmRoles { id name } } }`,
			map[string]any{"id": args[0]})
	},
}

var groupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a group",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			return requireInteractive("group creation", "--name")
		}
		input := map[string]any{"name": name}
		if v, _ := cmd.Flags().GetString("path"); v != "" {
			input["path"] = v
		}
		if roles := changedStringSlice(cmd, "realm-role"); roles != nil {
			input["realmRoles"] = roles
		}
		return gqlRun(`mutation($input: CreateGroupInput!) { createGroup(input: $input) { id name path } }`,
			map[string]any{"input": input})
	},
}

var groupUpdateCmd = &cobra.Command{
	Use:   "update [GROUP_ID]",
	Short: "Update a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := map[string]any{}
		if v, _ := cmd.Flags().GetString("name"); v != "" {
			input["name"] = v
		}
		if v, _ := cmd.Flags().GetString("path"); v != "" {
			input["path"] = v
		}
		if roles := changedStringSlice(cmd, "realm-role"); roles != nil {
			input["realmRoles"] = roles
		}
		if len(input) == 0 {
			return fmt.Errorf("no fields supplied; pass at least one flag")
		}
		return gqlRun(`mutation($id: ID!, $input: UpdateGroupInput!) { updateGroup(id: $id, input: $input) { id name path } }`,
			map[string]any{"id": args[0], "input": input})
	},
}

var groupDeleteCmd = &cobra.Command{
	Use:   "delete [GROUP_ID]",
	Short: "Delete a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($id: ID!) { deleteGroup(id: $id) }`, map[string]any{"id": args[0]})
	},
}

var groupMembersCmd = &cobra.Command{
	Use:   "members [GROUP_ID]",
	Short: "List a group's members",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query($groupId: ID!) { groupMembers(groupId: $groupId, first: 100) {
			edges { node { id email firstName lastName } }
		} }`, map[string]any{"groupId": args[0]})
	},
}

var groupAddMemberCmd = &cobra.Command{
	Use:   "add-member [GROUP_ID] [USER_ID]",
	Short: "Add a user to a group",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($groupId: ID!, $userId: ID!) { addUserToGroup(groupId: $groupId, userId: $userId) }`,
			map[string]any{"groupId": args[0], "userId": args[1]})
	},
}

var groupRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member [GROUP_ID] [USER_ID]",
	Short: "Remove a user from a group",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($groupId: ID!, $userId: ID!) { removeUserFromGroup(groupId: $groupId, userId: $userId) }`,
			map[string]any{"groupId": args[0], "userId": args[1]})
	},
}

// --- client scopes ---

var clientScopeCmd = &cobra.Command{Use: "client-scope", Short: "Manage client scopes"}

var clientScopeCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a client scope",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			return requireInteractive("client scope creation", "--name")
		}
		input := map[string]any{"name": name}
		if v, _ := cmd.Flags().GetString("description"); v != "" {
			input["description"] = v
		}
		if v, _ := cmd.Flags().GetString("protocol"); v != "" {
			input["protocol"] = v
		}
		if v, _ := cmd.Flags().GetString("consent-screen-text"); v != "" {
			input["consentScreenText"] = v
		}
		if cmd.Flags().Changed("display-order") {
			v, _ := cmd.Flags().GetInt("display-order")
			input["displayOrder"] = v
		}
		return gqlRun(`mutation($input: CreateClientScopeInput!) { createClientScope(input: $input) { id name } }`,
			map[string]any{"input": input})
	},
}

var clientScopeDeleteCmd = &cobra.Command{
	Use:   "delete [SCOPE_ID]",
	Short: "Delete a client scope",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($id: ID!) { deleteClientScope(id: $id) }`, map[string]any{"id": args[0]})
	},
}

// --- auth flows ---

var authFlowCmd = &cobra.Command{Use: "auth-flow", Short: "Manage authentication flows"}

var authFlowListCmd = &cobra.Command{
	Use:   "list",
	Short: "List authentication flows",
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query { authenticationFlows { id alias displayName description builtIn topLevel } }`, nil)
	},
}

var authFlowGetCmd = &cobra.Command{
	Use:   "get [FLOW_ID]",
	Short: "List a flow's executions",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query($flowId: ID!) { authenticationExecutions(flowId: $flowId) { id execution authenticator requirement priority } }`,
			map[string]any{"flowId": args[0]})
	},
}

var authFlowCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an authentication flow",
	RunE: func(cmd *cobra.Command, args []string) error {
		alias, _ := cmd.Flags().GetString("alias")
		display, _ := cmd.Flags().GetString("display-name")
		if alias == "" || display == "" {
			return requireInteractive("auth flow creation", "--alias --display-name")
		}
		input := map[string]any{"alias": alias, "displayName": display}
		if v, _ := cmd.Flags().GetString("description"); v != "" {
			input["description"] = v
		}
		if cmd.Flags().Changed("top-level") {
			v, _ := cmd.Flags().GetBool("top-level")
			input["topLevel"] = v
		}
		return gqlRun(`mutation($input: CreateAuthenticationFlowInput!) { createAuthenticationFlow(input: $input) { id alias } }`,
			map[string]any{"input": input})
	},
}

var authFlowUpdateCmd = &cobra.Command{
	Use:   "update [FLOW_ID]",
	Short: "Update an authentication flow",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := map[string]any{}
		if v, _ := cmd.Flags().GetString("alias"); v != "" {
			input["alias"] = v
		}
		if v, _ := cmd.Flags().GetString("display-name"); v != "" {
			input["displayName"] = v
		}
		if v, _ := cmd.Flags().GetString("description"); v != "" {
			input["description"] = v
		}
		if len(input) == 0 {
			return fmt.Errorf("no fields supplied; pass at least one flag")
		}
		return gqlRun(`mutation($id: ID!, $input: UpdateAuthenticationFlowInput!) { updateAuthenticationFlow(id: $id, input: $input) { id alias } }`,
			map[string]any{"id": args[0], "input": input})
	},
}

var authFlowDeleteCmd = &cobra.Command{
	Use:   "delete [FLOW_ID]",
	Short: "Delete an authentication flow",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`mutation($id: ID!) { deleteAuthenticationFlow(id: $id) }`, map[string]any{"id": args[0]})
	},
}

var authFlowExecutionsCmd = &cobra.Command{
	Use:   "set-executions [FLOW_ID]",
	Short: "Replace a flow's executions from JSON",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		raw, _ := cmd.Flags().GetString("executions-json")
		if raw == "" {
			return requireInteractive("set executions", "--executions-json")
		}
		var executions []map[string]any
		if err := json.Unmarshal([]byte(raw), &executions); err != nil {
			return fmt.Errorf("invalid --executions-json: %w", err)
		}
		return gqlRun(`mutation($flowId: ID!, $executions: [AuthenticationExecutionInput!]!) {
			updateAuthenticationExecutions(flowId: $flowId, executions: $executions)
		}`, map[string]any{"flowId": args[0], "executions": executions})
	},
}

// --- realm keys ---

var realmKeyCmd = &cobra.Command{Use: "realm-key", Short: "Inspect and update realm signing keys"}

var realmKeyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List realm keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		return gqlRun(`query { realmKeys { id name type providerId active priority } }`, nil)
	},
}

var realmKeyUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Replace realm keys from JSON",
	RunE: func(cmd *cobra.Command, args []string) error {
		raw, _ := cmd.Flags().GetString("keys-json")
		if raw == "" {
			return requireInteractive("realm key update", "--keys-json")
		}
		var keys []map[string]any
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			return fmt.Errorf("invalid --keys-json: %w", err)
		}
		return gqlRun(`mutation($input: UpdateRealmKeysInput!) { updateRealmKeys(input: $input) { id name active } }`,
			map[string]any{"input": map[string]any{"keys": keys}})
	},
}

// --- sessions ---

// Session revoke/revoke-all/logout-user moved to gRPC (AuthService.ClearUserSessions).
// See apps/sssoctl/cmd/session.go.

// --- user GraphQL extras ---

var userExecuteActionsCmd = &cobra.Command{
	Use:   "execute-actions [USER_ID]",
	Short: "Run Keycloak-style required actions (e.g. UPDATE_PASSWORD)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		actions, _ := cmd.Flags().GetStringSlice("action")
		if len(actions) == 0 {
			return requireInteractive("execute actions", "--action")
		}
		return gqlRun(`mutation($userId: ID!, $actions: [String!]!) { executeActions(userId: $userId, actions: $actions) }`,
			map[string]any{"userId": args[0], "actions": actions})
	},
}

func init() {
	rootCmd.AddCommand(realmCmd)
	realmCmd.AddCommand(realmShowCmd, realmUpdateCmd)
	realmUpdateCmd.Flags().String("display-name", "", "Realm display name")
	realmUpdateCmd.Flags().String("ssl-required", "", "SSL requirement (e.g. external)")
	realmUpdateCmd.Flags().Bool("registration-allowed", false, "Allow self-registration")
	realmUpdateCmd.Flags().Bool("login-with-email", false, "Allow login with email")
	realmUpdateCmd.Flags().Bool("reset-password", false, "Allow password reset")
	realmUpdateCmd.Flags().Bool("brute-force", false, "Enable brute-force protection")
	realmUpdateCmd.Flags().Bool("enabled", false, "Enable the realm")
	realmUpdateCmd.Flags().Int("access-token-lifespan", 0, "Access token lifespan (seconds)")
	realmUpdateCmd.Flags().Int("access-code-lifespan", 0, "Authorization code lifespan (seconds)")

	rootCmd.AddCommand(roleCmd)
	roleCmd.AddCommand(roleListCmd, roleGetCmd, roleCreateCmd, roleUpdateCmd, roleDeleteCmd,
		roleAssignUserCmd, roleUnassignUserCmd, roleAssignGroupCmd, roleUnassignGroupCmd, roleMappingsCmd, roleCompositeCmd)
	roleCreateCmd.Flags().String("name", "", "Role name")
	roleCreateCmd.Flags().String("description", "", "Description")
	roleCreateCmd.Flags().Bool("composite", false, "Composite role")
	roleCreateCmd.Flags().Bool("client-role", false, "Client role")
	roleCreateCmd.Flags().String("client-id", "", "Owning client ID for client roles")
	roleUpdateCmd.Flags().String("name", "", "New name")
	roleUpdateCmd.Flags().String("description", "", "New description")
	roleUpdateCmd.Flags().Bool("composite", false, "Composite role")
	roleCompositeCmd.Flags().String("name", "", "Role name")
	roleCompositeCmd.Flags().String("description", "", "Description")
	roleCompositeCmd.Flags().StringSlice("realm-role", nil, "Realm role ID to include (repeatable)")

	rootCmd.AddCommand(groupCmd)
	groupCmd.AddCommand(groupListCmd, groupGetCmd, groupCreateCmd, groupUpdateCmd, groupDeleteCmd,
		groupMembersCmd, groupAddMemberCmd, groupRemoveMemberCmd)
	groupCreateCmd.Flags().String("name", "", "Group name")
	groupCreateCmd.Flags().String("path", "", "Group path")
	groupCreateCmd.Flags().StringSlice("realm-role", nil, "Realm role ID (repeatable)")
	groupUpdateCmd.Flags().String("name", "", "New name")
	groupUpdateCmd.Flags().String("path", "", "New path")
	groupUpdateCmd.Flags().StringSlice("realm-role", nil, "Realm role ID (repeatable)")

	rootCmd.AddCommand(clientScopeCmd)
	clientScopeCmd.AddCommand(clientScopeCreateCmd, clientScopeDeleteCmd)
	clientScopeCreateCmd.Flags().String("name", "", "Scope name")
	clientScopeCreateCmd.Flags().String("description", "", "Description")
	clientScopeCreateCmd.Flags().String("protocol", "", "Protocol (openid-connect)")
	clientScopeCreateCmd.Flags().String("consent-screen-text", "", "Consent screen text")
	clientScopeCreateCmd.Flags().Int("display-order", 0, "Display order")

	rootCmd.AddCommand(authFlowCmd)
	authFlowCmd.AddCommand(authFlowListCmd, authFlowGetCmd, authFlowCreateCmd, authFlowUpdateCmd, authFlowDeleteCmd, authFlowExecutionsCmd)
	authFlowCreateCmd.Flags().String("alias", "", "Flow alias")
	authFlowCreateCmd.Flags().String("display-name", "", "Display name")
	authFlowCreateCmd.Flags().String("description", "", "Description")
	authFlowCreateCmd.Flags().Bool("top-level", false, "Top-level flow")
	authFlowUpdateCmd.Flags().String("alias", "", "New alias")
	authFlowUpdateCmd.Flags().String("display-name", "", "New display name")
	authFlowUpdateCmd.Flags().String("description", "", "New description")
	authFlowExecutionsCmd.Flags().String("executions-json", "", "JSON array of executions")

	rootCmd.AddCommand(realmKeyCmd)
	realmKeyCmd.AddCommand(realmKeyListCmd, realmKeyUpdateCmd)
	realmKeyUpdateCmd.Flags().String("keys-json", "", "JSON array of keys")

	userCmd.AddCommand(userExecuteActionsCmd)
	userExecuteActionsCmd.Flags().StringSlice("action", nil, "Required action (repeatable)")

	clientCmd.AddCommand(clientGenerateSecretCmd, clientGenerateKeysCmd)
	clientGenerateKeysCmd.Flags().String("key-type", "RSA", "Key type")
	clientGenerateKeysCmd.Flags().Int("key-bits", 2048, "Key size")
}
