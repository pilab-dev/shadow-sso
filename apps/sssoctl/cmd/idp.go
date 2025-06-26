package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var idpCmd = &cobra.Command{
	Use:     "idp",
	Short:   "Manage external Identity Provider (IdP) configurations",
	Aliases: []string{"idps"},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := config.InitConfig(); err != nil {
			return err
		}
		_, err := config.GetCurrentContext()
		if err != nil {
			return fmt.Errorf("failed to get current context: %w. Use 'ssoctl config set-context' or 'ssoctl auth login'", err)
		}
		return nil
	},
}

// Helper to parse AttributeMapping flag
func parseAttributeMappings(mappingsStr []string) ([]*ssov1.AttributeMappingProto, error) {
	mappings := make([]*ssov1.AttributeMappingProto, 0, len(mappingsStr))
	for _, mStr := range mappingsStr {
		parts := strings.SplitN(mStr, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid attribute mapping format: '%s'. Expected 'externalKey=localKey'", mStr)
		}
		mappings = append(mappings, &ssov1.AttributeMappingProto{
			ExternalAttributeName: strings.TrimSpace(parts[0]),
			LocalUserAttribute:    strings.TrimSpace(parts[1]),
		})
	}
	return mappings, nil
}

var idpAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new IdP configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		typeStr, _ := cmd.Flags().GetString("type") // "OIDC" or "SAML"
		isEnabled, _ := cmd.Flags().GetBool("enabled")

		oidcClientID, _ := cmd.Flags().GetString("oidc-client-id")
		oidcClientSecret, _ := cmd.Flags().GetString("oidc-client-secret")
		oidcIssuerURL, _ := cmd.Flags().GetString("oidc-issuer-url")
		oidcScopes, _ := cmd.Flags().GetStringSlice("oidc-scopes")

		// LDAP flags
		ldapServerURL, _ := cmd.Flags().GetString("ldap-server-url")
		ldapBindDN, _ := cmd.Flags().GetString("ldap-bind-dn")
		ldapBindPassword, _ := cmd.Flags().GetString("ldap-bind-password")
		ldapUserBaseDN, _ := cmd.Flags().GetString("ldap-user-base-dn")
		ldapUserFilter, _ := cmd.Flags().GetString("ldap-user-filter")
		ldapAttrUsername, _ := cmd.Flags().GetString("ldap-attr-username")
		ldapAttrEmail, _ := cmd.Flags().GetString("ldap-attr-email")
		ldapAttrFirstName, _ := cmd.Flags().GetString("ldap-attr-firstname")
		ldapAttrLastName, _ := cmd.Flags().GetString("ldap-attr-lastname")
		ldapAttrGroups, _ := cmd.Flags().GetString("ldap-attr-groups")
		ldapStartTLS, _ := cmd.Flags().GetBool("ldap-starttls")
		ldapSkipTLSVerify, _ := cmd.Flags().GetBool("ldap-skip-tls-verify")

		mappingsStr, _ := cmd.Flags().GetStringSlice("map-attribute")

		if name == "" {
			return errors.New("--name is required")
		}
		if typeStr == "" {
			return errors.New("--type (OIDC/SAML/LDAP) is required")
		}

		var idpTypeProto ssov1.IdPTypeProto
		// Placeholder for ssov1.IdPTypeProto_IDP_TYPE_LDAP - this needs to be added to protobuf definitions
		// For now, we'll handle type string and assume the server can interpret it or proto will be updated.
		// const IdPTypeProto_IDP_TYPE_LDAP ssov1.IdPTypeProto = 2 // Example, actual value from proto

		if strings.EqualFold(typeStr, "OIDC") {
			idpTypeProto = ssov1.IdPTypeProto_IDP_TYPE_OIDC
			if oidcIssuerURL == "" || oidcClientID == "" {
				return errors.New("--oidc-issuer-url and --oidc-client-id are required for OIDC type")
			}
		} else if strings.EqualFold(typeStr, "SAML") {
			idpTypeProto = ssov1.IdPTypeProto_IDP_TYPE_SAML
			// SAML specific checks would go here
			return errors.New("SAML IdP type is not fully supported yet") // Placeholder
		} else if strings.EqualFold(typeStr, "LDAP") {
			// idpTypeProto = IdPTypeProto_IDP_TYPE_LDAP // Use actual proto enum when available
			idpTypeProto = ssov1.IdPTypeProto(2) // Assuming 2 is LDAP, needs proto update
			if ldapServerURL == "" || ldapUserBaseDN == "" || ldapUserFilter == "" {
				return errors.New("--ldap-server-url, --ldap-user-base-dn, and --ldap-user-filter are required for LDAP type")
			}
		} else {
			return errors.New("invalid --type: must be 'OIDC', 'SAML', or 'LDAP'")
		}

		attributeMappings, err := parseAttributeMappings(mappingsStr)
		if err != nil {
			return err
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.IdPManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.AddIdPRequest{
			Name:              name,
			Type:              idpTypeProto,
			IsEnabled:         isEnabled,
			OidcScopes:        oidcScopes,
			AttributeMappings: attributeMappings,
		}

		if cmd.Flags().Changed("oidc-client-id") {
			req.OidcClientId = &oidcClientID
		}
		if cmd.Flags().Changed("oidc-client-secret") {
			req.OidcClientSecret = &oidcClientSecret
		}
		if cmd.Flags().Changed("oidc-issuer-url") {
			req.OidcIssuerUrl = &oidcIssuerURL
		}

		// Populate LDAP fields if type is LDAP
		// These req.Ldap... fields depend on protobuf updates.
		if idpTypeProto == ssov1.IdPTypeProto(2) { // Assuming 2 is LDAP
			req.LdapServerUrl = ldapServerURL
			req.LdapUserBaseDn = ldapUserBaseDN
			req.LdapUserFilter = ldapUserFilter
			req.LdapAttrUsername = ldapAttrUsername
			req.LdapAttrEmail = ldapAttrEmail
			req.LdapAttrFirstname = ldapAttrFirstName
			req.LdapAttrLastname = ldapAttrLastName
			req.LdapAttrGroups = ldapAttrGroups
			req.LdapStarttls = ldapStartTLS
			req.LdapSkipTlsVerify = ldapSkipTLSVerify
			if cmd.Flags().Changed("ldap-bind-dn") { // Optional
				req.LdapBindDn = ldapBindDN
			}
			if cmd.Flags().Changed("ldap-bind-password") { // Optional
				req.LdapBindPassword = ldapBindPassword
			}
		}

		resp, err := apiClient.AddIdP(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to add IdP: %w", err)
		}

		if resp.Msg == nil || resp.Msg.Idp == nil {
			return errors.New("server did not return IdP information")
		}

		fmt.Println("IdP configuration added successfully:")
		out, _ := yaml.Marshal(resp.Msg.Idp) // Server omits secret in response
		fmt.Println(string(out))
		return nil
	},
}

var idpGetCmd = &cobra.Command{
	Use:   "get [IDP_ID]",
	Short: "Get IdP configuration details by ID", // Changed to specify ID
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		idpID := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.IdPManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.GetIdPRequest{Id: idpID}
		resp, err := apiClient.GetIdP(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to get IdP: %w", err)
		}

		if resp.Msg == nil || resp.Msg.Idp == nil {
			return errors.New("server did not return IdP information")
		}
		out, _ := yaml.Marshal(resp.Msg.Idp) // Server omits secret
		fmt.Println(string(out))
		return nil
	},
}

var idpListCmd = &cobra.Command{
	Use:   "list",
	Short: "List IdP configurations",
	RunE: func(cmd *cobra.Command, args []string) error {
		onlyEnabled, _ := cmd.Flags().GetBool("only-enabled")
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.IdPManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.ListIdPsRequest{OnlyEnabled: onlyEnabled}
		resp, err := apiClient.ListIdPs(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to list IdPs: %w", err)
		}

		if resp.Msg == nil || len(resp.Msg.Idps) == 0 {
			fmt.Println("No IdP configurations found.")
			return nil
		}
		out, _ := yaml.Marshal(resp.Msg.Idps) // Server omits secrets
		fmt.Println(string(out))
		return nil
	},
}

var idpUpdateCmd = &cobra.Command{
	Use:   "update [IDP_ID]",
	Short: "Update an IdP configuration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		idpID := args[0]
		updateReq := &ssov1.UpdateIdPRequest{Id: idpID}
		changed := false

		if cmd.Flags().Changed("name") {
			name, _ := cmd.Flags().GetString("name")
			updateReq.Name = name
			changed = true
		}
		if cmd.Flags().Changed("enabled") {
			isEnabled, _ := cmd.Flags().GetBool("enabled")
			updateReq.IsEnabled = isEnabled
			changed = true
		}
		if cmd.Flags().Changed("oidc-client-id") {
			val, _ := cmd.Flags().GetString("oidc-client-id")
			updateReq.OidcClientId = &val
			changed = true
		}
		if cmd.Flags().Changed("oidc-client-secret") {
			val, _ := cmd.Flags().GetString("oidc-client-secret")
			updateReq.OidcClientSecret = &val
			changed = true
		}
		if cmd.Flags().Changed("oidc-issuer-url") {
			val, _ := cmd.Flags().GetString("oidc-issuer-url")
			updateReq.OidcIssuerUrl = &val
			changed = true
		}
		if cmd.Flags().Changed("oidc-scopes") {
			scopes, _ := cmd.Flags().GetStringSlice("oidc-scopes")
			updateReq.OidcScopes = scopes
			changed = true
		}
		if cmd.Flags().Changed("map-attribute") {
			mappingsStr, _ := cmd.Flags().GetStringSlice("map-attribute")
			mappings, errMap := parseAttributeMappings(mappingsStr)
			if errMap != nil {
				return errMap
			}
			updateReq.AttributeMappings = mappings
			changed = true
		}

		// LDAP specific fields for update
		if cmd.Flags().Changed("ldap-server-url") {
			val, _ := cmd.Flags().GetString("ldap-server-url")
			updateReq.LdapServerUrl = &val
			changed = true
		}
		if cmd.Flags().Changed("ldap-bind-dn") {
			val, _ := cmd.Flags().GetString("ldap-bind-dn")
			updateReq.LdapBindDn = &val // Pointer to allow setting to empty
			changed = true
		}
		if cmd.Flags().Changed("ldap-bind-password") {
			val, _ := cmd.Flags().GetString("ldap-bind-password")
			updateReq.LdapBindPassword = &val // Pointer to allow setting to empty
			changed = true
		}
		if cmd.Flags().Changed("ldap-user-base-dn") {
			val, _ := cmd.Flags().GetString("ldap-user-base-dn")
			updateReq.LdapUserBaseDn = &val
			changed = true
		}
		if cmd.Flags().Changed("ldap-user-filter") {
			val, _ := cmd.Flags().GetString("ldap-user-filter")
			updateReq.LdapUserFilter = &val
			changed = true
		}
		if cmd.Flags().Changed("ldap-attr-username") {
			val, _ := cmd.Flags().GetString("ldap-attr-username")
			updateReq.LdapAttrUsername = &val
			changed = true
		}
		if cmd.Flags().Changed("ldap-attr-email") {
			val, _ := cmd.Flags().GetString("ldap-attr-email")
			updateReq.LdapAttrEmail = &val
			changed = true
		}
		if cmd.Flags().Changed("ldap-attr-firstname") {
			val, _ := cmd.Flags().GetString("ldap-attr-firstname")
			updateReq.LdapAttrFirstname = &val
			changed = true
		}
		if cmd.Flags().Changed("ldap-attr-lastname") {
			val, _ := cmd.Flags().GetString("ldap-attr-lastname")
			updateReq.LdapAttrLastname = &val
			changed = true
		}
		if cmd.Flags().Changed("ldap-attr-groups") {
			val, _ := cmd.Flags().GetString("ldap-attr-groups")
			updateReq.LdapAttrGroups = &val
			changed = true
		}
		if cmd.Flags().Changed("ldap-starttls") {
			val, _ := cmd.Flags().GetBool("ldap-starttls")
			updateReq.LdapStarttls = &val
			changed = true
		}
		if cmd.Flags().Changed("ldap-skip-tls-verify") {
			val, _ := cmd.Flags().GetBool("ldap-skip-tls-verify")
			updateReq.LdapSkipTlsVerify = &val
			changed = true
		}

		if !changed {
			return errors.New("at least one field to update must be provided via flags")
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.IdPManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		resp, err := apiClient.UpdateIdP(context.Background(), connect.NewRequest(updateReq))
		if err != nil {
			return fmt.Errorf("failed to update IdP: %w", err)
		}

		fmt.Println("IdP configuration updated successfully:")
		out, _ := yaml.Marshal(resp.Msg.Idp) // Server omits secret
		fmt.Println(string(out))
		return nil
	},
}

var idpDeleteCmd = &cobra.Command{
	Use:   "delete [IDP_ID]",
	Short: "Delete an IdP configuration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		idpID := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.IdPManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.DeleteIdPRequest{Id: idpID}
		_, err = apiClient.DeleteIdP(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to delete IdP: %w", err)
		}

		fmt.Printf("IdP configuration '%s' deleted successfully.\n", idpID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(idpCmd)
	idpCmd.AddCommand(idpAddCmd)
	idpCmd.AddCommand(idpGetCmd)
	idpCmd.AddCommand(idpListCmd)
	idpCmd.AddCommand(idpUpdateCmd)
	idpCmd.AddCommand(idpDeleteCmd)

	// Flags for idpAddCmd
	idpAddCmd.Flags().StringP("name", "n", "", "Unique name for the IdP configuration (required)")
	idpAddCmd.Flags().StringP("type", "t", "", "IdP Type: 'OIDC' or 'SAML' (required)")
	idpAddCmd.Flags().Bool("enabled", true, "Set IdP as enabled (default true)")
	idpAddCmd.Flags().String("oidc-client-id", "", "OIDC Client ID")
	idpAddCmd.Flags().String("oidc-client-secret", "", "OIDC Client Secret")
	idpAddCmd.Flags().String("oidc-issuer-url", "", "OIDC Issuer URL")
	idpAddCmd.Flags().StringSlice("oidc-scopes", []string{"openid", "profile", "email"}, "OIDC scopes (comma-separated or multiple flags)")

	// LDAP specific flags for idpAddCmd
	idpAddCmd.Flags().String("ldap-server-url", "", "LDAP Server URL (e.g., ldap://ldap.example.com:389)")
	idpAddCmd.Flags().String("ldap-bind-dn", "", "LDAP Bind DN (for searching users, optional)")
	idpAddCmd.Flags().String("ldap-bind-password", "", "LDAP Bind Password (sensitive, for search user)")
	idpAddCmd.Flags().String("ldap-user-base-dn", "", "Base DN for user search (e.g., ou=users,dc=example,dc=com)")
	idpAddCmd.Flags().String("ldap-user-filter", "", "LDAP User Search Filter (e.g., (uid=%s) or (sAMAccountName=%s))")
	idpAddCmd.Flags().String("ldap-attr-username", "uid", "LDAP attribute for username (e.g., uid, sAMAccountName)")
	idpAddCmd.Flags().String("ldap-attr-email", "mail", "LDAP attribute for user email")
	idpAddCmd.Flags().String("ldap-attr-firstname", "givenName", "LDAP attribute for user first name")
	idpAddCmd.Flags().String("ldap-attr-lastname", "sn", "LDAP attribute for user last name")
	idpAddCmd.Flags().String("ldap-attr-groups", "memberOf", "LDAP attribute for user group membership")
	idpAddCmd.Flags().Bool("ldap-starttls", false, "Use StartTLS for LDAP connection")
	idpAddCmd.Flags().Bool("ldap-skip-tls-verify", false, "Skip TLS certificate verification for LDAP (unsafe, for testing only)")

	idpAddCmd.Flags().StringSlice("map-attribute", []string{}, "Attribute mapping 'ExternalKey=LocalUserKey' (e.g., 'sub=UserID', 'email=Email') (can be repeated)")

	// Flags for idpListCmd
	idpListCmd.Flags().Bool("only-enabled", false, "List only enabled IdP configurations")

	// Flags for idpUpdateCmd (similar to add, but all optional)
	idpUpdateCmd.Flags().StringP("name", "n", "", "New unique name for the IdP configuration")
	// For boolean flags like 'enabled', if not provided, it defaults to false.
	// To make it truly optional for update (i.e., only update if flag is explicitly set),
	// one might need to use different flag types or check cmd.Flags().Changed("enabled").
	// The current service logic for UpdateIdP updates `IsEnabled` based on the bool value passed,
	// which will be `false` if flag not set. This is acceptable if that's the desired behavior for updates.
	// If we want "don't change unless specified", a nullable bool or string "true/false/unset" flag is needed.
	// For now, GetBool's default (false if not set) will be passed.
	idpUpdateCmd.Flags().Bool("enabled", false, "Set IdP enabled status (true or false). If not set, might default to false in update.")
	idpUpdateCmd.Flags().String("oidc-client-id", "", "New OIDC Client ID")
	idpUpdateCmd.Flags().String("oidc-client-secret", "", "New OIDC Client Secret (sensitive, use with caution)")
	idpUpdateCmd.Flags().String("oidc-issuer-url", "", "New OIDC Issuer URL")
	idpUpdateCmd.Flags().StringSlice("oidc-scopes", []string{}, "New set of OIDC scopes")
	idpUpdateCmd.Flags().StringSlice("map-attribute", []string{}, "New set of attribute mappings 'ExternalKey=LocalUserKey'")

	// LDAP specific flags for idpUpdateCmd
	idpUpdateCmd.Flags().String("ldap-server-url", "", "New LDAP Server URL")
	idpUpdateCmd.Flags().String("ldap-bind-dn", "", "New LDAP Bind DN (set to empty string to remove)")
	idpUpdateCmd.Flags().String("ldap-bind-password", "", "New LDAP Bind Password (sensitive, use with caution)")
	idpUpdateCmd.Flags().String("ldap-user-base-dn", "", "New Base DN for user search")
	idpUpdateCmd.Flags().String("ldap-user-filter", "", "New LDAP User Search Filter")
	idpUpdateCmd.Flags().String("ldap-attr-username", "", "New LDAP attribute for username")
	idpUpdateCmd.Flags().String("ldap-attr-email", "", "New LDAP attribute for user email")
	idpUpdateCmd.Flags().String("ldap-attr-firstname", "", "New LDAP attribute for user first name")
	idpUpdateCmd.Flags().String("ldap-attr-lastname", "", "New LDAP attribute for user last name")
	idpUpdateCmd.Flags().String("ldap-attr-groups", "", "New LDAP attribute for user group membership")
	idpUpdateCmd.Flags().Bool("ldap-starttls", false, "Enable/Disable StartTLS for LDAP. Use with caution if changing existing.")
	idpUpdateCmd.Flags().Bool("ldap-skip-tls-verify", false, "Enable/Disable skipping TLS cert verification for LDAP. Use with caution.")
}
