package cmd

import (
	"bufio"
	"context"
	"time"

	// "encoding/json" // Not used directly, yaml is used for general struct output
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

var clientCmd = &cobra.Command{
	Use:     "client",
	Short:   "Manage OAuth2 clients",
	Aliases: []string{"clients"},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Ensure config is loaded and current context is available
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

// Helper function for checking string slice presence
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

var clientRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new OAuth2 client",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		clientTypeStr, _ := cmd.Flags().GetString("type") // "confidential" or "public"
		redirectURIs, _ := cmd.Flags().GetStringSlice("redirect-uris")
		postLogoutRedirectURIs, _ := cmd.Flags().GetStringSlice("post-logout-redirect-uris")
		scopes, _ := cmd.Flags().GetStringSlice("scopes")
		grantTypes, _ := cmd.Flags().GetStringSlice("grant-types")
		tokenEndpointAuthMethod, _ := cmd.Flags().GetString("token-endpoint-auth-method")
		jwksURI, _ := cmd.Flags().GetString("jwks-uri")
		contacts, _ := cmd.Flags().GetStringSlice("contacts")
		logoURI, _ := cmd.Flags().GetString("logo-uri")
		policyURI, _ := cmd.Flags().GetString("policy-uri")
		termsURI, _ := cmd.Flags().GetString("terms-uri")
		requireConsent, _ := cmd.Flags().GetBool("require-consent")
		// requirePKCE is usually determined by server based on client type

		ldapAttrEmail, _ := cmd.Flags().GetString("ldap-attr-email")
		ldapAttrFirstName, _ := cmd.Flags().GetString("ldap-attr-firstname")
		ldapAttrLastName, _ := cmd.Flags().GetString("ldap-attr-lastname")
		ldapAttrGroups, _ := cmd.Flags().GetString("ldap-attr-groups")
		ldapCustomClaims, _ := cmd.Flags().GetStringToString("ldap-custom-claims")

		if name == "" {
			return errors.New("--name is required")
		}
		if clientTypeStr == "" {
			return errors.New("--type (confidential/public) is required")
		}

		var clientTypeProto ssov1.ClientTypeProto
		if strings.EqualFold(clientTypeStr, "confidential") {
			clientTypeProto = ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL
		} else if strings.EqualFold(clientTypeStr, "public") {
			clientTypeProto = ssov1.ClientTypeProto_CLIENT_TYPE_PUBLIC
		} else {
			return errors.New("invalid --type: must be 'confidential' or 'public'")
		}

		// Basic validation for redirect URIs based on some common flows
		if len(redirectURIs) == 0 && clientTypeProto == ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL &&
			(contains(grantTypes, "authorization_code") || contains(grantTypes, "implicit")) {
			fmt.Println("Warning: No redirect URIs provided for a confidential client using authorization_code or implicit grant types.")
		}
		if len(redirectURIs) == 0 && clientTypeProto == ssov1.ClientTypeProto_CLIENT_TYPE_PUBLIC &&
			contains(grantTypes, "authorization_code") { // PKCE flow (implicit public) needs redirect URI
			fmt.Println("Warning: No redirect URIs provided for a public client using authorization_code grant type.")
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.ClientManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.RegisterClientRequest{
			ClientName:              name,
			ClientType:              clientTypeProto,
			RedirectUris:            redirectURIs,
			PostLogoutRedirectUris:  postLogoutRedirectURIs,
			AllowedScopes:           scopes,
			AllowedGrantTypes:       grantTypes,
			TokenEndpointAuthMethod: tokenEndpointAuthMethod,
			JwksUri:                 jwksURI,
			Contacts:                contacts,
			LogoUri:                 logoURI,
			PolicyUri:               policyURI,
			TermsUri:                termsURI,
			RequireConsent:          requireConsent,
			// LDAP Mapping fields - these depend on protobuf updates for ssov1.RegisterClientRequest
			ClientLdapAttributeEmail:      ldapAttrEmail,
			ClientLdapAttributeFirstName:  ldapAttrFirstName,
			ClientLdapAttributeLastName:   ldapAttrLastName,
			ClientLdapAttributeGroups:     ldapAttrGroups,
			ClientLdapCustomClaimsMapping: ldapCustomClaims,
		}
		resp, err := apiClient.RegisterClient(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to register client: %w", err)
		}

		if resp.Msg == nil || resp.Msg.Client == nil {
			return errors.New("server did not return client information")
		}

		fmt.Println("Client registered successfully:")
		clientOutput := map[string]interface{}{
			"client_id":                  resp.Msg.Client.ClientId,
			"client_name":                resp.Msg.Client.ClientName,
			"client_type":                resp.Msg.Client.ClientType.String(),
			"redirect_uris":              resp.Msg.Client.RedirectUris,
			"post_logout_redirect_uris":  resp.Msg.Client.PostLogoutRedirectUris,
			"allowed_scopes":             resp.Msg.Client.AllowedScopes,
			"allowed_grant_types":        resp.Msg.Client.AllowedGrantTypes,
			"token_endpoint_auth_method": resp.Msg.Client.TokenEndpointAuthMethod,
			"jwks_uri":                   resp.Msg.Client.JwksUri,
			"contacts":                   resp.Msg.Client.Contacts,
			"logo_uri":                   resp.Msg.Client.LogoUri,
			"policy_uri":                 resp.Msg.Client.PolicyUri,
			"terms_uri":                  resp.Msg.Client.TermsUri,
			"require_consent":            resp.Msg.Client.RequireConsent,
			"require_pkce":               resp.Msg.Client.RequirePkce,
			"is_active":                  resp.Msg.Client.IsActive,
			"created_at":                 resp.Msg.Client.CreatedAt.AsTime().Format(time.RFC3339),
			"updated_at":                 resp.Msg.Client.UpdatedAt.AsTime().Format(time.RFC3339),
		}
		if resp.Msg.Client.ClientType == ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL && resp.Msg.Client.ClientSecret != "" {
			clientOutput["client_secret"] = resp.Msg.Client.ClientSecret
			fmt.Println("IMPORTANT: Store the client_secret securely. It will not be shown again.")
		}

		out, _ := yaml.Marshal(clientOutput)
		fmt.Println(string(out))
		return nil
	},
}

var clientGetCmd = &cobra.Command{
	Use:   "get [CLIENT_ID]",
	Short: "Get OAuth2 client details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		clientID := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.ClientManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.GetClientRequest{ClientId: clientID}
		resp, err := apiClient.GetClient(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to get client: %w", err)
		}

		if resp.Msg == nil || resp.Msg.Client == nil {
			return errors.New("server did not return client information")
		}
		out, _ := yaml.Marshal(resp.Msg.Client) // ClientSecret will be empty here by server design
		fmt.Println(string(out))
		return nil
	},
}

var clientListCmd = &cobra.Command{
	Use:   "list",
	Short: "List OAuth2 clients",
	RunE: func(cmd *cobra.Command, args []string) error {
		pageSize, _ := cmd.Flags().GetInt32("page-size")
		pageToken, _ := cmd.Flags().GetString("page-token")

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.ClientManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.ListClientsRequest{PageSize: pageSize, PageToken: pageToken}
		resp, err := apiClient.ListClients(context.Background(), connect.NewRequest(req))
		if err != nil {
			// Handle unimplemented error gracefully if ListClients is not yet on server
			if connect.CodeOf(err) == connect.CodeUnimplemented {
				return errors.New("ListClients feature is not yet available on the server")
			}
			return fmt.Errorf("failed to list clients: %w", err)
		}

		if resp.Msg == nil || len(resp.Msg.Clients) == 0 {
			fmt.Println("No clients found.")
			return nil
		}
		out, _ := yaml.Marshal(resp.Msg.Clients)
		fmt.Println(string(out))
		if resp.Msg.NextPageToken != "" {
			fmt.Printf("\nNext page token: %s\n", resp.Msg.NextPageToken)
		}
		return nil
	},
}

var clientUpdateCmd = &cobra.Command{
	Use:   "update [CLIENT_ID]",
	Short: "Update an OAuth2 client",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		clientID := args[0]
		updateReq := &ssov1.UpdateClientRequest{ClientId: clientID}
		changed := false

		if cmd.Flags().Changed("name") {
			name, _ := cmd.Flags().GetString("name")
			updateReq.ClientName = name
			changed = true
		}
		if cmd.Flags().Changed("redirect-uris") {
			redirectURIs, _ := cmd.Flags().GetStringSlice("redirect-uris")
			updateReq.RedirectUris = redirectURIs
			changed = true
		}
		if cmd.Flags().Changed("post-logout-redirect-uris") {
			postLogoutRedirectURIs, _ := cmd.Flags().GetStringSlice("post-logout-redirect-uris")
			updateReq.PostLogoutRedirectUris = postLogoutRedirectURIs
			changed = true
		}
		if cmd.Flags().Changed("scopes") {
			scopes, _ := cmd.Flags().GetStringSlice("scopes")
			updateReq.AllowedScopes = scopes
			changed = true
		}
		if cmd.Flags().Changed("jwks-uri") {
			jwksURI, _ := cmd.Flags().GetString("jwks-uri")
			updateReq.JwksUri = jwksURI // Proto field is optional string
			changed = true
		}
		if cmd.Flags().Changed("contacts") {
			contacts, _ := cmd.Flags().GetStringSlice("contacts")
			updateReq.Contacts = contacts
			changed = true
		}
		if cmd.Flags().Changed("logo-uri") {
			logoURI, _ := cmd.Flags().GetString("logo-uri")
			updateReq.LogoUri = logoURI
			changed = true
		}
		if cmd.Flags().Changed("policy-uri") {
			policyURI, _ := cmd.Flags().GetString("policy-uri")
			updateReq.PolicyUri = policyURI
			changed = true
		}
		if cmd.Flags().Changed("terms-uri") {
			termsURI, _ := cmd.Flags().GetString("terms-uri")
			updateReq.TermsUri = termsURI
			changed = true
		}
		if cmd.Flags().Changed("require-consent") {
			requireConsent, _ := cmd.Flags().GetBool("require-consent")
			updateReq.RequireConsent = requireConsent
			changed = true
		}
		if cmd.Flags().Changed("active") {
			isActive, _ := cmd.Flags().GetBool("active") // Changed to GetBool
			updateReq.IsActive = isActive
			changed = true
		}

		// LDAP Attribute Mapping Flags for clientUpdateCmd
		// For string fields, if the flag is present, we update. To clear a field, user should pass an empty string.
		// For the map, providing the flag means replacing the map.
		if cmd.Flags().Changed("ldap-attr-email") {
			val, _ := cmd.Flags().GetString("ldap-attr-email")
			updateReq.ClientLdapAttributeEmail = val // Assuming proto field is string, not *string
			changed = true
		}
		if cmd.Flags().Changed("ldap-attr-firstname") {
			val, _ := cmd.Flags().GetString("ldap-attr-firstname")
			updateReq.ClientLdapAttributeFirstName = val
			changed = true
		}
		if cmd.Flags().Changed("ldap-attr-lastname") {
			val, _ := cmd.Flags().GetString("ldap-attr-lastname")
			updateReq.ClientLdapAttributeLastName = val
			changed = true
		}
		if cmd.Flags().Changed("ldap-attr-groups") {
			val, _ := cmd.Flags().GetString("ldap-attr-groups")
			updateReq.ClientLdapAttributeGroups = val
			changed = true
		}
		if cmd.Flags().Changed("ldap-custom-claims") {
			val, _ := cmd.Flags().GetStringToString("ldap-custom-claims")
			updateReq.ClientLdapCustomClaimsMapping = val // Assumes proto field is map[string]string
			changed = true
		}
		// Client type, grant types, token auth method are generally not updated. Secret has its own flow.

		if !changed {
			return errors.New("at least one field to update must be provided via flags")
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.ClientManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		resp, err := apiClient.UpdateClient(context.Background(), connect.NewRequest(updateReq))
		if err != nil {
			return fmt.Errorf("failed to update client: %w", err)
		}

		fmt.Println("Client updated successfully:")
		out, _ := yaml.Marshal(resp.Msg.Client)
		fmt.Println(string(out))
		return nil
	},
}

var clientDeleteCmd = &cobra.Command{
	Use:   "delete [CLIENT_ID]",
	Short: "Delete an OAuth2 client",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		clientID := args[0]
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			fmt.Printf("Are you sure you want to delete client '%s'? This action cannot be undone. (yes/no): ", clientID)
			reader := cmd.InOrStdin()
			scanner := bufio.NewScanner(reader)
			scanner.Scan()
			confirm := scanner.Text()
			if strings.TrimSpace(strings.ToLower(confirm)) != "yes" {
				fmt.Println("Client deletion cancelled.")
				return nil
			}
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.ClientManagementServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.DeleteClientRequest{ClientId: clientID}
		_, err = apiClient.DeleteClient(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to delete client: %w", err)
		}

		fmt.Printf("Client '%s' deleted successfully.\n", clientID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)
	clientCmd.AddCommand(clientRegisterCmd)
	clientCmd.AddCommand(clientGetCmd)
	clientCmd.AddCommand(clientListCmd)
	clientCmd.AddCommand(clientUpdateCmd)
	clientCmd.AddCommand(clientDeleteCmd)

	// Flags for RegisterClient
	clientRegisterCmd.Flags().StringP("name", "n", "", "Client name (required)")
	clientRegisterCmd.Flags().StringP("type", "t", "", "Client type: 'confidential' or 'public' (required)")
	clientRegisterCmd.Flags().StringSliceP("redirect-uris", "r", []string{}, "Redirect URI(s) for the client (comma-separated or multiple flags)")
	clientRegisterCmd.Flags().StringSlice("post-logout-redirect-uris", []string{}, "Post logout redirect URI(s) (comma-separated or multiple flags)")
	clientRegisterCmd.Flags().StringSliceP("scopes", "s", []string{}, "Allowed scopes (comma-separated or multiple flags)")
	clientRegisterCmd.Flags().StringSlice("grant-types", []string{}, "Allowed OAuth grant types (e.g., authorization_code,client_credentials,refresh_token)")
	clientRegisterCmd.Flags().String("token-endpoint-auth-method", "", "Token endpoint authentication method (e.g., client_secret_basic, client_secret_post, private_key_jwt, none)")
	clientRegisterCmd.Flags().String("jwks-uri", "", "Client's JWKS URI (for private_key_jwt)")
	clientRegisterCmd.Flags().StringSlice("contacts", []string{}, "Client contact email(s)")
	clientRegisterCmd.Flags().String("logo-uri", "", "URL of the client's logo")
	clientRegisterCmd.Flags().String("policy-uri", "", "URL of the client's policy document")
	clientRegisterCmd.Flags().String("terms-uri", "", "URL of the client's terms of service")
	clientRegisterCmd.Flags().Bool("require-consent", true, "Whether this client requires user consent for scopes")
	// LDAP Attribute Mapping Flags for clientRegisterCmd
	clientRegisterCmd.Flags().String("ldap-attr-email", "", "Client-specific LDAP attribute for email")
	clientRegisterCmd.Flags().String("ldap-attr-firstname", "", "Client-specific LDAP attribute for first name")
	clientRegisterCmd.Flags().String("ldap-attr-lastname", "", "Client-specific LDAP attribute for last name")
	clientRegisterCmd.Flags().String("ldap-attr-groups", "", "Client-specific LDAP attribute for groups/roles")
	clientRegisterCmd.Flags().StringToString("ldap-custom-claims", nil, "Client-specific custom claims from LDAP attributes (e.g., 'jwt_claim_name=ldap_attribute_name') (can be repeated)")

	// Flags for ListClients
	clientListCmd.Flags().Int32("page-size", 10, "Number of clients to list per page")
	clientListCmd.Flags().String("page-token", "", "Token for the next page of results")

	// Flags for UpdateClient (subset of RegisterClient flags, usually)
	clientUpdateCmd.Flags().StringP("name", "n", "", "New client name")
	clientUpdateCmd.Flags().StringSliceP("redirect-uris", "r", []string{}, "New set of redirect URI(s)")
	clientUpdateCmd.Flags().StringSlice("post-logout-redirect-uris", []string{}, "New set of post logout redirect URI(s)")
	clientUpdateCmd.Flags().StringSliceP("scopes", "s", []string{}, "New set of allowed scopes")
	clientUpdateCmd.Flags().String("jwks-uri", "", "New JWKS URI")
	clientUpdateCmd.Flags().StringSlice("contacts", []string{}, "New list of contact email(s)")
	clientUpdateCmd.Flags().String("logo-uri", "", "New URL of the client's logo")
	clientUpdateCmd.Flags().String("policy-uri", "", "New URL of the client's policy document")
	clientUpdateCmd.Flags().String("terms-uri", "", "New URL of the client's terms of service")
	clientUpdateCmd.Flags().Bool("require-consent", false, "Set whether client requires user consent") // Default false for update usually means "don't change if not provided"
	clientUpdateCmd.Flags().Bool("active", false, "Set client active status (true or false)")
	// LDAP Attribute Mapping Flags for clientUpdateCmd
	clientUpdateCmd.Flags().String("ldap-attr-email", "", "New client-specific LDAP attribute for email (set to empty string to clear)")
	clientUpdateCmd.Flags().String("ldap-attr-firstname", "", "New client-specific LDAP attribute for first name (set to empty string to clear)")
	clientUpdateCmd.Flags().String("ldap-attr-lastname", "", "New client-specific LDAP attribute for last name (set to empty string to clear)")
	clientUpdateCmd.Flags().String("ldap-attr-groups", "", "New client-specific LDAP attribute for groups/roles (set to empty string to clear)")
	clientUpdateCmd.Flags().StringToString("ldap-custom-claims", nil, "New set of client-specific custom claims from LDAP attributes (e.g., 'claim=attr'). Use an empty map or a special value to clear all.")

	// Flag for DeleteClient
	clientDeleteCmd.Flags().Bool("force", false, "Force deletion without confirmation")
}
