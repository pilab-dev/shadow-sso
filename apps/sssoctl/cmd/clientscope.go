package cmd

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

type clientScopeOutput struct {
	ID                string                 `yaml:"id"`
	Name              string                 `yaml:"name"`
	Description       string                 `yaml:"description,omitempty"`
	Protocol          string                 `yaml:"protocol"`
	DisplayOrder      int32                  `yaml:"displayOrder"`
	ConsentScreenText string                 `yaml:"consentScreenText,omitempty"`
	CreatedAt         *timestamppb.Timestamp `yaml:"createdAt,omitempty"`
}

func newClientScopeOutput(s *ssov1.ClientScope) clientScopeOutput {
	return clientScopeOutput{
		ID:                s.GetId(),
		Name:              s.GetName(),
		Description:       s.GetDescription(),
		Protocol:          s.GetProtocol(),
		DisplayOrder:      s.GetDisplayOrder(),
		ConsentScreenText: s.GetConsentScreenText(),
		CreatedAt:         s.GetCreatedAt(),
	}
}

var clientScopeCmd = &cobra.Command{
	Use:     "client-scope",
	Short:   "Manage Keycloak-style client scopes over ConnectRPC",
	Aliases: []string{"client-scopes", "scopes"},
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

var clientScopeCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a client scope",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		description, _ := cmd.Flags().GetString("description")
		protocol, _ := cmd.Flags().GetString("scope-protocol")
		consentText, _ := cmd.Flags().GetString("consent-screen-text")

		req := &ssov1.CreateClientScopeRequest{
			Name:              name,
			Description:       description,
			Protocol:          protocol,
			ConsentScreenText: consentText,
		}
		if cmd.Flags().Changed("display-order") {
			v, _ := cmd.Flags().GetInt32("display-order")
			req.DisplayOrder = proto.Int32(v)
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		scopeClient, err := client.ClientScopeServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := scopeClient.CreateClientScope(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to create client scope: %w", err)
		}
		out, _ := yaml.Marshal(newClientScopeOutput(resp.Msg.ClientScope))
		fmt.Println(string(out))
		return nil
	},
}

var clientScopeGetCmd = &cobra.Command{
	Use:   "get [SCOPE_ID]",
	Short: "Get a client scope by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		scopeClient, err := client.ClientScopeServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := scopeClient.GetClientScope(context.Background(), connect.NewRequest(&ssov1.GetClientScopeRequest{Id: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to get client scope: %w", err)
		}
		out, _ := yaml.Marshal(newClientScopeOutput(resp.Msg.ClientScope))
		fmt.Println(string(out))
		return nil
	},
}

var clientScopeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List client scopes",
	RunE: func(cmd *cobra.Command, args []string) error {
		pageSize, _ := cmd.Flags().GetInt32("limit")
		pageToken, _ := cmd.Flags().GetString("page-token")
		protocol, _ := cmd.Flags().GetString("scope-protocol")

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		scopeClient, err := client.ClientScopeServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := scopeClient.ListClientScopes(context.Background(), connect.NewRequest(&ssov1.ListClientScopesRequest{
			Protocol:  protocol,
			PageSize:  pageSize,
			PageToken: pageToken,
		}))
		if err != nil {
			return fmt.Errorf("failed to list client scopes: %w", err)
		}
		out := make([]clientScopeOutput, len(resp.Msg.ClientScopes))
		for i, s := range resp.Msg.ClientScopes {
			out[i] = newClientScopeOutput(s)
		}
		rendered, _ := yaml.Marshal(out)
		fmt.Println(string(rendered))
		if resp.Msg.NextPageToken != "" {
			fmt.Printf("next_page_token: %s\n", resp.Msg.NextPageToken)
		}
		return nil
	},
}

var clientScopeUpdateCmd = &cobra.Command{
	Use:   "update [SCOPE_ID]",
	Short: "Update a client scope",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		req := &ssov1.UpdateClientScopeRequest{Id: args[0]}
		if cmd.Flags().Changed("name") {
			v, _ := cmd.Flags().GetString("name")
			req.Name = proto.String(v)
		}
		if cmd.Flags().Changed("description") {
			v, _ := cmd.Flags().GetString("description")
			req.Description = proto.String(v)
		}
		if cmd.Flags().Changed("scope-protocol") {
			v, _ := cmd.Flags().GetString("scope-protocol")
			req.Protocol = proto.String(v)
		}
		if cmd.Flags().Changed("consent-screen-text") {
			v, _ := cmd.Flags().GetString("consent-screen-text")
			req.ConsentScreenText = proto.String(v)
		}
		if cmd.Flags().Changed("display-order") {
			v, _ := cmd.Flags().GetInt32("display-order")
			req.DisplayOrder = proto.Int32(v)
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		scopeClient, err := client.ClientScopeServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := scopeClient.UpdateClientScope(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to update client scope: %w", err)
		}
		out, _ := yaml.Marshal(newClientScopeOutput(resp.Msg.ClientScope))
		fmt.Println(string(out))
		return nil
	},
}

var clientScopeDeleteCmd = &cobra.Command{
	Use:   "delete [SCOPE_ID]",
	Short: "Delete a client scope",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		scopeClient, err := client.ClientScopeServiceClient(currentCtx)
		if err != nil {
			return err
		}
		if _, err := scopeClient.DeleteClientScope(context.Background(), connect.NewRequest(&ssov1.DeleteClientScopeRequest{Id: args[0]})); err != nil {
			return fmt.Errorf("failed to delete client scope: %w", err)
		}
		fmt.Printf("client scope %s deleted\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(clientScopeCmd)
	clientScopeCmd.AddCommand(clientScopeCreateCmd, clientScopeGetCmd, clientScopeListCmd, clientScopeUpdateCmd, clientScopeDeleteCmd)

	clientScopeCreateCmd.Flags().String("name", "", "Scope name (required)")
	clientScopeCreateCmd.Flags().String("description", "", "Description")
	clientScopeCreateCmd.Flags().String("scope-protocol", "openid-connect", "Protocol (openid-connect)")
	clientScopeCreateCmd.Flags().String("consent-screen-text", "", "Consent screen text")
	clientScopeCreateCmd.Flags().Int32("display-order", 0, "Display order")

	clientScopeListCmd.Flags().String("scope-protocol", "", "Filter by protocol")
	clientScopeListCmd.Flags().Int32("limit", 50, "Page size (max 100)")
	clientScopeListCmd.Flags().String("page-token", "", "Pagination token")

	clientScopeUpdateCmd.Flags().String("name", "", "New name")
	clientScopeUpdateCmd.Flags().String("description", "", "New description")
	clientScopeUpdateCmd.Flags().String("scope-protocol", "", "New protocol")
	clientScopeUpdateCmd.Flags().String("consent-screen-text", "", "New consent screen text")
	clientScopeUpdateCmd.Flags().Int32("display-order", 0, "New display order")
}
