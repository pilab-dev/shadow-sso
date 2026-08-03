package cmd

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client" // Path to your client package
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3" // For pretty printing federated identity list
)

var federationCmd = &cobra.Command{
	Use:     "federation",
	Short:   "Manage linked federated identities for the current user",
	Aliases: []string{"fed"},
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

var federationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List federated identities linked to the current user",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}

		fedClient, err := client.FederationServiceClient(currentCtx)
		if err != nil {
			return fmt.Errorf("failed to create federation service client: %w", err)
		}

		resp, err := fedClient.ListUserFederatedIdentities(context.Background(), connect.NewRequest(&ssov1.ListUserFederatedIdentitiesRequest{}))
		if err != nil {
			return fmt.Errorf("failed to list federated identities: %w", err)
		}

		if resp.Msg == nil || len(resp.Msg.Identities) == 0 {
			fmt.Println("No linked federated identities found.")
			return nil
		}

		fmt.Println("Linked federated identities:")
		out, _ := yaml.Marshal(resp.Msg.Identities)
		fmt.Println(string(out))
		return nil
	},
}

var federationRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Unlink a federated identity from the current user",
	Long: `Unlinks a federated identity.
Requires --provider-name (the provider alias, e.g. "google") and --provider-user-id
(the user's ID at the external provider, e.g. the Google sub).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		providerName, _ := cmd.Flags().GetString("provider-name")
		providerUserID, _ := cmd.Flags().GetString("provider-user-id")

		if providerName == "" || providerUserID == "" {
			return fmt.Errorf("both --provider-name and --provider-user-id are required")
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}

		fedClient, err := client.FederationServiceClient(currentCtx)
		if err != nil {
			return fmt.Errorf("failed to create federation service client: %w", err)
		}

		_, err = fedClient.RemoveUserFederatedIdentity(context.Background(), connect.NewRequest(&ssov1.RemoveUserFederatedIdentityRequest{
			ProviderName:           providerName,
			ProviderUserIdToRemove: providerUserID,
		}))
		if err != nil {
			return fmt.Errorf("failed to remove federated identity: %w", err)
		}

		fmt.Printf("Federated identity %s (%s) removed successfully.\n", providerUserID, providerName)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(federationCmd)
	federationCmd.AddCommand(federationListCmd)
	federationCmd.AddCommand(federationRemoveCmd)

	federationRemoveCmd.Flags().String("provider-name", "", "Alias of the identity provider (e.g. 'google')")
	federationRemoveCmd.Flags().String("provider-user-id", "", "User's ID at the external provider (e.g. the Google sub)")
}
