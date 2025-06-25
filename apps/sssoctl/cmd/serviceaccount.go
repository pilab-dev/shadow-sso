package cmd

import (
	"context"
	"encoding/json" // For outputting the JSON key directly
	"errors"
	"fmt"
	"os"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3" // For list output
)

var saCmd = &cobra.Command{
	Use:     "service-account",
	Short:   "Manage service accounts and their keys",
	Aliases: []string{"sa"},
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

var saCreateKeyCmd = &cobra.Command{
	Use:   "create-key",
	Short: "Create a new service account key",
	Long:  "Creates a new service account key. If a service account with the given project ID and client email doesn't exist, it might be created by the server. Outputs the service account key in JSON format.",
	RunE: func(cmd *cobra.Command, args []string) error {
		projectID, _ := cmd.Flags().GetString("project-id")
		clientEmail, _ := cmd.Flags().GetString("client-email") // Optional on server
		displayName, _ := cmd.Flags().GetString("display-name") // Optional

		if projectID == "" {
			return errors.New("--project-id is required")
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		saClient, err := client.ServiceAccountServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.CreateServiceAccountKeyRequest{
			ProjectId:   projectID,
			ClientEmail: clientEmail,
			DisplayName: displayName,
		}
		resp, err := saClient.CreateServiceAccountKey(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to create service account key: %w", err)
		}

		if resp.Msg == nil || resp.Msg.Key == nil {
			return errors.New("server did not return a key")
		}

		// Construct a map to ensure JSON field names are snake_case as expected.
		keyOutput := map[string]string{
			"type":                        resp.Msg.Key.Type,
			"project_id":                  resp.Msg.Key.ProjectId,
			"private_key_id":              resp.Msg.Key.PrivateKeyId,
			"private_key":                 resp.Msg.Key.PrivateKey,
			"client_email":                resp.Msg.Key.ClientEmail,
			"client_id":                   resp.Msg.Key.ClientId,
			"auth_uri":                    resp.Msg.Key.AuthUri,
			"token_uri":                   resp.Msg.Key.TokenUri,
			"auth_provider_x509_cert_url": resp.Msg.Key.AuthProviderX509CertUrl,
			"client_x509_cert_url":        resp.Msg.Key.ClientX509CertUrl,
		}

		jsonKey, err := json.MarshalIndent(keyOutput, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal service account key to JSON: %w", err)
		}
		fmt.Println(string(jsonKey))
		if resp.Msg.ServiceAccountId != "" {
			fmt.Fprintf(os.Stderr, "\nService Account ID: %s\n", resp.Msg.ServiceAccountId)
		}
		return nil
	},
}

var saListKeysCmd = &cobra.Command{
	Use:   "list-keys [SERVICE_ACCOUNT_ID]",
	Short: "List public keys for a service account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceAccountID := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		saClient, err := client.ServiceAccountServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.ListServiceAccountKeysRequest{ServiceAccountId: serviceAccountID}
		resp, err := saClient.ListServiceAccountKeys(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to list service account keys: %w", err)
		}

		if resp.Msg == nil || len(resp.Msg.Keys) == 0 {
			fmt.Println("No keys found for this service account.")
			return nil
		}
		out, _ := yaml.Marshal(resp.Msg.Keys)
		fmt.Println(string(out))
		return nil
	},
}

var saDeleteKeyCmd = &cobra.Command{
	Use:   "delete-key [SERVICE_ACCOUNT_ID] [KEY_ID]",
	Short: "Delete a service account key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceAccountID := args[0]
		keyID := args[1]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		saClient, err := client.ServiceAccountServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.DeleteServiceAccountKeyRequest{ServiceAccountId: serviceAccountID, KeyId: keyID}
		_, err = saClient.DeleteServiceAccountKey(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to delete service account key: %w", err)
		}

		fmt.Printf("Service account key '%s' for service account '%s' deleted successfully (or marked for revocation).\n", keyID, serviceAccountID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(saCmd)
	saCmd.AddCommand(saCreateKeyCmd)
	saCmd.AddCommand(saListKeysCmd)
	saCmd.AddCommand(saDeleteKeyCmd)

	saCreateKeyCmd.Flags().String("project-id", "", "Project ID for the service account (required)")
	saCreateKeyCmd.Flags().String("client-email", "", "Client email for the service account (optional, server may generate if empty)")
	saCreateKeyCmd.Flags().String("display-name", "", "Display name for the service account (optional)")

	// saListKeysCmd flags if needed (e.g. --show-revoked)
}
