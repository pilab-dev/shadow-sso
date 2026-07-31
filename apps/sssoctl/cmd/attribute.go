package cmd

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3" // For pretty printing user attributes
)

// attributeOutput is the YAML-rendered shape of a user attribute, with
// explicit camelCase field names (yaml.v3 would otherwise lowercase the Go
// struct field names, e.g. UserId -> userid).
type attributeOutput struct {
	ID        string                 `yaml:"id"`
	Name      string                 `yaml:"name"`
	Value     string                 `yaml:"value"`
	UserId    string                 `yaml:"userId"`
	CreatedAt *timestamppb.Timestamp `yaml:"createdAt"`
	UpdatedAt *timestamppb.Timestamp `yaml:"updatedAt"`
}

// newAttributeOutput converts a proto user attribute into its YAML output shape.
func newAttributeOutput(a *ssov1.UserAttribute) attributeOutput {
	return attributeOutput{
		ID:        a.GetId(),
		Name:      a.GetName(),
		Value:     a.GetValue(),
		UserId:    a.GetUserId(),
		CreatedAt: a.GetCreatedAt(),
		UpdatedAt: a.GetUpdatedAt(),
	}
}

var userAttributeCmd = &cobra.Command{
	Use:     "attribute",
	Short:   "Manage custom user attributes",
	Aliases: []string{"ua", "attributes"},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Ensure config is loaded and current context is available for client setup.
		if err := config.InitConfig(); err != nil {
			return err
		}
		_, err := config.GetCurrentContext() // Check if context can be determined
		if err != nil {
			return fmt.Errorf("failed to get current context: %w. Use 'ssoctl config set-context' or 'ssoctl auth login'", err)
		}
		return nil
	},
}

var userAttributeCreateCmd = &cobra.Command{
	Use:   "create [USER_ID]",
	Short: "Create a custom user attribute",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userID := args[0]
		name, _ := cmd.Flags().GetString("name")
		value, _ := cmd.Flags().GetString("value")

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		attrClient, err := client.UserAttributeServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.CreateUserAttributeRequest{UserId: userID, Name: name, Value: value}
		resp, err := attrClient.CreateUserAttribute(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to create user attribute: %w", err)
		}

		out, _ := yaml.Marshal(newAttributeOutput(resp.Msg.UserAttribute))
		fmt.Println(string(out))
		return nil
	},
}

var userAttributeGetCmd = &cobra.Command{
	Use:   "get [ATTRIBUTE_ID]",
	Short: "Get a custom user attribute by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		attributeID := args[0]

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		attrClient, err := client.UserAttributeServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.GetUserAttributeRequest{Id: attributeID}
		resp, err := attrClient.GetUserAttribute(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to get user attribute: %w", err)
		}

		out, _ := yaml.Marshal(newAttributeOutput(resp.Msg.UserAttribute))
		fmt.Println(string(out))
		return nil
	},
}

var userAttributeListCmd = &cobra.Command{
	Use:   "list [USER_ID]",
	Short: "List custom user attributes with optional user filter and pagination",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		req := &ssov1.ListUserAttributesRequest{Name: name, PageSize: int32(limit)}
		if len(args) > 0 {
			req.UserId = args[0]
		}
		if offset > 0 {
			req.PageToken = fmt.Sprintf("%d", offset)
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		attrClient, err := client.UserAttributeServiceClient(currentCtx)
		if err != nil {
			return err
		}

		resp, err := attrClient.ListUserAttributes(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to list user attributes: %w", err)
		}

		if len(resp.Msg.UserAttributes) == 0 {
			fmt.Println("No user attributes found.")
			return nil
		}
		output := make([]attributeOutput, 0, len(resp.Msg.UserAttributes))
		for _, a := range resp.Msg.UserAttributes {
			output = append(output, newAttributeOutput(a))
		}
		out, _ := yaml.Marshal(output)
		fmt.Println(string(out))
		if resp.Msg.NextPageToken != "" {
			fmt.Printf("\nnextPageToken: %s\n", resp.Msg.NextPageToken)
		}
		return nil
	},
}

var userAttributeUpdateCmd = &cobra.Command{
	Use:   "update [ATTRIBUTE_ID]",
	Short: "Update a custom user attribute (name and/or value)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		attributeID := args[0]

		nameChanged := cmd.Flags().Changed("name")
		valueChanged := cmd.Flags().Changed("value")
		if !nameChanged && !valueChanged {
			return errors.New("at least one of --name or --value must be provided")
		}

		req := &ssov1.UpdateUserAttributeRequest{Id: attributeID}
		if nameChanged {
			name, _ := cmd.Flags().GetString("name")
			req.Name = &name
		}
		if valueChanged {
			value, _ := cmd.Flags().GetString("value")
			req.Value = &value
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		attrClient, err := client.UserAttributeServiceClient(currentCtx)
		if err != nil {
			return err
		}

		resp, err := attrClient.UpdateUserAttribute(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to update user attribute: %w", err)
		}

		out, _ := yaml.Marshal(newAttributeOutput(resp.Msg.UserAttribute))
		fmt.Println(string(out))
		return nil
	},
}

var userAttributeDeleteCmd = &cobra.Command{
	Use:   "delete [ATTRIBUTE_ID]",
	Short: "Delete a custom user attribute",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		attributeID := args[0]

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		attrClient, err := client.UserAttributeServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.DeleteUserAttributeRequest{Id: attributeID}
		_, err = attrClient.DeleteUserAttribute(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to delete user attribute: %w", err)
		}

		fmt.Printf("User attribute '%s' deleted.\n", attributeID)
		return nil
	},
}

var userAttributeDeleteByUserCmd = &cobra.Command{
	Use:   "delete-by-user [USER_ID]",
	Short: "Delete all custom user attributes for a user (irreversible, admin-only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userID := args[0]

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		attrClient, err := client.UserAttributeServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.DeleteUserAttributesByUserIdRequest{UserId: userID}
		_, err = attrClient.DeleteUserAttributesByUserId(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to delete user attributes: %w", err)
		}

		fmt.Printf("All user attributes for user '%s' deleted.\n", userID)
		return nil
	},
}

func init() {
	userCmd.AddCommand(userAttributeCmd)
	userAttributeCmd.AddCommand(userAttributeCreateCmd)
	userAttributeCmd.AddCommand(userAttributeGetCmd)
	userAttributeCmd.AddCommand(userAttributeListCmd)
	userAttributeCmd.AddCommand(userAttributeUpdateCmd)
	userAttributeCmd.AddCommand(userAttributeDeleteCmd)
	userAttributeCmd.AddCommand(userAttributeDeleteByUserCmd)

	userAttributeCreateCmd.Flags().String("name", "", "Attribute name (required)")
	_ = userAttributeCreateCmd.MarkFlagRequired("name")
	userAttributeCreateCmd.Flags().String("value", "", "Attribute value (required)")
	_ = userAttributeCreateCmd.MarkFlagRequired("value")

	userAttributeListCmd.Flags().String("name", "", "Filter by attribute name")
	userAttributeListCmd.Flags().Int("limit", 50, "Results per page (max 100)")
	userAttributeListCmd.Flags().Int("offset", 0, "Pagination offset")

	userAttributeUpdateCmd.Flags().String("name", "", "New name (leave empty to keep current)")
	userAttributeUpdateCmd.Flags().String("value", "", "New value (leave empty to keep current)")
}
