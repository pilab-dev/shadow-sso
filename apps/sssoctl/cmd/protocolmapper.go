package cmd

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

type protocolMapperOutput struct {
	ID             string                 `yaml:"id"`
	Name           string                 `yaml:"name"`
	Protocol       string                 `yaml:"protocol"`
	ProtocolMapper string                 `yaml:"protocolMapper"`
	Config         map[string]string      `yaml:"config,omitempty"`
	ClientID       string                 `yaml:"clientId,omitempty"`
	CreatedAt      *timestamppb.Timestamp `yaml:"createdAt,omitempty"`
	UpdatedAt      *timestamppb.Timestamp `yaml:"updatedAt,omitempty"`
}

func newProtocolMapperOutput(m *ssov1.ProtocolMapper) protocolMapperOutput {
	return protocolMapperOutput{
		ID:             m.GetId(),
		Name:           m.GetName(),
		Protocol:       m.GetProtocol(),
		ProtocolMapper: m.GetProtocolMapper(),
		Config:         m.GetConfig(),
		ClientID:       m.GetClientId(),
		CreatedAt:      m.GetCreatedAt(),
		UpdatedAt:      m.GetUpdatedAt(),
	}
}

// parseMapperConfig parses repeated key=value flags.
func parseMapperConfig(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("invalid --config value %q: expected key=value", pair)
		}
		out[strings.TrimSpace(key)] = value
	}
	return out, nil
}

var protocolMapperCmd = &cobra.Command{
	Use:     "protocol-mapper",
	Short:   "Manage Keycloak-style protocol mappers over ConnectRPC",
	Aliases: []string{"pm", "protocol-mappers"},
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

var protocolMapperCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a protocol mapper (omit --client-id for a realm-wide mapper)",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		mapperType, _ := cmd.Flags().GetString("mapper")
		protocol, _ := cmd.Flags().GetString("mapper-protocol")
		configPairs, _ := cmd.Flags().GetStringArray("mapper-config")

		configMap, err := parseMapperConfig(configPairs)
		if err != nil {
			return err
		}

		req := &ssov1.CreateProtocolMapperRequest{
			Name:           name,
			Protocol:       protocol,
			ProtocolMapper: mapperType,
			Config:         configMap,
		}
		if cmd.Flags().Changed("client-id") {
			clientID, _ := cmd.Flags().GetString("client-id")
			req.ClientId = proto.String(clientID)
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.ProtocolMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}

		resp, err := mapperClient.CreateProtocolMapper(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to create protocol mapper: %w", err)
		}
		out, _ := yaml.Marshal(newProtocolMapperOutput(resp.Msg.ProtocolMapper))
		fmt.Println(string(out))
		return nil
	},
}

var protocolMapperGetCmd = &cobra.Command{
	Use:   "get [MAPPER_ID]",
	Short: "Get a protocol mapper by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.ProtocolMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := mapperClient.GetProtocolMapper(context.Background(), connect.NewRequest(&ssov1.GetProtocolMapperRequest{Id: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to get protocol mapper: %w", err)
		}
		out, _ := yaml.Marshal(newProtocolMapperOutput(resp.Msg.ProtocolMapper))
		fmt.Println(string(out))
		return nil
	},
}

var protocolMapperListCmd = &cobra.Command{
	Use:   "list",
	Short: "List protocol mappers (all, per-client effective, or realm-only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		pageSize, _ := cmd.Flags().GetInt32("limit")
		pageToken, _ := cmd.Flags().GetString("page-token")
		realmOnly, _ := cmd.Flags().GetBool("realm-only")

		req := &ssov1.ListProtocolMappersRequest{
			RealmOnly: realmOnly,
			PageSize:  pageSize,
			PageToken: pageToken,
		}
		clientID, _ := cmd.Flags().GetString("client-id")
		req.ClientId = clientID

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.ProtocolMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}

		resp, err := mapperClient.ListProtocolMappers(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to list protocol mappers: %w", err)
		}
		out := make([]protocolMapperOutput, len(resp.Msg.ProtocolMappers))
		for i, m := range resp.Msg.ProtocolMappers {
			out[i] = newProtocolMapperOutput(m)
		}
		rendered, _ := yaml.Marshal(out)
		fmt.Println(string(rendered))
		if resp.Msg.NextPageToken != "" {
			fmt.Printf("next_page_token: %s\n", resp.Msg.NextPageToken)
		}
		return nil
	},
}

var protocolMapperUpdateCmd = &cobra.Command{
	Use:   "update [MAPPER_ID]",
	Short: "Update a protocol mapper (--client-id \"\" moves it to realm level)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		req := &ssov1.UpdateProtocolMapperRequest{Id: args[0]}
		if cmd.Flags().Changed("name") {
			v, _ := cmd.Flags().GetString("name")
			req.Name = proto.String(v)
		}
		if cmd.Flags().Changed("mapper") {
			v, _ := cmd.Flags().GetString("mapper")
			req.ProtocolMapper = proto.String(v)
		}
		if cmd.Flags().Changed("mapper-protocol") {
			v, _ := cmd.Flags().GetString("mapper-protocol")
			req.Protocol = proto.String(v)
		}
		if cmd.Flags().Changed("client-id") {
			v, _ := cmd.Flags().GetString("client-id")
			req.ClientId = proto.String(v)
		}
		if cmd.Flags().Changed("mapper-config") {
			pairs, _ := cmd.Flags().GetStringArray("mapper-config")
			configMap, err := parseMapperConfig(pairs)
			if err != nil {
				return err
			}
			req.Config = configMap
		}
		req.ClearConfig, _ = cmd.Flags().GetBool("clear-config")

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.ProtocolMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := mapperClient.UpdateProtocolMapper(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to update protocol mapper: %w", err)
		}
		out, _ := yaml.Marshal(newProtocolMapperOutput(resp.Msg.ProtocolMapper))
		fmt.Println(string(out))
		return nil
	},
}

var protocolMapperDeleteCmd = &cobra.Command{
	Use:   "delete [MAPPER_ID]",
	Short: "Delete a protocol mapper",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.ProtocolMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}
		if _, err := mapperClient.DeleteProtocolMapper(context.Background(), connect.NewRequest(&ssov1.DeleteProtocolMapperRequest{Id: args[0]})); err != nil {
			return fmt.Errorf("failed to delete protocol mapper: %w", err)
		}
		fmt.Printf("protocol mapper %s deleted\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(protocolMapperCmd)
	protocolMapperCmd.AddCommand(protocolMapperCreateCmd, protocolMapperGetCmd, protocolMapperListCmd, protocolMapperUpdateCmd, protocolMapperDeleteCmd)

	protocolMapperCreateCmd.Flags().String("name", "", "Mapper name (required)")
	protocolMapperCreateCmd.Flags().String("mapper", "", "Keycloak mapper type, e.g. oidc-usermodel-attribute-mapper (required)")
	protocolMapperCreateCmd.Flags().String("mapper-protocol", "openid-connect", "Protocol the mapper applies to (openid-connect)")
	protocolMapperCreateCmd.Flags().String("client-id", "", "Bind to this client; omit for a realm-wide mapper")
	protocolMapperCreateCmd.Flags().StringArray("mapper-config", nil, "Mapper config key=value (repeatable)")

	protocolMapperListCmd.Flags().String("client-id", "", "Return the effective mappers for this client")
	protocolMapperListCmd.Flags().Bool("realm-only", false, "Return only realm-wide mappers")
	protocolMapperListCmd.Flags().Int32("limit", 50, "Page size (max 100)")
	protocolMapperListCmd.Flags().String("page-token", "", "Pagination token")

	protocolMapperUpdateCmd.Flags().String("name", "", "New name")
	protocolMapperUpdateCmd.Flags().String("mapper", "", "New mapper type")
	protocolMapperUpdateCmd.Flags().String("mapper-protocol", "", "New mapper protocol")
	protocolMapperUpdateCmd.Flags().String("client-id", "", "New client binding; empty string moves to realm level")
	protocolMapperUpdateCmd.Flags().StringArray("mapper-config", nil, "Replacement config key=value (repeatable)")
	protocolMapperUpdateCmd.Flags().Bool("clear-config", false, "Remove all config entries")
}
