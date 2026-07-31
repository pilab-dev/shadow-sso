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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3" // For pretty printing mapper(s)
)

// tokenTypeFromString maps a CLI --token-type value to its proto enum.
func tokenTypeFromString(v string) (ssov1.TokenTypeProto, error) {
	switch v {
	case "id_token":
		return ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN, nil
	case "access_token":
		return ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN, nil
	case "userinfo":
		return ssov1.TokenTypeProto_TOKEN_TYPE_USERINFO, nil
	default:
		return ssov1.TokenTypeProto_TOKEN_TYPE_UNSPECIFIED, fmt.Errorf("invalid token type %q: must be one of id_token, access_token, userinfo", v)
	}
}

// tokenTypeToString is the inverse of tokenTypeFromString: it renders a proto
// token type enum as its canonical CLI string.
func tokenTypeToString(v ssov1.TokenTypeProto) string {
	switch v {
	case ssov1.TokenTypeProto_TOKEN_TYPE_ID_TOKEN:
		return "id_token"
	case ssov1.TokenTypeProto_TOKEN_TYPE_ACCESS_TOKEN:
		return "access_token"
	case ssov1.TokenTypeProto_TOKEN_TYPE_USERINFO:
		return "userinfo"
	default:
		return v.String()
	}
}

// protocolFromString maps a CLI --protocol value to its proto enum.
func protocolFromString(v string) (ssov1.ProtocolProto, error) {
	switch v {
	case "openid-connect":
		return ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT, nil
	default:
		return ssov1.ProtocolProto_PROTOCOL_UNSPECIFIED, fmt.Errorf("invalid protocol %q: must be openid-connect", v)
	}
}

// protocolToString is the inverse of protocolFromString: it renders a proto
// protocol enum as its canonical CLI string.
func protocolToString(v ssov1.ProtocolProto) string {
	if v == ssov1.ProtocolProto_PROTOCOL_OPENID_CONNECT {
		return "openid-connect"
	}
	return v.String()
}

// mapperOutput is the YAML-rendered shape of a token mapper, with enum fields
// rendered as canonical strings (e.g. tokenType: id_token, protocol: openid-connect).
type mapperOutput struct {
	ID             string                 `yaml:"id"`
	Name           string                 `yaml:"name"`
	UserAttribute  string                 `yaml:"userAttribute"`
	TokenClaimName string                 `yaml:"tokenClaimName"`
	TokenType      string                 `yaml:"tokenType"`
	MultiValued    bool                   `yaml:"multiValued"`
	Protocol       string                 `yaml:"protocol"`
	ClientId       string                 `yaml:"clientId,omitempty"`
	CreatedAt      *timestamppb.Timestamp `yaml:"createdAt"`
	UpdatedAt      *timestamppb.Timestamp `yaml:"updatedAt"`
}

// newMapperOutput converts a proto token mapper into its YAML output shape.
func newMapperOutput(m *ssov1.UserAttributeMapper) mapperOutput {
	return mapperOutput{
		ID:             m.GetId(),
		Name:           m.GetName(),
		UserAttribute:  m.GetUserAttribute(),
		TokenClaimName: m.GetTokenClaimName(),
		TokenType:      tokenTypeToString(m.GetTokenType()),
		MultiValued:    m.GetMultiValued(),
		Protocol:       protocolToString(m.GetProtocol()),
		ClientId:       m.GetClientId(),
		CreatedAt:      m.GetCreatedAt(),
		UpdatedAt:      m.GetUpdatedAt(),
	}
}

// protocolPtr returns a pointer to the given protocol enum value.
func protocolPtr(v ssov1.ProtocolProto) *ssov1.ProtocolProto {
	return &v
}

// tokenTypePtr returns a pointer to the given token type enum value.
func tokenTypePtr(v ssov1.TokenTypeProto) *ssov1.TokenTypeProto {
	return &v
}

var tokenMapperCmd = &cobra.Command{
	Use:     "token-mapper",
	Short:   "Map user attributes to token claims",
	Aliases: []string{"tm", "token-mappers", "mapper"},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Ensure config is loaded and current context is available for client setup
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

var tokenMapperCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a token mapper that maps a user attribute to a token claim",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		userAttribute, _ := cmd.Flags().GetString("user-attribute")
		claimName, _ := cmd.Flags().GetString("claim-name")
		tokenTypeStr, _ := cmd.Flags().GetString("token-type")

		if name == "" {
			return errors.New("name is required via --name flag")
		}
		if userAttribute == "" {
			return errors.New("user-attribute is required via --user-attribute flag")
		}
		if claimName == "" {
			return errors.New("claim-name is required via --claim-name flag")
		}
		if tokenTypeStr == "" {
			return errors.New("token-type is required via --token-type flag (one of id_token, access_token, userinfo)")
		}
		tokenType, err := tokenTypeFromString(tokenTypeStr)
		if err != nil {
			return err
		}

		req := &ssov1.CreateUserAttributeMapperRequest{
			Name:           name,
			UserAttribute:  userAttribute,
			TokenClaimName: claimName,
			TokenType:      tokenType,
		}

		// --multi-valued: only set when explicitly provided (server defaults to false).
		if cmd.Flags().Changed("multi-valued") {
			multiValued, _ := cmd.Flags().GetBool("multi-valued")
			req.MultiValued = proto.Bool(multiValued)
		}
		// --protocol: always send, defaulting to openid-connect.
		protocolStr, _ := cmd.Flags().GetString("protocol")
		protocol, err := protocolFromString(protocolStr)
		if err != nil {
			return err
		}
		req.Protocol = protocolPtr(protocol)
		// --client-id: only set when explicitly provided.
		if cmd.Flags().Changed("client-id") {
			clientID, _ := cmd.Flags().GetString("client-id")
			req.ClientId = proto.String(clientID)
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.UserAttributeMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}

		resp, err := mapperClient.CreateUserAttributeMapper(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to create token mapper: %w", err)
		}

		out, _ := yaml.Marshal(newMapperOutput(resp.Msg.UserAttributeMapper))
		fmt.Println(string(out))
		return nil
	},
}

var tokenMapperGetCmd = &cobra.Command{
	Use:   "get [MAPPER_ID]",
	Short: "Get a token mapper by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mapperID := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.UserAttributeMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.GetUserAttributeMapperRequest{Id: mapperID}
		resp, err := mapperClient.GetUserAttributeMapper(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to get token mapper: %w", err)
		}

		out, _ := yaml.Marshal(newMapperOutput(resp.Msg.UserAttributeMapper))
		fmt.Println(string(out))
		return nil
	},
}

var tokenMapperListCmd = &cobra.Command{
	Use:   "list",
	Short: "List token mappers with optional filters and pagination",
	RunE: func(cmd *cobra.Command, args []string) error {
		pageSize, _ := cmd.Flags().GetInt32("limit")
		pageToken, _ := cmd.Flags().GetString("page-token")

		req := &ssov1.ListUserAttributeMappersRequest{
			PageSize:  pageSize,
			PageToken: pageToken,
		}

		// --token-type: only set when explicitly provided (filter).
		if cmd.Flags().Changed("token-type") {
			tokenTypeStr, _ := cmd.Flags().GetString("token-type")
			tokenType, err := tokenTypeFromString(tokenTypeStr)
			if err != nil {
				return err
			}
			req.TokenType = tokenType
		}
		if cmd.Flags().Changed("client-id") {
			clientID, _ := cmd.Flags().GetString("client-id")
			req.ClientId = clientID
		}
		if cmd.Flags().Changed("user-attribute") {
			userAttribute, _ := cmd.Flags().GetString("user-attribute")
			req.UserAttribute = userAttribute
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.UserAttributeMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}

		resp, err := mapperClient.ListUserAttributeMappers(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to list token mappers: %w", err)
		}

		if len(resp.Msg.UserAttributeMappers) == 0 {
			fmt.Println("No token mappers found.")
			return nil
		}
		output := make([]mapperOutput, 0, len(resp.Msg.UserAttributeMappers))
		for _, m := range resp.Msg.UserAttributeMappers {
			output = append(output, newMapperOutput(m))
		}
		out, _ := yaml.Marshal(output)
		fmt.Println(string(out))
		if resp.Msg.NextPageToken != "" {
			fmt.Printf("\nNext page token: %s\n", resp.Msg.NextPageToken)
		}
		return nil
	},
}

var tokenMapperUpdateCmd = &cobra.Command{
	Use:   "update [MAPPER_ID]",
	Short: "Update a token mapper (only explicitly provided fields are changed)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mapperID := args[0]

		req := &ssov1.UpdateUserAttributeMapperRequest{Id: mapperID}

		// Only set the fields the user explicitly passed (partial update).
		if cmd.Flags().Changed("name") {
			name, _ := cmd.Flags().GetString("name")
			req.Name = proto.String(name)
		}
		if cmd.Flags().Changed("user-attribute") {
			userAttribute, _ := cmd.Flags().GetString("user-attribute")
			req.UserAttribute = proto.String(userAttribute)
		}
		if cmd.Flags().Changed("claim-name") {
			claimName, _ := cmd.Flags().GetString("claim-name")
			req.TokenClaimName = proto.String(claimName)
		}
		if cmd.Flags().Changed("token-type") {
			tokenTypeStr, _ := cmd.Flags().GetString("token-type")
			tokenType, err := tokenTypeFromString(tokenTypeStr)
			if err != nil {
				return err
			}
			req.TokenType = tokenTypePtr(tokenType)
		}
		if cmd.Flags().Changed("multi-valued") {
			multiValued, _ := cmd.Flags().GetBool("multi-valued")
			req.MultiValued = proto.Bool(multiValued)
		}
		if cmd.Flags().Changed("protocol") {
			protocolStr, _ := cmd.Flags().GetString("protocol")
			protocol, err := protocolFromString(protocolStr)
			if err != nil {
				return err
			}
			req.Protocol = protocolPtr(protocol)
		}
		if cmd.Flags().Changed("client-id") {
			clientID, _ := cmd.Flags().GetString("client-id")
			req.ClientId = proto.String(clientID)
		}

		if req.Name == nil && req.UserAttribute == nil && req.TokenClaimName == nil &&
			req.TokenType == nil && req.MultiValued == nil && req.Protocol == nil && req.ClientId == nil {
			return errors.New("at least one flag must be provided: --name, --user-attribute, --claim-name, --token-type, --multi-valued, --protocol, --client-id")
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.UserAttributeMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}

		resp, err := mapperClient.UpdateUserAttributeMapper(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to update token mapper: %w", err)
		}

		out, _ := yaml.Marshal(newMapperOutput(resp.Msg.UserAttributeMapper))
		fmt.Println(string(out))
		return nil
	},
}

var tokenMapperDeleteCmd = &cobra.Command{
	Use:   "delete [MAPPER_ID]",
	Short: "Delete a token mapper by ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mapperID := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		mapperClient, err := client.UserAttributeMapperServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.DeleteUserAttributeMapperRequest{Id: mapperID}
		_, err = mapperClient.DeleteUserAttributeMapper(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to delete token mapper: %w", err)
		}
		fmt.Printf("Token mapper '%s' deleted.\n", mapperID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(tokenMapperCmd)
	tokenMapperCmd.AddCommand(tokenMapperCreateCmd)
	tokenMapperCmd.AddCommand(tokenMapperGetCmd)
	tokenMapperCmd.AddCommand(tokenMapperListCmd)
	tokenMapperCmd.AddCommand(tokenMapperUpdateCmd)
	tokenMapperCmd.AddCommand(tokenMapperDeleteCmd)

	tokenMapperCreateCmd.Flags().String("name", "", "Name of the token mapper (required)")
	tokenMapperCreateCmd.Flags().String("user-attribute", "", "User attribute to map from (required)")
	tokenMapperCreateCmd.Flags().String("claim-name", "", "JWT claim name to map to, supports dot-notation for nested claims e.g. realm_access.roles (required)")
	tokenMapperCreateCmd.Flags().String("token-type", "", "Token type to map into: id_token, access_token, userinfo (required)")
	tokenMapperCreateCmd.Flags().Bool("multi-valued", false, "Treat the attribute as multi-valued (array)")
	tokenMapperCreateCmd.Flags().String("protocol", "openid-connect", "Protocol for the mapper (only openid-connect is supported)")
	tokenMapperCreateCmd.Flags().String("client-id", "", "Scope the mapper to a specific client")

	tokenMapperListCmd.Flags().String("token-type", "", "Filter by token type: id_token, access_token, userinfo")
	tokenMapperListCmd.Flags().String("client-id", "", "Filter by client ID")
	tokenMapperListCmd.Flags().String("user-attribute", "", "Filter by user attribute")
	tokenMapperListCmd.Flags().Int32("limit", 50, "Maximum number of mappers to list per page")
	tokenMapperListCmd.Flags().String("page-token", "", "Token for the next page of results")

	tokenMapperUpdateCmd.Flags().String("name", "", "New name for the token mapper")
	tokenMapperUpdateCmd.Flags().String("user-attribute", "", "New user attribute to map from")
	tokenMapperUpdateCmd.Flags().String("claim-name", "", "New JWT claim name to map to")
	tokenMapperUpdateCmd.Flags().String("token-type", "", "New token type: id_token, access_token, userinfo")
	tokenMapperUpdateCmd.Flags().Bool("multi-valued", false, "Treat the attribute as multi-valued (array)")
	tokenMapperUpdateCmd.Flags().String("protocol", "openid-connect", "New protocol (only openid-connect is supported)")
	tokenMapperUpdateCmd.Flags().String("client-id", "", "New client ID to scope the mapper to")
}
