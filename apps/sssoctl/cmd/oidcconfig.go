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
	"gopkg.in/yaml.v3"
)

type oidcConfigurationOutput struct {
	Issuer                            string   `yaml:"issuer"`
	ScopesSupported                   []string `yaml:"scopesSupported"`
	ClaimsSupported                   []string `yaml:"claimsSupported"`
	TokenEndpointAuthMethodsSupported []string `yaml:"tokenEndpointAuthMethodsSupported"`
	ResponseTypesSupported            []string `yaml:"responseTypesSupported"`
	ResponseModesSupported            []string `yaml:"responseModesSupported"`
}

func newOIDCConfigurationOutput(c *ssov1.OIDCConfiguration) oidcConfigurationOutput {
	return oidcConfigurationOutput{
		Issuer:                            c.GetIssuer(),
		ScopesSupported:                   c.GetScopesSupported(),
		ClaimsSupported:                   c.GetClaimsSupported(),
		TokenEndpointAuthMethodsSupported: c.GetTokenEndpointAuthMethodsSupported(),
		ResponseTypesSupported:            c.GetResponseTypesSupported(),
		ResponseModesSupported:            c.GetResponseModesSupported(),
	}
}

// splitCSVList turns "a, b,c" into []string{"a","b","c"}. An explicitly empty
// value yields an empty slice, which resets the override server-side.
func splitCSVList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

var oidcConfigCmd = &cobra.Command{
	Use:     "oidc-config",
	Short:   "Read and update /.well-known/openid-configuration metadata over ConnectRPC",
	Aliases: []string{"oidc"},
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

var oidcConfigGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the effective discovery metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		oidcClient, err := client.OIDCConfigurationServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := oidcClient.GetOIDCConfiguration(context.Background(), connect.NewRequest(&ssov1.GetOIDCConfigurationRequest{}))
		if err != nil {
			return fmt.Errorf("failed to get OIDC configuration: %w", err)
		}
		out, _ := yaml.Marshal(newOIDCConfigurationOutput(resp.Msg.Configuration))
		fmt.Println(string(out))
		return nil
	},
}

var oidcConfigUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update discovery metadata (empty value resets that field to the server default)",
	RunE: func(cmd *cobra.Command, args []string) error {
		reset, _ := cmd.Flags().GetBool("reset")
		req := &ssov1.UpdateOIDCConfigurationRequest{}
		anyField := reset

		setList := func(flag string, target **ssov1.StringList) error {
			if !cmd.Flags().Changed(flag) && !reset {
				return nil
			}
			anyField = true
			value, _ := cmd.Flags().GetString(flag)
			*target = &ssov1.StringList{Values: splitCSVList(value)}
			return nil
		}
		if err := setList("scopes", &req.ScopesSupported); err != nil {
			return err
		}
		if err := setList("claims", &req.ClaimsSupported); err != nil {
			return err
		}
		if err := setList("auth-methods", &req.TokenEndpointAuthMethodsSupported); err != nil {
			return err
		}
		if err := setList("response-types", &req.ResponseTypesSupported); err != nil {
			return err
		}
		if err := setList("response-modes", &req.ResponseModesSupported); err != nil {
			return err
		}
		if !anyField {
			return fmt.Errorf("nothing to update: pass --scopes/--claims/--auth-methods/--response-types/--response-modes or --reset")
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		oidcClient, err := client.OIDCConfigurationServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := oidcClient.UpdateOIDCConfiguration(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to update OIDC configuration: %w", err)
		}
		out, _ := yaml.Marshal(newOIDCConfigurationOutput(resp.Msg.Configuration))
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(oidcConfigCmd)
	oidcConfigCmd.AddCommand(oidcConfigGetCmd, oidcConfigUpdateCmd)

	oidcConfigUpdateCmd.Flags().String("scopes", "", "Comma-separated scopes_supported")
	oidcConfigUpdateCmd.Flags().String("claims", "", "Comma-separated claims_supported")
	oidcConfigUpdateCmd.Flags().String("auth-methods", "", "Comma-separated token_endpoint_auth_methods_supported")
	oidcConfigUpdateCmd.Flags().String("response-types", "", "Comma-separated response_types_supported")
	oidcConfigUpdateCmd.Flags().String("response-modes", "", "Comma-separated response_modes_supported")
	oidcConfigUpdateCmd.Flags().Bool("reset", false, "Reset every discovery list to the server default")
}
