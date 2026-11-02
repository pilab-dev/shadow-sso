package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	"github.com/spf13/cobra"
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Call any Connect RPC directly (universal management escape hatch)",
	Long: `Call any sso.v1 Connect procedure with a JSON request body.

This is the guaranteed coverage path: every RPC exposed by the server is
reachable here, including procedures that do not have a bespoke subcommand yet.

Examples:
  ssoctl api services
  ssoctl api describe UserService/UpdateUser
  ssoctl api call UserService/GetUser --data '{"user_id":"..."}'
  ssoctl api call UserService/UpdateUser --data @user.json
  echo '{"user_id":"..."}' | ssoctl api call UserService/GetUser --data -`,
}

var apiServicesCmd = &cobra.Command{
	Use:   "services",
	Short: "List every RPC exposed by the server",
	RunE: func(cmd *cobra.Command, args []string) error {
		methods, err := client.ListRPCMethods()
		if err != nil {
			return err
		}
		sort.Slice(methods, func(i, j int) bool {
			return methods[i].Service+"/"+methods[i].Method < methods[j].Service+"/"+methods[j].Method
		})
		asJSON, _ := cmd.Flags().GetBool("json")
		if asJSON {
			out, _ := json.MarshalIndent(methods, "", "  ")
			fmt.Println(string(out))
			return nil
		}
		currentService := ""
		for _, m := range methods {
			if m.Service != currentService {
				currentService = m.Service
				fmt.Printf("\n%s\n", currentService)
			}
			fmt.Printf("  %-42s %s -> %s\n", m.Method, m.Input, m.Output)
		}
		fmt.Printf("\n%d procedures. Call any with: ssoctl api call <Service>/<Method> --data '{...}'\n", len(methods))
		return nil
	},
}

var apiDescribeCmd = &cobra.Command{
	Use:   "describe <Service>/<Method>",
	Short: "Print the JSON request template for an RPC",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		template, err := client.DescribeRPC(args[0])
		if err != nil {
			return err
		}
		fmt.Println(template)
		return nil
	},
}

var apiCallCmd = &cobra.Command{
	Use:   "call <Service>/<Method>",
	Short: "Invoke an RPC with a JSON request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dataFlag, _ := cmd.Flags().GetString("data")
		data, err := readDataFlag(dataFlag)
		if err != nil {
			return err
		}
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		out, err := client.CallRPC(context.Background(), currentCtx, args[0], data)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	},
}

// readDataFlag resolves --data from a literal, @file or stdin ("-").
func readDataFlag(value string) ([]byte, error) {
	switch {
	case value == "-":
		return io.ReadAll(os.Stdin)
	case strings.HasPrefix(value, "@"):
		return os.ReadFile(strings.TrimPrefix(value, "@"))
	case value == "":
		return []byte("{}"), nil
	default:
		return []byte(value), nil
	}
}

func init() {
	rootCmd.AddCommand(apiCmd)
	apiCmd.AddCommand(apiServicesCmd)
	apiCmd.AddCommand(apiDescribeCmd)
	apiCmd.AddCommand(apiCallCmd)

	apiServicesCmd.Flags().Bool("json", false, "Output as JSON")
	apiCallCmd.Flags().StringP("data", "d", "{}", "Request JSON, @file, or - for stdin")
}
