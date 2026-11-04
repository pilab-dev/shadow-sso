package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

var browserPolicyCmd = &cobra.Command{
	Use:     "browser-policy",
	Aliases: []string{"browserpolicy", "browser-baseline"},
	Short:   "Manage the enterprise browser version baseline",
	Long: `Controls which browser versions may complete an interactive login.
Machine clients (ssoctl, curl, SDKs, health probes) are exempt by default.

Enforcement "block" rejects outdated browsers; "warn" only writes an audit
event so you can roll the policy out safely.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := config.InitConfig(); err != nil {
			return err
		}
		if _, err := config.GetCurrentContext(); err != nil {
			return fmt.Errorf("failed to get current context: %w", err)
		}
		return nil
	},
}

var browserPolicyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the current browser policy and built-in defaults",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := browserPolicyClient()
		if err != nil {
			return err
		}
		resp, err := c.GetBrowserPolicy(context.Background(), connect.NewRequest(&ssov1.GetBrowserPolicyRequest{}))
		if err != nil {
			return fmt.Errorf("failed to get browser policy: %w", err)
		}
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			out, _ := protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}.Marshal(resp.Msg)
			fmt.Println(string(out))
			return nil
		}
		printBrowserPolicy(resp.Msg.GetPolicy(), resp.Msg.GetDefaults())
		return nil
	},
}

var browserPolicySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update the browser policy",
	Long: `Updates only the flags you pass, preserving the rest of the policy.

Examples:
  ssoctl browser-policy set --enabled --enforcement block --block-bots
  ssoctl browser-policy set --min chrome=126 --min firefox=128
  ssoctl browser-policy set --exempt "MyCorpUpdater/"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := browserPolicyClient()
		if err != nil {
			return err
		}
		current, err := c.GetBrowserPolicy(context.Background(), connect.NewRequest(&ssov1.GetBrowserPolicyRequest{}))
		if err != nil {
			return fmt.Errorf("failed to read current browser policy: %w", err)
		}
		policy := current.Msg.GetPolicy()
		if policy == nil {
			policy = &ssov1.BrowserPolicy{Enforcement: "block"}
		}

		if cmd.Flags().Changed("enabled") {
			policy.Enabled, _ = cmd.Flags().GetBool("enabled")
		}
		if cmd.Flags().Changed("disable") {
			disable, _ := cmd.Flags().GetBool("disable")
			if disable {
				policy.Enabled = false
			}
		}
		if cmd.Flags().Changed("enforcement") {
			policy.Enforcement, _ = cmd.Flags().GetString("enforcement")
		}
		if cmd.Flags().Changed("block-unknown") {
			policy.BlockUnknown, _ = cmd.Flags().GetBool("block-unknown")
		}
		if cmd.Flags().Changed("block-bots") {
			policy.BlockBots, _ = cmd.Flags().GetBool("block-bots")
		}
		if cmd.Flags().Changed("min") {
			mins, _ := cmd.Flags().GetStringToString("min")
			if policy.MinVersions == nil {
				policy.MinVersions = make(map[string]string)
			}
			for browser, version := range mins {
				policy.MinVersions[strings.ToLower(browser)] = version
			}
		}
		if cmd.Flags().Changed("clear-min") {
			clear, _ := cmd.Flags().GetBool("clear-min")
			if clear {
				policy.MinVersions = nil
			}
		}
		if cmd.Flags().Changed("exempt") {
			exempt, _ := cmd.Flags().GetStringArray("exempt")
			policy.ExemptUserAgents = exempt
		}

		resp, err := c.UpdateBrowserPolicy(context.Background(), connect.NewRequest(&ssov1.UpdateBrowserPolicyRequest{Policy: policy}))
		if err != nil {
			return fmt.Errorf("failed to update browser policy: %w", err)
		}
		fmt.Println("Browser policy updated.")
		printBrowserPolicy(resp.Msg.GetPolicy(), nil)
		return nil
	},
}

var browserPolicyResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Remove the browser policy (disable enforcement)",
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		if err := requireConfirmation(force, "Remove the browser policy and allow every browser?"); err != nil {
			return err
		}
		c, err := browserPolicyClient()
		if err != nil {
			return err
		}
		if _, err := c.UpdateBrowserPolicy(context.Background(), connect.NewRequest(&ssov1.UpdateBrowserPolicyRequest{Reset_: true})); err != nil {
			return fmt.Errorf("failed to reset browser policy: %w", err)
		}
		fmt.Println("Browser policy removed.")
		return nil
	},
}

var browserPolicyCheckCmd = &cobra.Command{
	Use:   "check [USER_AGENT]",
	Short: "Evaluate a User-Agent against the current policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := browserPolicyClient()
		if err != nil {
			return err
		}
		resp, err := c.CheckBrowser(context.Background(), connect.NewRequest(&ssov1.CheckBrowserRequest{UserAgent: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to check browser: %w", err)
		}
		m := resp.Msg
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			out, _ := protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}.Marshal(m)
			fmt.Println(string(out))
			return nil
		}
		verdict := "ALLOWED"
		if !m.GetAllowed() {
			verdict = "BLOCKED"
		}
		fmt.Printf("%s (%s)\n", verdict, m.GetReason())
		fmt.Printf("browser=%s version=%s os=%s device=%s bot=%t required=%s enforcement=%s\n",
			dash(m.GetBrowser()), dash(m.GetBrowserVersion()), dash(m.GetOs()), dash(m.GetDeviceType()),
			m.GetIsBot(), dash(m.GetRequiredVersion()), dash(m.GetEnforcement()))
		return nil
	},
}

func browserPolicyClient() (ssov1connect.BrowserPolicyServiceClient, error) {
	currentCtx, err := config.GetCurrentContext()
	if err != nil {
		return nil, err
	}
	return client.BrowserPolicyServiceClient(currentCtx)
}

func printBrowserPolicy(policy *ssov1.BrowserPolicy, defaults map[string]string) {
	if policy == nil {
		fmt.Println("Browser policy: not configured (all browsers allowed)")
	} else {
		state := "disabled"
		if policy.GetEnabled() {
			state = "enabled"
		}
		fmt.Printf("Browser policy: %s\n", state)
		fmt.Printf("Enforcement:    %s\n", dash(policy.GetEnforcement()))
		fmt.Printf("Block unknown:  %t\n", policy.GetBlockUnknown())
		fmt.Printf("Block bots:     %t\n", policy.GetBlockBots())
		if policy.GetUpdatedAt() != nil {
			fmt.Printf("Updated:        %s\n", formatTS(policy.GetUpdatedAt()))
		}
		printVersionMap(policy.GetMinVersions(), defaults)
		fmt.Printf("Exempt agents:  %s\n", dash(strings.Join(policy.GetExemptUserAgents(), ", ")))
		return
	}
	printVersionMap(nil, defaults)
}

func printVersionMap(configured, defaults map[string]string) {
	if len(configured) == 0 && len(defaults) == 0 {
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "\nBROWSER\tMIN VERSION\tSOURCE")
	seen := make(map[string]bool)
	keys := make([]string, 0, len(configured)+len(defaults))
	for k := range configured {
		keys = append(keys, k)
		seen[k] = true
	}
	for k := range defaults {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		version := configured[k]
		source := "configured"
		if version == "" {
			version = defaults[k]
			source = "default"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", k, version, source)
	}
	w.Flush()
}

func init() {
	rootCmd.AddCommand(browserPolicyCmd)
	browserPolicyCmd.AddCommand(browserPolicyShowCmd, browserPolicySetCmd, browserPolicyResetCmd, browserPolicyCheckCmd)

	browserPolicyShowCmd.Flags().Bool("json", false, "Output JSON")
	browserPolicyCheckCmd.Flags().Bool("json", false, "Output JSON")

	browserPolicySetCmd.Flags().Bool("enabled", false, "Enable the policy")
	browserPolicySetCmd.Flags().Bool("disable", false, "Disable the policy")
	browserPolicySetCmd.Flags().String("enforcement", "", "block or warn")
	browserPolicySetCmd.Flags().Bool("block-unknown", false, "Reject browsers that cannot be identified")
	browserPolicySetCmd.Flags().Bool("block-bots", false, "Reject crawlers and headless browsers")
	browserPolicySetCmd.Flags().StringToString("min", nil, "Minimum major version, e.g. chrome=126 (repeatable)")
	browserPolicySetCmd.Flags().Bool("clear-min", false, "Remove all explicit minimum versions")
	browserPolicySetCmd.Flags().StringArray("exempt", nil, "User-Agent substring exempt from the policy (repeatable)")

	browserPolicyResetCmd.Flags().Bool("force", false, "Do not ask for confirmation")
}
