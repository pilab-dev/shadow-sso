package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

var deviceCmd = &cobra.Command{
	Use:     "device",
	Short:   "Inspect a user's devices, browsers and agents",
	Aliases: []string{"devices"},
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

var deviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List devices (sessions) with browser, OS and token counts",
	RunE: func(cmd *cobra.Command, args []string) error {
		devices, total, err := fetchDevices(cmd)
		if err != nil {
			return err
		}
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			out, _ := protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}.Marshal(
				&ssov1.ListUserDevicesResponse{Devices: devices, Total: total})
			fmt.Println(string(out))
			return nil
		}
		printDevices(devices, total)
		return nil
	},
}

var deviceShowCmd = &cobra.Command{
	Use:   "show [SESSION_ID]",
	Short: "Show one device and its tokens",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		devices, _, err := fetchDevices(cmd)
		if err != nil {
			return err
		}
		var found *ssov1.UserDevice
		for _, d := range devices {
			if d.GetSessionId() == args[0] {
				found = d
				break
			}
		}
		if found == nil {
			return fmt.Errorf("session %s not found for this user", args[0])
		}
		printDevice(found)

		c, err := tokenClient()
		if err != nil {
			return err
		}
		resp, err := c.ListUserTokens(context.Background(), connect.NewRequest(&ssov1.ListUserTokensRequest{
			UserId:         found.GetUserId(),
			SessionId:      found.GetSessionId(),
			IncludeRevoked: true,
			IncludeExpired: true,
			Limit:          500,
		}))
		if err != nil {
			return fmt.Errorf("failed to list tokens for device: %w", err)
		}
		fmt.Println()
		printTokens(resp.Msg.GetTokens(), resp.Msg.GetTotal())
		return nil
	},
}

func fetchDevices(cmd *cobra.Command) ([]*ssov1.UserDevice, int64, error) {
	req := &ssov1.ListUserDevicesRequest{}
	req.UserId, _ = cmd.Flags().GetString("user-id")
	if req.UserId == "" {
		req.UserId = "me"
	}
	req.IncludeRevoked, _ = cmd.Flags().GetBool("include-revoked")
	req.IncludeExpired, _ = cmd.Flags().GetBool("include-expired")
	if all, _ := cmd.Flags().GetBool("all"); all {
		req.IncludeRevoked = true
		req.IncludeExpired = true
	}
	limit, _ := cmd.Flags().GetInt32("limit")
	req.Limit = limit
	offset, _ := cmd.Flags().GetInt32("offset")
	req.Offset = offset

	currentCtx, err := config.GetCurrentContext()
	if err != nil {
		return nil, 0, err
	}
	c, err := client.TokenServiceClient(currentCtx)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.ListUserDevices(context.Background(), connect.NewRequest(req))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list devices: %w", err)
	}
	return resp.Msg.GetDevices(), resp.Msg.GetTotal(), nil
}

func printDevices(devices []*ssov1.UserDevice, total int64) {
	if len(devices) == 0 {
		fmt.Println("No devices found.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "\tSESSION\tBROWSER\tOS\tDEVICE\tIP\tLAST USED\tTOKENS\tSTATE")
	for _, d := range devices {
		marker := " "
		if d.GetIsCurrentSession() {
			marker = "*"
		}
		browser := strings.TrimSpace(d.GetBrowser() + " " + d.GetBrowserVersion())
		if browser == "" {
			browser = "-"
		}
		state := "active"
		if d.GetIsRevoked() {
			state = "revoked"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d/%d\t%s\n",
			marker, shortID(d.GetSessionId()), browser, dash(d.GetOs()), dash(d.GetDeviceType()),
			dash(d.GetIpAddress()), formatTS(d.GetLastUsedAt()), d.GetActiveTokenCount(), d.GetTokenCount(), state)
	}
	w.Flush()
	fmt.Printf("\ntotal=%d\n", total)
}

func printDevice(d *ssov1.UserDevice) {
	fmt.Printf("Session:   %s\n", d.GetSessionId())
	fmt.Printf("User:      %s\n", d.GetUserId())
	fmt.Printf("Browser:   %s %s\n", dash(d.GetBrowser()), d.GetBrowserVersion())
	fmt.Printf("OS:        %s\n", dash(d.GetOs()))
	fmt.Printf("Device:    %s\n", dash(d.GetDeviceType()))
	fmt.Printf("IP:        %s\n", dash(d.GetIpAddress()))
	fmt.Printf("Created:   %s\n", formatTS(d.GetCreatedAt()))
	fmt.Printf("LastUsed:  %s\n", formatTS(d.GetLastUsedAt()))
	fmt.Printf("Expires:   %s\n", formatTS(d.GetExpiresAt()))
	fmt.Printf("Revoked:   %t\n", d.GetIsRevoked())
	fmt.Printf("Current:   %t\n", d.GetIsCurrentSession())
	fmt.Printf("Clients:   %s\n", dash(strings.Join(d.GetClientIds(), ", ")))
	fmt.Printf("Tokens:    %d active / %d total\n", d.GetActiveTokenCount(), d.GetTokenCount())
	if d.GetUserAgent() != "" {
		fmt.Printf("UserAgent: %s\n", d.GetUserAgent())
	}
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func init() {
	rootCmd.AddCommand(deviceCmd)
	deviceCmd.AddCommand(deviceListCmd, deviceShowCmd)
	for _, c := range []*cobra.Command{deviceListCmd, deviceShowCmd} {
		c.Flags().String("user-id", "", "User ID or 'me' (default: me)")
		c.Flags().Bool("all", false, "Include revoked and expired devices")
		c.Flags().Bool("include-revoked", false, "Include revoked devices")
		c.Flags().Bool("include-expired", false, "Include expired devices")
		c.Flags().Int32("limit", 100, "Maximum devices (1-500)")
		c.Flags().Int32("offset", 0, "Devices to skip")
		c.Flags().Bool("json", false, "Output JSON")
	}
}
