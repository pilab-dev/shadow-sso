package cmd

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Read the audit log",
}

var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit events (admin)",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		c, err := client.AuditServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.ListAuditEventsRequest{}
		req.User, _ = cmd.Flags().GetString("user")
		req.Action, _ = cmd.Flags().GetString("action")
		limit, _ := cmd.Flags().GetInt32("limit")
		req.Limit = limit
		offset, _ := cmd.Flags().GetInt32("offset")
		req.Offset = offset

		if v, _ := cmd.Flags().GetString("from"); v != "" {
			t, err := parseAuditTime(v)
			if err != nil {
				return fmt.Errorf("invalid --from: %w", err)
			}
			req.From = timestamppb.New(t)
		}
		if v, _ := cmd.Flags().GetString("to"); v != "" {
			t, err := parseAuditTime(v)
			if err != nil {
				return fmt.Errorf("invalid --to: %w", err)
			}
			req.To = timestamppb.New(t)
		}

		resp, err := c.ListAuditEvents(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to list audit events: %w", err)
		}

		asJSON, _ := cmd.Flags().GetBool("json")
		if asJSON {
			out, _ := protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}.Marshal(resp.Msg)
			fmt.Println(string(out))
			return nil
		}

		fmt.Printf("total=%d limit=%d offset=%d\n\n", resp.Msg.GetTotal(), resp.Msg.GetLimit(), resp.Msg.GetOffset())
		for _, e := range resp.Msg.GetEvents() {
			ts := ""
			if e.GetTimestamp() != nil {
				ts = e.GetTimestamp().AsTime().Format(time.RFC3339)
			}
			status := "ok"
			if !e.GetSuccess() {
				status = "FAIL"
			}
			fmt.Printf("%s  %-8s %-14s %-40s user=%s target=%s\n", ts, status, e.GetService(), e.GetAction(), e.GetUser(), e.GetTarget())
			if e.GetDetails() != "" {
				fmt.Printf("    %s\n", e.GetDetails())
			}
			if e.GetError() != "" {
				fmt.Printf("    error: %s\n", e.GetError())
			}
		}
		return nil
	},
}

func parseAuditTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD, got %q", value)
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditListCmd)
	auditListCmd.Flags().String("user", "", "Filter by user ID or username")
	auditListCmd.Flags().String("action", "", "Filter by action")
	auditListCmd.Flags().String("from", "", "Inclusive lower bound (RFC3339 or YYYY-MM-DD)")
	auditListCmd.Flags().String("to", "", "Inclusive upper bound (RFC3339 or YYYY-MM-DD)")
	auditListCmd.Flags().Int32("limit", 50, "Maximum events (1-500)")
	auditListCmd.Flags().Int32("offset", 0, "Events to skip")
	auditListCmd.Flags().Bool("json", false, "Output JSON")
}
