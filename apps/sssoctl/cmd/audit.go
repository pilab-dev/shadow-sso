package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
		asJSON, _ := cmd.Flags().GetBool("json")
		if follow, _ := cmd.Flags().GetBool("follow"); follow {
			user, _ := cmd.Flags().GetString("user")
			action, _ := cmd.Flags().GetString("action")
			since, _ := cmd.Flags().GetString("from")
			if strings.TrimSpace(since) == "" {
				since = "15m"
			}
			start, err := parseAuditSince(since)
			if err != nil {
				return fmt.Errorf("invalid --from: %w", err)
			}
			interval, _ := cmd.Flags().GetInt32("interval-ms")
			batch, _ := cmd.Flags().GetInt32("batch")
			return streamAuditEvents(cmd, start, user, action, interval, batch, asJSON)
		}

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

// parseAuditSince accepts an absolute timestamp or a relative window such as
// "15m", "-15m" or "now".
func parseAuditSince(value string) (time.Time, error) {
	v := strings.TrimSpace(value)
	if v == "" || strings.EqualFold(v, "now") {
		return time.Now().UTC(), nil
	}
	relative := v
	if strings.HasPrefix(relative, "-") {
		relative = relative[1:]
	}
	if d, err := time.ParseDuration(relative); err == nil {
		return time.Now().UTC().Add(-d), nil
	}
	return parseAuditTime(v)
}

var auditFollowCmd = &cobra.Command{
	Use:     "follow",
	Aliases: []string{"tail", "watch"},
	Short:   "Stream audit events as they happen (like 'kubectl logs -f')",
	Long: `Streams audit events oldest-first. Use --since to replay a window first
(e.g. --since 15m) and then keep following. Ctrl-C stops the stream.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		start, err := parseAuditSince(since)
		if err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		interval, _ := cmd.Flags().GetInt32("interval-ms")
		batch, _ := cmd.Flags().GetInt32("batch")
		asJSON, _ := cmd.Flags().GetBool("json")
		return streamAuditEvents(cmd, start, mustFlag(cmd, "user"), mustFlag(cmd, "action"), interval, batch, asJSON)
	},
}

func streamAuditEvents(cmd *cobra.Command, start time.Time, user, action string, interval, batch int32, asJSON bool) error {
	currentCtx, err := config.GetCurrentContext()
	if err != nil {
		return err
	}
	c, err := client.AuditServiceClient(currentCtx)
	if err != nil {
		return err
	}

	req := &ssov1.FollowAuditEventsRequest{
		User:            user,
		Action:          action,
		From:            timestamppb.New(start),
		IncludeExisting: true,
		PollIntervalMs:  interval,
		BatchSize:       batch,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stream, err := c.FollowAuditEvents(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("failed to follow audit events: %w", err)
	}
	defer stream.Close()

	for stream.Receive() {
		ev := stream.Msg()
		if asJSON {
			out, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(ev)
			fmt.Println(string(out))
			continue
		}
		printAuditEvent(ev)
	}
	if err := stream.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("audit stream failed: %w", err)
	}
	return nil
}

func mustFlag(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func printAuditEvent(e *ssov1.AuditEventProto) {
	ts := ""
	if e.GetTimestamp() != nil {
		ts = e.GetTimestamp().AsTime().Format(time.RFC3339)
	}
	status := "ok"
	if !e.GetSuccess() {
		status = "FAIL"
	}
	fmt.Printf("%s  %-4s %-14s %-24s user=%s target=%s\n", ts, status, e.GetService(), e.GetAction(), e.GetUser(), e.GetTarget())
	if e.GetDetails() != "" {
		fmt.Printf("    %s\n", e.GetDetails())
	}
	if e.GetError() != "" {
		fmt.Printf("    error: %s\n", e.GetError())
	}
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditListCmd, auditFollowCmd)
	auditListCmd.Flags().String("user", "", "Filter by user ID or username")
	auditListCmd.Flags().String("action", "", "Filter by action")
	auditListCmd.Flags().String("from", "", "Inclusive lower bound (RFC3339 or YYYY-MM-DD)")
	auditListCmd.Flags().String("to", "", "Inclusive upper bound (RFC3339 or YYYY-MM-DD)")
	auditListCmd.Flags().Int32("limit", 50, "Maximum events (1-500)")
	auditListCmd.Flags().Int32("offset", 0, "Events to skip")
	auditListCmd.Flags().Bool("json", false, "Output JSON")
	auditListCmd.Flags().BoolP("follow", "f", false, "Keep streaming new events after the page (like 'kubectl logs -f')")
	auditListCmd.Flags().Int32("interval-ms", 1000, "Follow poll interval (250-30000)")
	auditListCmd.Flags().Int32("batch", 200, "Follow batch size")

	auditFollowCmd.Flags().String("user", "", "Filter by user ID or username")
	auditFollowCmd.Flags().String("action", "", "Filter by action")
	auditFollowCmd.Flags().String("since", "15m", "Replay this window before following (e.g. 15m, -1h, now, RFC3339)")
	auditFollowCmd.Flags().Int32("interval-ms", 1000, "How often the server polls for new events (250-30000)")
	auditFollowCmd.Flags().Int32("batch", 200, "Maximum events per batch")
	auditFollowCmd.Flags().Bool("json", false, "Output one JSON object per line (NDJSON)")
}
