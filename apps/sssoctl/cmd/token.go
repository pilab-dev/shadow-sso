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
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var tokenCmd = &cobra.Command{
	Use:     "token",
	Short:   "Inspect and revoke issued tokens",
	Aliases: []string{"tokens"},
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

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List a user's tokens (metadata only; token values are never shown)",
	Long: `Lists access and refresh tokens for the authenticated user, including
expired and revoked ones when asked. Admins can inspect another user with
--user-id. The token value is never returned; use the JTI to revoke a token.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		req := &ssov1.ListUserTokensRequest{}
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
		req.TokenType, _ = cmd.Flags().GetString("type")
		req.SessionId, _ = cmd.Flags().GetString("session")
		req.ClientId, _ = cmd.Flags().GetString("client")
		limit, _ := cmd.Flags().GetInt32("limit")
		req.Limit = limit
		offset, _ := cmd.Flags().GetInt32("offset")
		req.Offset = offset

		c, err := tokenClient()
		if err != nil {
			return err
		}
		resp, err := c.ListUserTokens(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to list tokens: %w", err)
		}
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			out, _ := protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}.Marshal(resp.Msg)
			fmt.Println(string(out))
			return nil
		}
		printTokens(resp.Msg.GetTokens(), resp.Msg.GetTotal())
		return nil
	},
}

var tokenGetCmd = &cobra.Command{
	Use:   "get [JTI]",
	Short: "Show one token by its JTI",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := tokenClient()
		if err != nil {
			return err
		}
		resp, err := c.GetToken(context.Background(), connect.NewRequest(&ssov1.GetTokenRequest{TokenId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			out, _ := protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}.Marshal(resp.Msg)
			fmt.Println(string(out))
			return nil
		}
		printTokenDetail(resp.Msg.GetToken())
		return nil
	},
}

var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke [JTI]",
	Short: "Revoke one token by its JTI",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		if err := requireConfirmation(force, fmt.Sprintf("Revoke token %s?", args[0])); err != nil {
			return err
		}
		reason, _ := cmd.Flags().GetString("reason")
		c, err := tokenClient()
		if err != nil {
			return err
		}
		if _, err := c.RevokeToken(context.Background(), connect.NewRequest(&ssov1.RevokeTokenRequest{
			TokenId: args[0],
			Reason:  reason,
		})); err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}
		fmt.Printf("Token %s revoked.\n", args[0])
		return nil
	},
}

func tokenClient() (ssov1connect.TokenServiceClient, error) {
	currentCtx, err := config.GetCurrentContext()
	if err != nil {
		return nil, err
	}
	return client.TokenServiceClient(currentCtx)
}

func printTokens(tokens []*ssov1.UserToken, total int64) {
	if len(tokens) == 0 {
		fmt.Println("No tokens found.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "JTI\tTYPE\tSTATUS\tCLIENT\tSESSION\tDEVICE\tISSUED\tEXPIRES")
	for _, t := range tokens {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			t.GetId(), t.GetTokenType(), tokenStatusLabel(t.GetStatus()), t.GetClientId(),
			shortID(t.GetSessionId()), deviceLabel(t),
			formatTS(t.GetIssuedAt()), formatTS(t.GetExpiresAt()))
	}
	w.Flush()
	fmt.Printf("\ntotal=%d\n", total)
}

func printTokenDetail(t *ssov1.UserToken) {
	if t == nil {
		fmt.Println("Token not found.")
		return
	}
	fmt.Printf("JTI:       %s\n", t.GetId())
	fmt.Printf("Type:      %s\n", t.GetTokenType())
	fmt.Printf("Status:    %s\n", tokenStatusLabel(t.GetStatus()))
	fmt.Printf("User:      %s\n", t.GetUserId())
	fmt.Printf("Client:    %s\n", t.GetClientId())
	fmt.Printf("Scope:     %s\n", t.GetScope())
	fmt.Printf("Session:   %s\n", t.GetSessionId())
	fmt.Printf("Family:    %s\n", t.GetFamily())
	fmt.Printf("Parent:    %s\n", t.GetParentJti())
	fmt.Printf("RotatedTo: %s\n", t.GetRotatedTo())
	fmt.Printf("Issued:    %s\n", formatTS(t.GetIssuedAt()))
	fmt.Printf("Expires:   %s\n", formatTS(t.GetExpiresAt()))
	if t.GetUsedAt() != nil {
		fmt.Printf("UsedAt:    %s\n", formatTS(t.GetUsedAt()))
	}
	fmt.Printf("Device:    %s\n", deviceLabel(t))
	if t.GetIpAddress() != "" {
		fmt.Printf("IP:        %s\n", t.GetIpAddress())
	}
	if t.GetUserAgent() != "" {
		fmt.Printf("UserAgent: %s\n", t.GetUserAgent())
	}
}

func tokenStatusLabel(s ssov1.UserTokenStatus) string {
	return strings.TrimPrefix(s.String(), "USER_TOKEN_STATUS_")
}

func deviceLabel(t *ssov1.UserToken) string {
	parts := make([]string, 0, 3)
	if t.GetBrowser() != "" {
		parts = append(parts, strings.TrimSpace(t.GetBrowser()+" "+t.GetBrowserVersion()))
	}
	if t.GetOs() != "" {
		parts = append(parts, t.GetOs())
	}
	if t.GetDeviceType() != "" {
		parts = append(parts, t.GetDeviceType())
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "/")
}

func shortID(id string) string {
	if id == "" {
		return "-"
	}
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

func formatTS(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "-"
	}
	t := ts.AsTime()
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func init() {
	rootCmd.AddCommand(tokenCmd)
	tokenCmd.AddCommand(tokenListCmd, tokenGetCmd, tokenRevokeCmd)

	tokenListCmd.Flags().String("user-id", "", "User ID or 'me' (default: me)")
	tokenListCmd.Flags().Bool("all", false, "Include revoked and expired tokens")
	tokenListCmd.Flags().Bool("include-revoked", false, "Include revoked tokens")
	tokenListCmd.Flags().Bool("include-expired", false, "Include expired tokens")
	tokenListCmd.Flags().String("type", "", "Filter by token type (access_token, refresh_token)")
	tokenListCmd.Flags().String("session", "", "Filter by session ID")
	tokenListCmd.Flags().String("client", "", "Filter by OAuth client ID")
	tokenListCmd.Flags().Int32("limit", 100, "Maximum tokens (1-1000)")
	tokenListCmd.Flags().Int32("offset", 0, "Tokens to skip")
	tokenListCmd.Flags().Bool("json", false, "Output JSON")

	tokenGetCmd.Flags().Bool("json", false, "Output JSON")
	tokenRevokeCmd.Flags().String("reason", "", "Audit reason for the revocation")
	tokenRevokeCmd.Flags().Bool("force", false, "Do not ask for confirmation")
}
