package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
)

// completionContext loads the current context for dynamic completion. It never
// prompts and silently returns false when the CLI is not configured.
func completionContext() (context.Context, *config.Context, bool) {
	if err := config.InitConfigQuiet(); err != nil {
		return nil, nil, false
	}
	current, err := config.GetCurrentContext()
	if err != nil || current == nil || current.ServerEndpoint == "" {
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = cancel // the deadline is enough; the request is short-lived
	return ctx, current, true
}

func filterCompletion(prefix string, values []string) []string {
	if prefix == "" {
		return values
	}
	lower := strings.ToLower(prefix)
	var out []string
	for _, v := range values {
		// Values are "value\tdescription"; match either part.
		if strings.Contains(strings.ToLower(v), lower) {
			out = append(out, v)
		}
	}
	return out
}

// completeClients dynamically lists OAuth clients for shell completion.
func completeClients(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, current, ok := completionContext()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	c, err := client.ClientManagementServiceClient(current)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	resp, err := c.ListClients(ctx, connect.NewRequest(&ssov1.ListClientsRequest{PageSize: 100}))
	if err != nil || resp.Msg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	values := make([]string, 0, len(resp.Msg.Clients))
	for _, cl := range resp.Msg.Clients {
		values = append(values, fmt.Sprintf("%s\t%s", cl.GetClientId(), cl.GetClientName()))
	}
	return filterCompletion(toComplete, values), cobra.ShellCompDirectiveNoFileComp
}

// completeUsers dynamically lists users (ID and email) for shell completion.
func completeUsers(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, current, ok := completionContext()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	c, err := client.UserServiceClient(current)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	resp, err := c.ListUsers(ctx, connect.NewRequest(&ssov1.ListUsersRequest{PageSize: 100}))
	if err != nil || resp.Msg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var values []string
	for _, u := range resp.Msg.Users {
		values = append(values, fmt.Sprintf("%s\t%s (%s)", u.GetId(), u.GetEmail(), u.GetStatus()))
	}
	return filterCompletion(toComplete, values), cobra.ShellCompDirectiveNoFileComp
}

// completeIdPs dynamically lists identity providers for shell completion.
func completeIdPs(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, current, ok := completionContext()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	c, err := client.IdPManagementServiceClient(current)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	resp, err := c.ListIdPs(ctx, connect.NewRequest(&ssov1.ListIdPsRequest{}))
	if err != nil || resp.Msg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var values []string
	for _, idp := range resp.Msg.Idps {
		values = append(values, fmt.Sprintf("%s\t%s", idp.GetId(), idp.GetName()))
	}
	return filterCompletion(toComplete, values), cobra.ShellCompDirectiveNoFileComp
}

// completeMappers dynamically lists user attribute mappers.
func completeMappers(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, current, ok := completionContext()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	c, err := client.UserAttributeMapperServiceClient(current)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	resp, err := c.ListUserAttributeMappers(ctx, connect.NewRequest(&ssov1.ListUserAttributeMappersRequest{PageSize: 100}))
	if err != nil || resp.Msg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var values []string
	for _, m := range resp.Msg.UserAttributeMappers {
		values = append(values, fmt.Sprintf("%s\t%s", m.GetId(), m.GetName()))
	}
	return filterCompletion(toComplete, values), cobra.ShellCompDirectiveNoFileComp
}

func init() {
	for _, c := range []*cobra.Command{clientGetCmd, clientUpdateCmd, clientDeleteCmd, clientGenerateSecretCmd, clientGenerateKeysCmd} {
		c.ValidArgsFunction = completeClients
	}
	for _, c := range []*cobra.Command{
		userGetCmd, userActivateCmd, userLockCmd, userChangePasswordCmd,
		mfaStatusCmd, mfaResetCmd, mfaRequireCmd, mfaListCmd, mfaTotpEnrollCmd,
		mfaRecoveryGenerateCmd, mfaPasskeyListCmd, mfaPasskeyRemoveCmd,
	} {
		c.ValidArgsFunction = completeUsers
	}
	for _, c := range []*cobra.Command{idpGetCmd, idpUpdateCmd, idpDeleteCmd} {
		c.ValidArgsFunction = completeIdPs
	}
	for _, c := range []*cobra.Command{tokenMapperGetCmd, tokenMapperUpdateCmd, tokenMapperDeleteCmd} {
		c.ValidArgsFunction = completeMappers
	}
}
