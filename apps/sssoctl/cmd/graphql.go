package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	"github.com/spf13/cobra"
)

var graphqlCmd = &cobra.Command{
	Use:   "graphql",
	Short: "Run GraphQL queries and mutations (admin API)",
	Long: `Run arbitrary GraphQL operations against /graphql.

This covers every management feature that only exists in the GraphQL schema:
roles, groups, realm settings, client scopes, authentication flows, realm keys,
client secrets and keys, and user credential actions.

Examples:
  ssoctl graphql query 'query { realm { realm displayName } }'
  ssoctl graphql mutate 'mutation($id: ID!) { deleteRole(id: $id) }' --variable id=abc
  ssoctl graphql query --file ./query.graphql --variables '{"first":10}'`,
}

func runGraphQL(cmd *cobra.Command, query string) error {
	variables := map[string]any{}
	if raw, _ := cmd.Flags().GetString("variables"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &variables); err != nil {
			return fmt.Errorf("invalid --variables JSON: %w", err)
		}
	}
	vars, _ := cmd.Flags().GetStringArray("variable")
	for _, pair := range vars {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			return fmt.Errorf("invalid --variable %q (expected key=value)", pair)
		}
		var decoded any
		if err := json.Unmarshal([]byte(value), &decoded); err != nil {
			decoded = value
		}
		variables[key] = decoded
	}

	queryFile, _ := cmd.Flags().GetString("file")
	if queryFile != "" {
		data, err := os.ReadFile(queryFile)
		if err != nil {
			return err
		}
		query = string(data)
	}
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("a GraphQL operation is required")
	}

	currentCtx, err := config.GetCurrentContext()
	if err != nil {
		return err
	}
	data, err := graphqlRequest(context.Background(), currentCtx, query, variables)
	if err != nil {
		return err
	}
	raw, _ := cmd.Flags().GetBool("raw")
	if raw {
		fmt.Println(string(data))
		return nil
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		fmt.Println(string(data))
		return nil
	}
	fmt.Println(pretty.String())
	return nil
}

var graphqlQueryCmd = &cobra.Command{
	Use:   "query <query>",
	Short: "Run a GraphQL query",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGraphQL(cmd, strings.Join(args, " "))
	},
}

var graphqlMutateCmd = &cobra.Command{
	Use:   "mutate <mutation>",
	Short: "Run a GraphQL mutation",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGraphQL(cmd, strings.Join(args, " "))
	},
}

var graphqlIntrospectCmd = &cobra.Command{
	Use:   "introspect",
	Short: "Dump the GraphQL schema (types and fields)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGraphQL(cmd, introspectionQuery)
	},
}

const introspectionQuery = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields {
        name
        args { name type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
      inputFields { name type { kind name ofType { kind name ofType { kind name } } } }
    }
  }
}`

func graphqlRequest(ctx context.Context, cfg *config.Context, query string, variables map[string]any) (json.RawMessage, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint")
	}
	if variables == nil {
		variables = map[string]any{}
	}
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(cfg.ServerEndpoint, "/") + "/graphql"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.UserAuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.UserAuthToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("invalid GraphQL response (HTTP %d): %s", resp.StatusCode, truncate(string(payload), 300))
	}
	if len(envelope.Errors) > 0 {
		msgs := make([]string, len(envelope.Errors))
		for i, e := range envelope.Errors {
			msgs[i] = e.Message
		}
		return nil, fmt.Errorf("graphql: %s", strings.Join(msgs, "; "))
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("graphql HTTP %d: %s", resp.StatusCode, truncate(string(payload), 300))
	}
	if len(envelope.Data) == 0 {
		return json.RawMessage("null"), nil
	}
	return envelope.Data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func init() {
	rootCmd.AddCommand(graphqlCmd)
	graphqlCmd.AddCommand(graphqlQueryCmd)
	graphqlCmd.AddCommand(graphqlMutateCmd)
	graphqlCmd.AddCommand(graphqlIntrospectCmd)

	for _, c := range []*cobra.Command{graphqlQueryCmd, graphqlMutateCmd, graphqlIntrospectCmd} {
		c.Flags().String("variables", "", "Variables as a JSON object")
		c.Flags().StringArray("variable", nil, "Variable as key=value (repeatable; values may be JSON)")
		c.Flags().String("file", "", "Read the operation from a file")
		c.Flags().Bool("raw", false, "Print the raw data JSON without re-indenting")
	}
}
