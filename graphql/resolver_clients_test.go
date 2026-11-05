package graphql_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/graphql"
	"go.uber.org/mock/gomock"
)

// clientsCall captures the arguments the Clients resolver forwards to
// ListClientsPage, so tests can assert the resolver-side translation
// (filter/skip/limit) without coupling to the mongo implementation. Unlike
// Users there is no separate sort arg — SortBy/SortDir travel inside filter.
type clientsCall struct {
	filter domain.ClientFilter
	skip   int
	limit  int
}

// clientsResp mirrors the ClientConnection shape returned by the clients query.
type clientsResp struct {
	Data struct {
		Clients struct {
			Edges []struct {
				Cursor string `json:"cursor"`
			} `json:"edges"`
			PageInfo struct {
				HasNextPage     bool    `json:"hasNextPage"`
				HasPreviousPage bool    `json:"hasPreviousPage"`
				StartCursor     *string `json:"startCursor"`
				EndCursor       *string `json:"endCursor"`
			} `json:"pageInfo"`
			TotalCount int `json:"totalCount"`
		} `json:"clients"`
	} `json:"data"`
}

// serveClients drives the clients query through the real gqlgen handler,
// captures the ListClientsPage arguments and returns the decoded response body.
func serveClients(t *testing.T, repo *mock_domain.MockClientRepository, query string, clients []*domain.Client, total int64) (clientsCall, clientsResp) {
	t.Helper()

	var call clientsCall
	repo.EXPECT().
		ListClientsPage(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, f domain.ClientFilter, skip, limit int) ([]*domain.Client, int64, error) {
			call = clientsCall{filter: f, skip: skip, limit: limit}
			return clients, total, nil
		}).
		Times(1)

	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	srv := handler.New(graphql.NewExecutableSchema(graphql.Config{Resolvers: &graphql.Resolver{ClientRepo: repo}}))
	srv.AddTransport(transport.POST{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var raw struct {
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode response envelope: %v", err)
	}
	if len(raw.Errors) > 0 {
		t.Fatalf("query returned errors: %s", rec.Body.String())
	}

	var resp clientsResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return call, resp
}

func makeClients(n int) []*domain.Client {
	clients := make([]*domain.Client, n)
	for i := range clients {
		clients[i] = &domain.Client{ID: fmt.Sprintf("c%02d", i+1)}
	}
	return clients
}

// TestClientsResolver_Pagination covers skip/limit derivation from the
// first/after GraphQL arguments and the PageInfo cursor construction.
func TestClientsResolver_Pagination(t *testing.T) {
	t.Run("first defaults to 20 and after to 0 when omitted", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockClientRepository(ctrl)

		clients := makeClients(20)
		call, resp := serveClients(t, repo,
			`query { clients { edges { cursor } pageInfo { hasNextPage hasPreviousPage startCursor endCursor } totalCount } }`,
			clients, 25)

		if call.skip != 0 {
			t.Errorf("skip = %d, want 0", call.skip)
		}
		if call.limit != 20 {
			t.Errorf("limit = %d, want 20", call.limit)
		}
		if resp.Data.Clients.TotalCount != 25 {
			t.Errorf("totalCount = %d, want 25", resp.Data.Clients.TotalCount)
		}
		if !resp.Data.Clients.PageInfo.HasNextPage {
			t.Errorf("hasNextPage = false, want true (0+20 < 25)")
		}
		if resp.Data.Clients.PageInfo.HasPreviousPage {
			t.Errorf("hasPreviousPage = true, want false (skip == 0)")
		}
		if resp.Data.Clients.PageInfo.StartCursor == nil || *resp.Data.Clients.PageInfo.StartCursor != "c01" {
			t.Errorf("startCursor = %v, want c01", resp.Data.Clients.PageInfo.StartCursor)
		}
		if resp.Data.Clients.PageInfo.EndCursor == nil || *resp.Data.Clients.PageInfo.EndCursor != "c20" {
			t.Errorf("endCursor = %v, want c20", resp.Data.Clients.PageInfo.EndCursor)
		}
	})

	t.Run("first caps at 100", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockClientRepository(ctrl)

		call, _ := serveClients(t, repo,
			`query { clients(first: 500) { totalCount } }`,
			makeClients(100), 100)

		if call.limit != 100 {
			t.Errorf("limit = %d, want 100", call.limit)
		}
	})

	t.Run("first below 1 clamps to 20", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockClientRepository(ctrl)

		call, _ := serveClients(t, repo,
			`query { clients(first: 0) { totalCount } }`,
			[]*domain.Client{}, 0)

		if call.limit != 20 {
			t.Errorf("limit = %d, want 20", call.limit)
		}
	})

	t.Run("after maps to skip and sets hasPreviousPage", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockClientRepository(ctrl)

		call, resp := serveClients(t, repo,
			`query { clients(after: 5, first: 10) { pageInfo { hasNextPage hasPreviousPage } totalCount } }`,
			makeClients(10), 25)

		if call.skip != 5 {
			t.Errorf("skip = %d, want 5", call.skip)
		}
		if call.limit != 10 {
			t.Errorf("limit = %d, want 10", call.limit)
		}
		if !resp.Data.Clients.PageInfo.HasNextPage {
			t.Errorf("hasNextPage = false, want true (5+10 < 25)")
		}
		if !resp.Data.Clients.PageInfo.HasPreviousPage {
			t.Errorf("hasPreviousPage = false, want true (skip == 5)")
		}
	})

	t.Run("hasNextPage false when total equals skip+limit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockClientRepository(ctrl)

		_, resp := serveClients(t, repo,
			`query { clients(first: 20) { pageInfo { hasNextPage } totalCount } }`,
			makeClients(20), 20)

		if resp.Data.Clients.PageInfo.HasNextPage {
			t.Errorf("hasNextPage = true, want false (0+20 == 20)")
		}
	})

	t.Run("empty page yields nil cursors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockClientRepository(ctrl)

		_, resp := serveClients(t, repo,
			`query { clients { pageInfo { startCursor endCursor } totalCount } }`,
			[]*domain.Client{}, 0)

		if resp.Data.Clients.PageInfo.StartCursor != nil || resp.Data.Clients.PageInfo.EndCursor != nil {
			t.Errorf("cursors = %v/%v, want nil/nil on empty page",
				resp.Data.Clients.PageInfo.StartCursor, resp.Data.Clients.PageInfo.EndCursor)
		}
	})
}

// TestClientsResolver_FilterPassthrough covers the sort-direction asymmetry
// with Users: SortBy/SortDir live inside ClientFilter (not a separate
// SortSpec) and mongo's buildClientSort matches SortDir case-insensitively
// (strings.ToLower == "desc"), so the uppercase enum values must reach the
// repo unchanged — no ASC→asc/DESC→desc switch in the resolver.
func TestClientsResolver_FilterPassthrough(t *testing.T) {
	t.Run("clientId publicClient sortBy sortDir reach the repo unchanged", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockClientRepository(ctrl)

		call, _ := serveClients(t, repo,
			`query { clients(filter: { clientId: "web-app", publicClient: true, sortBy: "clientName", sortDir: DESC }) { totalCount } }`,
			[]*domain.Client{}, 0)

		if call.filter.ClientID != "web-app" {
			t.Errorf("filter.ClientID = %q, want web-app", call.filter.ClientID)
		}
		if call.filter.PublicClient == nil || !*call.filter.PublicClient {
			t.Errorf("filter.PublicClient = %v, want true", call.filter.PublicClient)
		}
		if call.filter.SortBy != "clientName" {
			t.Errorf("filter.SortBy = %q, want clientName", call.filter.SortBy)
		}
		if call.filter.SortDir != "DESC" {
			t.Errorf("filter.SortDir = %q, want DESC (uppercase passes through; mongo lowercases)", call.filter.SortDir)
		}
	})

	t.Run("empty sort input passes zero-value SortBy and SortDir", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockClientRepository(ctrl)

		call, _ := serveClients(t, repo,
			`query { clients(filter: { clientName: "Web App" }) { totalCount } }`,
			[]*domain.Client{}, 0)

		if call.filter.SortBy != "" {
			t.Errorf("filter.SortBy = %q, want empty (mongo falls back to client_id asc)", call.filter.SortBy)
		}
		if call.filter.SortDir != "" {
			t.Errorf("filter.SortDir = %q, want empty", call.filter.SortDir)
		}
	})
}
