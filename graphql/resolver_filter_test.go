package graphql_test

import (
	"context"
	"encoding/json"
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

// TestClientFilterInput_Passthrough is the regression test for the historical
// silent-drop bug: the old clientFilterResolver.ClientID/ClientName/Enabled
// stubs returned nil, dropping those filter fields. gqlgen now autobinds those
// fields inline and only sortDir crosses the SortDir resolver bridge; this
// drives the real GraphQL input path end-to-end and asserts every ClientFilter
// field reaches the repository (via the Clients resolver's ListClientsPage
// call, which carries the whole filter).
//
// It requires the whole graphql package to compile, which is blocked by the
// item-11 Sessions signature until items 9-11 land; verified green against a
// package with that single stub satisfied.
func TestClientFilterInput_Passthrough(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	var got domain.ClientFilter
	clientRepo := mock_domain.NewMockClientRepository(ctrl)
	clientRepo.EXPECT().
		ListClientsPage(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, f domain.ClientFilter, _, _ int) ([]*domain.Client, int64, error) {
			got = f
			return []*domain.Client{}, 0, nil
		}).
		Times(1)

	query := `query { clients(filter: {
		clientId: "web-app",
		clientName: "Web App",
		enabled: true,
		publicClient: true,
		search: "app",
		sortBy: "clientName",
		sortDir: ASC
	}) { totalCount } }`

	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	srv := handler.New(graphql.NewExecutableSchema(graphql.Config{Resolvers: &graphql.Resolver{ClientRepo: clientRepo}}))
	srv.AddTransport(transport.POST{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, hasErrors := resp["errors"]; hasErrors {
		t.Fatalf("query returned errors: %s", rec.Body.String())
	}

	if got.ClientID != "web-app" {
		t.Errorf("ClientID = %q, want web-app", got.ClientID)
	}
	if got.ClientName != "Web App" {
		t.Errorf("ClientName = %q, want Web App", got.ClientName)
	}
	if got.Enabled == nil || !*got.Enabled {
		t.Errorf("Enabled = %v, want true", got.Enabled)
	}
	if got.PublicClient == nil || !*got.PublicClient {
		t.Errorf("PublicClient = %v, want true", got.PublicClient)
	}
	if got.Search != "app" {
		t.Errorf("Search = %q, want app", got.Search)
	}
	if got.SortBy != "clientName" {
		t.Errorf("SortBy = %q, want clientName", got.SortBy)
	}
	if got.SortDir != "ASC" {
		t.Errorf("SortDir = %q, want ASC", got.SortDir)
	}
}

// TestFilterSortDirResolvers covers the SortDir enum-to-string bridge directly
// for the ClientFilter and AuditLogFilter resolvers, and locks the wiring for
// the UserFilter resolver (whose sort fields must persist into the filter).
func TestFilterSortDirResolvers(t *testing.T) {
	r := &graphql.Resolver{}

	t.Run("ClientFilter maps ASC and tolerates nil", func(t *testing.T) {
		f := &domain.ClientFilter{}
		asc := graphql.SortDirAsc
		if err := r.ClientFilter().SortDir(context.Background(), f, &asc); err != nil {
			t.Fatalf("SortDir: %v", err)
		}
		if f.SortDir != "ASC" {
			t.Fatalf("SortDir = %q, want ASC", f.SortDir)
		}
		if err := r.ClientFilter().SortDir(context.Background(), f, nil); err != nil {
			t.Fatalf("SortDir(nil): %v", err)
		}
		if f.SortDir != "ASC" {
			t.Fatalf("SortDir(nil) mutated the filter: %q", f.SortDir)
		}
	})

	t.Run("AuditLogFilter maps DESC", func(t *testing.T) {
		f := &domain.AuditLogFilter{}
		desc := graphql.SortDirDesc
		if err := r.AuditLogFilter().SortDir(context.Background(), f, &desc); err != nil {
			t.Fatalf("SortDir: %v", err)
		}
		if f.SortDir != "DESC" {
			t.Fatalf("SortDir = %q, want DESC", f.SortDir)
		}
	})

	t.Run("UserFilter persists sort fields", func(t *testing.T) {
		f := &domain.UserFilter{}
		sortBy := "createdAt"
		asc := graphql.SortDirAsc
		if err := r.UserFilter().SortBy(context.Background(), f, &sortBy); err != nil {
			t.Fatalf("SortBy: %v", err)
		}
		if err := r.UserFilter().SortDir(context.Background(), f, &asc); err != nil {
			t.Fatalf("SortDir: %v", err)
		}
		if f.SortBy != "createdAt" {
			t.Errorf("SortBy = %q, want createdAt", f.SortBy)
		}
		if f.SortDir != "ASC" {
			t.Errorf("SortDir = %q, want ASC", f.SortDir)
		}
	})
}
