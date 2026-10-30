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

// usersCall captures the arguments the Users resolver forwards to
// ListUsersPage, so tests can assert the resolver-side translation
// (filter/sort/skip/limit) without coupling to the mongo implementation.
type usersCall struct {
	filter domain.UserFilter
	sort   domain.SortSpec
	skip   int
	limit  int
}

// usersResp mirrors the UserConnection shape returned by the users query.
type usersResp struct {
	Data struct {
		Users struct {
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
		} `json:"users"`
	} `json:"data"`
}

// serveUsers drives the users query through the real gqlgen handler, captures
// the ListUsersPage arguments and returns the decoded response body.
func serveUsers(t *testing.T, repo *mock_domain.MockUserRepository, query string, users []*domain.User, total int64) (usersCall, usersResp) {
	t.Helper()

	var call usersCall
	repo.EXPECT().
		ListUsersPage(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, f domain.UserFilter, s domain.SortSpec, skip, limit int) ([]*domain.User, int64, error) {
			call = usersCall{filter: f, sort: s, skip: skip, limit: limit}
			return users, total, nil
		}).
		Times(1)

	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	srv := handler.New(graphql.NewExecutableSchema(graphql.Config{Resolvers: &graphql.Resolver{UserRepo: repo}}))
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

	var resp usersResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return call, resp
}

func makeUsers(n int) []*domain.User {
	users := make([]*domain.User, n)
	for i := range users {
		users[i] = &domain.User{ID: fmt.Sprintf("u%02d", i+1)}
	}
	return users
}

// TestUsersResolver_Pagination covers skip/limit derivation from the
// first/after GraphQL arguments and the PageInfo cursor construction.
func TestUsersResolver_Pagination(t *testing.T) {
	t.Run("first defaults to 20 and after to 0 when omitted", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		users := makeUsers(20)
		call, resp := serveUsers(t, repo,
			`query { users { edges { cursor } pageInfo { hasNextPage hasPreviousPage startCursor endCursor } totalCount } }`,
			users, 25)

		if call.skip != 0 {
			t.Errorf("skip = %d, want 0", call.skip)
		}
		if call.limit != 20 {
			t.Errorf("limit = %d, want 20", call.limit)
		}
		if resp.Data.Users.TotalCount != 25 {
			t.Errorf("totalCount = %d, want 25", resp.Data.Users.TotalCount)
		}
		if !resp.Data.Users.PageInfo.HasNextPage {
			t.Errorf("hasNextPage = false, want true (0+20 < 25)")
		}
		if resp.Data.Users.PageInfo.HasPreviousPage {
			t.Errorf("hasPreviousPage = true, want false (skip == 0)")
		}
		if resp.Data.Users.PageInfo.StartCursor == nil || *resp.Data.Users.PageInfo.StartCursor != "u01" {
			t.Errorf("startCursor = %v, want u01", resp.Data.Users.PageInfo.StartCursor)
		}
		if resp.Data.Users.PageInfo.EndCursor == nil || *resp.Data.Users.PageInfo.EndCursor != "u20" {
			t.Errorf("endCursor = %v, want u20", resp.Data.Users.PageInfo.EndCursor)
		}
	})

	t.Run("first caps at 100", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		call, _ := serveUsers(t, repo,
			`query { users(first: 500) { totalCount } }`,
			makeUsers(100), 100)

		if call.limit != 100 {
			t.Errorf("limit = %d, want 100", call.limit)
		}
	})

	t.Run("first below 1 clamps to 20", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		call, _ := serveUsers(t, repo,
			`query { users(first: 0) { totalCount } }`,
			[]*domain.User{}, 0)

		if call.limit != 20 {
			t.Errorf("limit = %d, want 20", call.limit)
		}
	})

	t.Run("after maps to skip and sets hasPreviousPage", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		call, resp := serveUsers(t, repo,
			`query { users(after: 5, first: 10) { pageInfo { hasNextPage hasPreviousPage } totalCount } }`,
			makeUsers(10), 25)

		if call.skip != 5 {
			t.Errorf("skip = %d, want 5", call.skip)
		}
		if call.limit != 10 {
			t.Errorf("limit = %d, want 10", call.limit)
		}
		if !resp.Data.Users.PageInfo.HasNextPage {
			t.Errorf("hasNextPage = false, want true (5+10 < 25)")
		}
		if !resp.Data.Users.PageInfo.HasPreviousPage {
			t.Errorf("hasPreviousPage = false, want true (skip == 5)")
		}
	})

	t.Run("hasNextPage false when total equals skip+limit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		_, resp := serveUsers(t, repo,
			`query { users(first: 20) { pageInfo { hasNextPage } totalCount } }`,
			makeUsers(20), 20)

		if resp.Data.Users.PageInfo.HasNextPage {
			t.Errorf("hasNextPage = true, want false (0+20 == 20)")
		}
	})

	t.Run("empty page yields nil cursors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		_, resp := serveUsers(t, repo,
			`query { users { pageInfo { startCursor endCursor } totalCount } }`,
			[]*domain.User{}, 0)

		if resp.Data.Users.PageInfo.StartCursor != nil || resp.Data.Users.PageInfo.EndCursor != nil {
			t.Errorf("cursors = %v/%v, want nil/nil on empty page",
				resp.Data.Users.PageInfo.StartCursor, resp.Data.Users.PageInfo.EndCursor)
		}
	})
}

// TestUsersResolver_SortTranslation covers the sort-persistence gap fix: the
// sortBy/sortDir GraphQL inputs must survive the userFilterResolver bridge
// and reach ListUsersPage as the SortSpec the mongo layer consumes.
func TestUsersResolver_SortTranslation(t *testing.T) {
	t.Run("sortBy and sortDir DESC translate to SortSpec", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		call, _ := serveUsers(t, repo,
			`query { users(filter: { sortBy: "createdAt", sortDir: DESC }) { totalCount } }`,
			[]*domain.User{}, 0)

		if call.sort.Field != "createdAt" {
			t.Errorf("SortSpec.Field = %q, want createdAt", call.sort.Field)
		}
		if call.sort.Dir != "desc" {
			t.Errorf("SortSpec.Dir = %q, want desc (lowercase, mongo contract)", call.sort.Dir)
		}
	})

	t.Run("sortDir ASC translates to asc", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		call, _ := serveUsers(t, repo,
			`query { users(filter: { sortDir: ASC }) { totalCount } }`,
			[]*domain.User{}, 0)

		if call.sort.Dir != "asc" {
			t.Errorf("SortSpec.Dir = %q, want asc", call.sort.Dir)
		}
	})

	t.Run("empty sort input leaves SortSpec zero value", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		call, _ := serveUsers(t, repo,
			`query { users(filter: { email: "a@b.c" }) { totalCount } }`,
			[]*domain.User{}, 0)

		if call.sort != (domain.SortSpec{}) {
			t.Errorf("SortSpec = %+v, want zero value", call.sort)
		}
	})

	t.Run("filter fields still reach the repository", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockUserRepository(ctrl)

		call, _ := serveUsers(t, repo,
			`query { users(filter: { search: "alice", enabled: true }) { totalCount } }`,
			[]*domain.User{}, 0)

		if call.filter.Search == nil || *call.filter.Search != "alice" {
			t.Errorf("filter.Search = %v, want alice", call.filter.Search)
		}
		if call.filter.Enabled == nil || !*call.filter.Enabled {
			t.Errorf("filter.Enabled = %v, want true", call.filter.Enabled)
		}
	})
}
