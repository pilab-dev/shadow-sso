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

// sessionsCall captures the arguments the Sessions resolver forwards to
// ListSessionsByUserID (the positional userID + the filter), so tests can
// assert the clientId/userId arg plumbing without coupling to the mongo impl.
// Note there is no skip/limit: the repo call shape is fixed and sessions stay
// non-paginated (see TestSessionsResolver_NonPaginatedConnection).
type sessionsCall struct {
	userID string
	filter domain.SessionFilter
}

// sessionsResp mirrors the SessionConnection shape returned by the sessions query.
type sessionsResp struct {
	Data struct {
		Sessions struct {
			Edges []struct {
				Cursor string `json:"cursor"`
			} `json:"edges"`
			TotalCount int `json:"totalCount"`
			PageInfo   struct {
				HasNextPage     bool `json:"hasNextPage"`
				HasPreviousPage bool `json:"hasPreviousPage"`
			} `json:"pageInfo"`
		} `json:"sessions"`
	} `json:"data"`
}

// serveSessions drives the sessions query through the real gqlgen handler,
// captures the ListSessionsByUserID arguments and returns the decoded response.
func serveSessions(t *testing.T, repo *mock_domain.MockSessionRepository, query string, sessions []*domain.Session) (sessionsCall, sessionsResp) {
	t.Helper()

	var call sessionsCall
	repo.EXPECT().
		ListSessionsByUserID(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, userID string, f domain.SessionFilter) ([]*domain.Session, error) {
			call = sessionsCall{userID: userID, filter: f}
			return sessions, nil
		}).
		Times(1)

	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	srv := handler.New(graphql.NewExecutableSchema(graphql.Config{Resolvers: &graphql.Resolver{SessionRepo: repo}}))
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

	var resp sessionsResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return call, resp
}

func makeSessions(n int) []*domain.Session {
	sessions := make([]*domain.Session, n)
	for i := range sessions {
		sessions[i] = &domain.Session{
			ID:       fmt.Sprintf("s%02d", i+1),
			UserID:   "u-1",
			ClientID: "web-app",
		}
	}
	return sessions
}

// TestSessionsResolver_ClientIDAndUserIDPlumbing covers the clientId/userId
// GraphQL args reaching SessionFilter.ClientID/UserID on the repo call.
func TestSessionsResolver_ClientIDAndUserIDPlumbing(t *testing.T) {
	t.Run("clientId arg reaches SessionFilter.ClientID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockSessionRepository(ctrl)

		call, _ := serveSessions(t, repo,
			`query { sessions(clientId: "web-app") { edges { cursor } totalCount } }`,
			makeSessions(2))

		if call.filter.ClientID != "web-app" {
			t.Errorf("filter.ClientID = %q, want web-app", call.filter.ClientID)
		}
		if call.filter.UserID != "" {
			t.Errorf("filter.UserID = %q, want empty", call.filter.UserID)
		}
		if call.userID != "" {
			t.Errorf("positional userID = %q, want empty (filter carries the args)", call.userID)
		}
	})

	t.Run("userId arg still reaches SessionFilter.UserID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockSessionRepository(ctrl)

		call, _ := serveSessions(t, repo,
			`query { sessions(userId: "u-42") { totalCount } }`,
			makeSessions(1))

		if call.filter.UserID != "u-42" {
			t.Errorf("filter.UserID = %q, want u-42", call.filter.UserID)
		}
		if call.userID != "u-42" {
			t.Errorf("positional userID = %q, want u-42", call.userID)
		}
		if call.filter.ClientID != "" {
			t.Errorf("filter.ClientID = %q, want empty", call.filter.ClientID)
		}
	})

	t.Run("clientId and userId compose in the same filter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockSessionRepository(ctrl)

		call, _ := serveSessions(t, repo,
			`query { sessions(userId: "u-42", clientId: "web-app") { totalCount } }`,
			makeSessions(1))

		if call.filter.UserID != "u-42" || call.filter.ClientID != "web-app" {
			t.Errorf("filter = %+v, want UserID=u-42 ClientID=web-app", call.filter)
		}
	})

	t.Run("no args produces a zero-value filter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockSessionRepository(ctrl)

		call, _ := serveSessions(t, repo,
			`query { sessions { totalCount } }`,
			[]*domain.Session{})

		if call.filter.UserID != "" || call.filter.ClientID != "" {
			t.Errorf("filter = %+v, want zero-value UserID and ClientID", call.filter)
		}
		if call.userID != "" {
			t.Errorf("positional userID = %q, want empty", call.userID)
		}
	})
}

// TestSessionsResolver_NonPaginatedConnection covers the sessions connection
// shape: unlike Users/Clients, ListSessionsByUserID takes no skip/limit, so
// first/after are accepted by the query but do not change the connection
// (TotalCount = len(returned), PageInfo false/false). This locks the
// plan-mandated non-paginated semantics.
func TestSessionsResolver_NonPaginatedConnection(t *testing.T) {
	t.Run("first and after args are accepted without changing non-paginated semantics", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockSessionRepository(ctrl)

		sessions := makeSessions(3)
		call, resp := serveSessions(t, repo,
			`query { sessions(clientId: "web-app", first: 10, after: 5) { edges { cursor } totalCount pageInfo { hasNextPage hasPreviousPage } } }`,
			sessions)

		if call.filter.ClientID != "web-app" {
			t.Errorf("filter.ClientID = %q, want web-app", call.filter.ClientID)
		}
		if len(resp.Data.Sessions.Edges) != 3 {
			t.Errorf("edges = %d, want 3", len(resp.Data.Sessions.Edges))
		}
		if resp.Data.Sessions.Edges[0].Cursor != "s01" {
			t.Errorf("first cursor = %q, want s01", resp.Data.Sessions.Edges[0].Cursor)
		}
		if resp.Data.Sessions.TotalCount != 3 {
			t.Errorf("totalCount = %d, want 3 (len of returned sessions)", resp.Data.Sessions.TotalCount)
		}
		if resp.Data.Sessions.PageInfo.HasNextPage || resp.Data.Sessions.PageInfo.HasPreviousPage {
			t.Errorf("pageInfo = %+v, want false/false (sessions not paginated by the repo)", resp.Data.Sessions.PageInfo)
		}
	})

	t.Run("clientId filter with empty result still yields a well-formed connection", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)
		repo := mock_domain.NewMockSessionRepository(ctrl)

		call, resp := serveSessions(t, repo,
			`query { sessions(clientId: "no-such-client") { edges { cursor } totalCount pageInfo { hasNextPage hasPreviousPage } } }`,
			[]*domain.Session{})

		if call.filter.ClientID != "no-such-client" {
			t.Errorf("filter.ClientID = %q, want no-such-client", call.filter.ClientID)
		}
		if len(resp.Data.Sessions.Edges) != 0 || resp.Data.Sessions.TotalCount != 0 {
			t.Errorf("edges/totalCount = %d/%d, want 0/0", len(resp.Data.Sessions.Edges), resp.Data.Sessions.TotalCount)
		}
		if resp.Data.Sessions.PageInfo.HasNextPage || resp.Data.Sessions.PageInfo.HasPreviousPage {
			t.Errorf("pageInfo = %+v, want false/false", resp.Data.Sessions.PageInfo)
		}
	})
}
