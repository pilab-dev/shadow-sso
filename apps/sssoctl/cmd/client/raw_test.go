package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	_ "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListRPCMethods_IncludesUserService(t *testing.T) {
	methods, err := ListRPCMethods()
	require.NoError(t, err)
	require.NotEmpty(t, methods)

	found := false
	for _, m := range methods {
		if m.Service == "UserService" && m.Method == "GetUser" {
			found = true
			assert.Equal(t, "GetUserRequest", m.Input)
			break
		}
	}
	assert.True(t, found, "UserService/GetUser must be registered")
}

func TestCallRPC_DynamicUnary(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "user-1", body["user_id"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":{"id":"user-1","email":"user@example.com","status":"USER_STATUS_ACTIVE"}}`))
	}))
	defer srv.Close()

	out, err := CallRPC(context.Background(), &config.Context{ServerEndpoint: srv.URL}, "UserService/GetUser", []byte(`{"user_id":"user-1"}`))
	require.NoError(t, err)
	assert.Equal(t, "POST", gotMethod)
	assert.Equal(t, "/sso.v1.UserService/GetUser", gotPath)
	assert.Contains(t, string(out), "user@example.com")
}

func TestCallRPC_ConnectError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"not_found","message":"user not found"}`))
	}))
	defer srv.Close()

	_, err := CallRPC(context.Background(), &config.Context{ServerEndpoint: srv.URL}, "UserService/GetUser", []byte(`{"user_id":"missing"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not_found")
	assert.Contains(t, err.Error(), "user not found")
}
