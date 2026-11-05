package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestTokenIntrospection_ActiveIncludesAuthorizationDetails(t *testing.T) {
	ctrl := gomock.NewController(t)
	tokens := newFakeIntrospectTokens()
	users := mock_domain.NewMockUserRepository(ctrl)
	exp := time.Now().Add(time.Hour)
	tokens.access["tok"] = &domain.TokenInfo{
		ID: "jti", TokenType: "access_token", ClientID: "c1", UserID: "u1", Scope: "openid",
		IssuedAt: time.Now(), ExpiresAt: exp, AuthorizationDetails: `[{"type":"payment"}]`,
	}
	users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{Email: "a@b.c"}, nil)
	server := NewTokenIntrospectionServer(tokens, users, "https://iss")

	resp, err := server.IntrospectToken(context.Background(), connect.NewRequest(&ssov1.IntrospectTokenRequest{Token: "tok"}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Active)
	assert.Equal(t, "a@b.c", resp.Msg.Username)
	assert.Equal(t, "https://iss", resp.Msg.Iss)
	assert.Equal(t, `[{"type":"payment"}]`, resp.Msg.AuthorizationDetails)
	assert.Equal(t, exp.Unix(), resp.Msg.Exp)
}

func TestTokenIntrospection_UnknownAndRevokedInactive(t *testing.T) {
	tokens := newFakeIntrospectTokens()
	tokens.access["rev"] = &domain.TokenInfo{IsRevoked: true, ExpiresAt: time.Now().Add(time.Hour)}
	server := NewTokenIntrospectionServer(tokens, nil, "iss")

	for _, tok := range []string{"bad", "rev"} {
		resp, err := server.IntrospectToken(context.Background(), connect.NewRequest(&ssov1.IntrospectTokenRequest{Token: tok}))
		require.NoError(t, err)
		assert.False(t, resp.Msg.Active)
	}
}

func TestTokenIntrospection_EmptyTokenRejected(t *testing.T) {
	server := NewTokenIntrospectionServer(newFakeIntrospectTokens(), nil, "iss")
	_, err := server.IntrospectToken(context.Background(), connect.NewRequest(&ssov1.IntrospectTokenRequest{}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

type fakeIntrospectTokens struct {
	TokenService
	access  map[string]*domain.TokenInfo
	refresh map[string]*domain.TokenInfo
}

func newFakeIntrospectTokens() *fakeIntrospectTokens {
	return &fakeIntrospectTokens{access: map[string]*domain.TokenInfo{}, refresh: map[string]*domain.TokenInfo{}}
}

func (f *fakeIntrospectTokens) GetAccessTokenInfo(_ context.Context, v string) (*domain.TokenInfo, error) {
	if i, ok := f.access[v]; ok {
		return i, nil
	}
	return nil, errors.New("not found")
}

func (f *fakeIntrospectTokens) GetRefreshTokenInfo(_ context.Context, v string) (*domain.TokenInfo, error) {
	if i, ok := f.refresh[v]; ok {
		return i, nil
	}
	return nil, errors.New("not found")
}
