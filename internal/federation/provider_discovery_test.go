package federation

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newDiscoveryServer(t *testing.T, emailVerified bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q}`,
			srv.URL, srv.URL+"/authorize", srv.URL+"/tok", srv.URL+"/me")
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"sub":"u1","email":"a@b.c","email_verified":%t,"given_name":"A","preferred_username":"ab"}`, emailVerified)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestBaseProviderDiscovery(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	p := NewBaseProvider(&domain.IdentityProvider{OIDCClientID: "id", OIDCClientSecret: "s", OIDCIssuerURL: srv.URL})

	cfg, err := p.GetOAuth2Config("http://cb")
	require.NoError(t, err)
	require.Equal(t, srv.URL+"/authorize", cfg.Endpoint.AuthURL)
	require.Equal(t, srv.URL+"/tok", cfg.Endpoint.TokenURL)

	info, err := p.FetchUserInfo(context.Background(), &oauth2.Token{AccessToken: "x"})
	require.NoError(t, err)
	require.Equal(t, "u1", info.ProviderUserID)
	require.Equal(t, "ab", info.Username)
}

func TestBaseProviderRejectsUnverifiedEmail(t *testing.T) {
	srv := newDiscoveryServer(t, false)
	p := NewBaseProvider(&domain.IdentityProvider{OIDCClientID: "id", OIDCClientSecret: "s", OIDCIssuerURL: srv.URL})
	_, err := p.FetchUserInfo(context.Background(), &oauth2.Token{AccessToken: "x"})
	require.ErrorIs(t, err, ErrEmailNotVerified)
}

func TestBaseProviderIssuerMismatch(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	p := NewBaseProvider(&domain.IdentityProvider{OIDCClientID: "id", OIDCClientSecret: "s", OIDCIssuerURL: srv.URL + "/"})
	_, err := p.GetOAuth2Config("http://cb")
	require.NoError(t, err) // trailing slash normalised

	p2 := NewBaseProvider(&domain.IdentityProvider{OIDCClientID: "id", OIDCClientSecret: "s", OIDCIssuerURL: "http://127.0.0.1:1"})
	_, err = p2.GetOAuth2Config("http://cb")
	require.ErrorIs(t, err, ErrProviderMisconfigured)
}
