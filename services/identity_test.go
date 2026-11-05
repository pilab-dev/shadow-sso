package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/identity"
)

// fakeRepos answers the one repository the identity seam needs.
type fakeRepos struct {
	RepositoryProvider
	users domain.UserRepository
}

func (f fakeRepos) UserRepository(context.Context) domain.UserRepository { return f.users }

// fakeUsers stands in for the local user collection.
type fakeUsers struct {
	domain.UserRepository
}

func TestNewIdentityServiceIsLocalByDefault(t *testing.T) {
	for name, cfg := range map[string]*config.Config{
		"nil config":  nil,
		"empty":       {},
		"explicit":    {IdentitySource: identity.SourceLocal},
		"other value": {IdentitySource: ""},
	} {
		t.Run(name, func(t *testing.T) {
			svc, err := newIdentityService(cfg, fakeRepos{users: &fakeUsers{}}, nil)
			require.NoError(t, err)
			assert.Equal(t, identity.SourceLocal, svc.Name())
		})
	}
}

func TestNewIdentityServiceRefusesAnUnknownSource(t *testing.T) {
	_, err := newIdentityService(&config.Config{IdentitySource: "ldap"}, fakeRepos{}, nil)
	require.ErrorContains(t, err, "unknown identity_source")
	require.ErrorContains(t, err, "ldap")
}

func TestNewIdentityServiceNeedsAnAddressForTheDirectory(t *testing.T) {
	_, err := newIdentityService(&config.Config{IdentitySource: identity.SourceDirectory}, fakeRepos{}, nil)
	require.ErrorContains(t, err, "directory_addr")
}

func TestNewIdentityServiceRefusesToReachADirectoryItCannotRead(t *testing.T) {
	_, err := newIdentityService(&config.Config{
		IdentitySource: identity.SourceDirectory,
		DirectoryAddr:  "https://127.0.0.1:7443",
	}, fakeRepos{}, nil)
	require.ErrorContains(t, err, "client certificate")
}
