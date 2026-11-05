package services

import (
	"fmt"

	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/directory"
	"github.com/pilab-dev/shadow-sso/internal/identity"
)

// newIdentityService builds the identity seam the login paths authenticate
// through. It is local unless the configuration points at a directory, and it
// fails construction when the directory is misconfigured, so a deployment
// that cannot reach its identity source refuses to start instead of failing
// every login.
func newIdentityService(cfg *config.Config, repos RepositoryProvider, hasher domain.PasswordHasher) (*identity.Service, error) {
	users := repos.UserRepository(initCtx)

	source := identity.SourceLocal
	if cfg != nil && cfg.IdentitySource != "" {
		source = cfg.IdentitySource
	}
	switch source {
	case identity.SourceLocal:
		// The local record is both the identity and the SSO state, so there
		// is no separate state store to merge.
		return identity.New(identity.NewLocalSource(users, hasher), nil), nil

	case identity.SourceDirectory:
		if cfg.DirectoryAddr == "" {
			return nil, fmt.Errorf("identity_source=%s needs directory_addr", identity.SourceDirectory)
		}
		dir, err := directory.New(directory.Config{
			Addr:         cfg.DirectoryAddr,
			CAFile:       cfg.DirectoryCAFile,
			CertFile:     cfg.DirectoryCertFile,
			KeyFile:      cfg.DirectoryKeyFile,
			ActorKeyFile: cfg.DirectoryActorKeyFile,
			Timeout:      cfg.DirectoryTimeout,
		})
		if err != nil {
			return nil, err
		}
		// The directory owns the identity; MFA, required actions, WebAuthn
		// and local roles stay here, keyed by the objectGUID.
		return identity.New(dir, identity.NewLocalState(users)), nil

	default:
		return nil, fmt.Errorf("unknown identity_source %q (want %q or %q)",
			source, identity.SourceLocal, identity.SourceDirectory)
	}
}
