package openidv2_1

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

const rarTypesCacheTTL = time.Minute

// rarTypesCache memoises the union of client-allowed authorization_details
// types so the public discovery endpoint does not list clients on every hit.
type rarTypesCache struct {
	mu      sync.Mutex
	types   []string
	expires time.Time
}

// authorizationDetailsTypes returns the sorted union of RFC 9396 types that
// any enabled client is allowed to request.
func (oa *OAuth2API) authorizationDetailsTypes(ctx context.Context) []string {
	if oa.clientRepo == nil {
		return nil
	}

	oa.rarTypesCache.mu.Lock()
	defer oa.rarTypesCache.mu.Unlock()

	if time.Now().Before(oa.rarTypesCache.expires) {
		return append([]string(nil), oa.rarTypesCache.types...)
	}

	clients, err := oa.clientRepo.ListClients(ctx, domain.ClientFilter{})
	if err != nil {
		log.Warn().Err(err).Msg("discovery: failed to list clients for authorization_details_types_supported")

		return append([]string(nil), oa.rarTypesCache.types...)
	}

	seen := map[string]struct{}{}
	for _, cl := range clients {
		for _, t := range cl.AllowedAuthorizationDetails {
			seen[t] = struct{}{}
		}
	}

	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, t)
	}
	sort.Strings(types)

	oa.rarTypesCache.types = types
	oa.rarTypesCache.expires = time.Now().Add(rarTypesCacheTTL)

	return append([]string(nil), types...)
}
