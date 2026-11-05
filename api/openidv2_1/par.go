package openidv2_1

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

const (
	parTTL        = 60 * time.Second
	parMaxBody    = 64 << 10
	parMaxEntries = 10000
)

type parEntry struct {
	params    map[string]string
	clientID  string
	expiresAt time.Time
}

// parStore holds pushed authorization requests keyed by request_uri.
// It is process-local; multi-replica deployments need a shared store.
type parStore struct {
	mu   sync.Mutex
	data map[string]parEntry
}

var defaultPARStore = &parStore{data: make(map[string]parEntry)}

func (s *parStore) sweepLocked(now time.Time) {
	for k, e := range s.data {
		if now.After(e.expiresAt) {
			delete(s.data, k)
		}
	}
}

func (s *parStore) put(uri, clientID string, params map[string]string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sweepLocked(now)
	if len(s.data) >= parMaxEntries {
		return false
	}
	s.data[uri] = parEntry{params: params, clientID: clientID, expiresAt: now.Add(parTTL)}
	return true
}

// PushedAuthorizationRequestHandler implements RFC 9126 (PAR).
func (oa *OAuth2API) PushedAuthorizationRequestHandler(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, parMaxBody)
	applyBasicClientAuth(c)
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("invalid or oversized request body"))
		return
	}

	clientID := c.Request.PostForm.Get("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("client_id is required"))
		return
	}
	if c.Request.PostForm.Get("request_uri") != "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("request_uri must not be used in a pushed request"))
		return
	}

	ctx := c.Request.Context()
	cli, err := oa.clientService.GetClient(ctx, clientID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("Invalid client credentials"))
		return
	}

	form := c.Request.PostForm
	authParams := map[string][]string{
		"client_secret":         {form.Get("client_secret")},
		"client_assertion":      {form.Get("client_assertion")},
		"client_assertion_type": {form.Get("client_assertion_type")},
	}
	if cli.IsConfidential && form.Get("client_secret") == "" && form.Get("client_assertion") == "" {
		c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("Client authentication required"))
		return
	}
	if _, err := oa.authenticateClient(ctx, clientID, cli, authParams); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("client_id", clientID).Msg("PAR client authentication failed")
		c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("Invalid client credentials"))
		return
	}

	params := make(map[string]string)
	for k, v := range form {
		switch k {
		case "client_secret", "client_assertion", "client_assertion_type":
			continue
		}
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	uri := "urn:ietf:params:oauth:request_uri:" + hex.EncodeToString(buf)
	if !defaultPARStore.put(uri, clientID, params) {
		c.JSON(http.StatusServiceUnavailable, domain.NewServerError("too many pending pushed requests"))
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"request_uri": uri,
		"expires_in":  int(parTTL.Seconds()),
	})
}

// LookupPAR returns stored params for a request_uri without consuming it.
func LookupPAR(uri string) (map[string]string, bool) {
	defaultPARStore.mu.Lock()
	defer defaultPARStore.mu.Unlock()
	e, ok := defaultPARStore.data[uri]
	if !ok || time.Now().After(e.expiresAt) {
		delete(defaultPARStore.data, uri)
		return nil, false
	}
	return copyParams(e.params), true
}

// ConsumePAR atomically resolves and removes a request_uri (single use).
// It fails when the request was pushed by a different client than clientID;
// an empty clientID skips that binding check.
func ConsumePAR(uri, clientID string) (map[string]string, bool) {
	defaultPARStore.mu.Lock()
	defer defaultPARStore.mu.Unlock()
	e, ok := defaultPARStore.data[uri]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		delete(defaultPARStore.data, uri)
		return nil, false
	}
	if clientID != "" && clientID != e.clientID {
		return nil, false
	}
	delete(defaultPARStore.data, uri)
	return copyParams(e.params), true
}

func copyParams(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
