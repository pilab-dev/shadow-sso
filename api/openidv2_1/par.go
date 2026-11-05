package openidv2_1

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// parStore holds pushed authorization requests keyed by request_uri.
type parStore struct {
	mu   sync.Mutex
	data map[string]map[string]string
}

var defaultPARStore = &parStore{data: make(map[string]map[string]string)}

// PushedAuthorizationRequestHandler implements RFC 9126 (PAR).
func (oa *OAuth2API) PushedAuthorizationRequestHandler(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	params := make(map[string]string)
	for k, v := range c.Request.PostForm {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	uri := "urn:ietf:params:oauth:request_uri:" + hex.EncodeToString(buf)
	defaultPARStore.mu.Lock()
	defaultPARStore.data[uri] = params
	defaultPARStore.mu.Unlock()

	// expire after 60s
	go func(u string) {
		time.Sleep(60 * time.Second)
		defaultPARStore.mu.Lock()
		delete(defaultPARStore.data, u)
		defaultPARStore.mu.Unlock()
	}(uri)

	c.JSON(http.StatusCreated, gin.H{
		"request_uri": uri,
		"expires_in":  60,
	})
}

// LookupPAR returns stored params for a request_uri.
func LookupPAR(uri string) (map[string]string, bool) {
	defaultPARStore.mu.Lock()
	defer defaultPARStore.mu.Unlock()
	v, ok := defaultPARStore.data[uri]
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(v))
	for k, val := range v {
		out[k] = val
	}
	return out, true
}
