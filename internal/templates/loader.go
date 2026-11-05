package templates

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/pilab-dev/shadow-sso/port"
)

// EmbeddedFS is the embedded template filesystem supplied by the caller.
var EmbeddedFS embed.FS

// Loader implements port.TemplateLoader with an on-disk override directory
// (SHADOW_SSO_TEMPLATE_DIR) layered on top of an embedded FS.
type Loader struct {
	mu       sync.RWMutex
	embedded fs.FS
	dir      string // override directory; "" means embedded-only
}

// New creates a Loader. If dir is non-empty it must exist; templates found
// there take precedence over embedded ones.
func New(embedded fs.FS, dir string) *Loader {
	if dir != "" {
		if _, err := os.Stat(dir); err != nil {
			dir = ""
		}
	}
	return &Loader{embedded: embedded, dir: dir}
}

// FromEnv builds a Loader using SHADOW_SSO_TEMPLATE_DIR (if set) over the
// provided embedded FS.
func FromEnv(embedded fs.FS) *Loader {
	return New(embedded, os.Getenv("SHADOW_SSO_TEMPLATE_DIR"))
}

func (l *Loader) Read(name string) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.dir != "" {
		if b, err := os.ReadFile(filepath.Join(l.dir, name)); err == nil {
			return b, nil
		}
	}
	if l.embedded != nil {
		return fs.ReadFile(l.embedded, name)
	}
	return nil, fmt.Errorf("template not found: %s", name)
}

func (l *Loader) FS() fs.FS {
	// Return a composite FS: on-disk dir if set, else embedded.
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.dir != "" {
		return os.DirFS(l.dir)
	}
	return l.embedded
}

func (l *Loader) Reload() error {
	// For on-disk overrides there is nothing to cache; embedded is immutable.
	// This method exists so callers (gRPC/HTTP) can signal a cache bust.
	l.mu.Lock()
	defer l.mu.Unlock()
	return nil
}

// Ensure interface compliance.
var _ port.TemplateLoader = (*Loader)(nil)