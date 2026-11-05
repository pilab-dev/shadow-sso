package port

import "io/fs"

// TemplateLoader resolves template files by name, allowing ShadowSSO to run
// with embedded templates by default while permitting operators to override
// them from disk (and reload without rebuilding).
type TemplateLoader interface {
	// Read returns the template content for the given name.
	Read(name string) ([]byte, error)
	// FS returns the underlying filesystem (embedded or on-disk) for engines
	// that need an fs.FS (e.g. html/template ParseFS).
	FS() fs.FS
	// Reload re-reads templates from disk (no-op for embedded-only loaders).
	Reload() error
}