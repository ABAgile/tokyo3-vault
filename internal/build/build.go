// Package build exposes version information stamped at link time via ldflags.
// The Makefile sets these via: -X 'github.com/abagile/tokyo3-vault/internal/build.Version=...'
package build

// These variables are overwritten by the linker at build time.
// Defaults are used when running via `go run` without ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)
