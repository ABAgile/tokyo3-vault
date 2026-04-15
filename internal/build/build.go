// Package build exposes version information read from the embedded build info.
// All three values are populated from runtime/debug.ReadBuildInfo — no ldflags needed.
package build

import "runtime/debug"

var (
	Version    = "dev"
	Commit     = "unknown"
	CommitTime = "unknown"
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		Version = info.Main.Version
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 7 {
				Commit = s.Value[:7]
			} else if s.Value != "" {
				Commit = s.Value
			}
		case "vcs.time":
			if s.Value != "" {
				CommitTime = s.Value
			}
		}
	}
}
