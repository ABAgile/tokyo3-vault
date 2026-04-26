package build

import "testing"

// TestBuildVars tests that the build variables are accessible and have non-empty defaults.
func TestBuildVars(t *testing.T) {
	// These values are set by init() from runtime/debug.ReadBuildInfo.
	// In test context they will typically remain at their defaults.
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if Commit == "" {
		t.Error("Commit should not be empty")
	}
	if CommitTime == "" {
		t.Error("CommitTime should not be empty")
	}
	// Log the values for visibility.
	t.Logf("Version=%s Commit=%s CommitTime=%s", Version, Commit, CommitTime)
}
