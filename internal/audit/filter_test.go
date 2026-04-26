package audit

import (
	"testing"
	"time"
)

func TestFilter_ZeroValue(t *testing.T) {
	var f Filter
	if f.ProjectID != "" || f.EnvID != "" || f.Action != "" || f.Limit != 0 {
		t.Errorf("expected zero-value Filter, got %+v", f)
	}
}

func TestFilter_Fields(t *testing.T) {
	f := Filter{ProjectID: "proj-1", EnvID: "env-1", Action: "secret.get", Limit: 25}
	if f.ProjectID != "proj-1" {
		t.Errorf("ProjectID = %q", f.ProjectID)
	}
	if f.EnvID != "env-1" {
		t.Errorf("EnvID = %q", f.EnvID)
	}
	if f.Action != "secret.get" {
		t.Errorf("Action = %q", f.Action)
	}
	if f.Limit != 25 {
		t.Errorf("Limit = %d", f.Limit)
	}
}

func TestConstants(t *testing.T) {
	if Subject == "" {
		t.Error("Subject must not be empty")
	}
	if StreamName == "" {
		t.Error("StreamName must not be empty")
	}
	if StreamMaxAge <= 0 {
		t.Error("StreamMaxAge must be positive")
	}
	// PCI-DSS 10.5 requires 12 months; 400 days > 365 — verify the floor.
	if StreamMaxAge < 365*24*time.Hour {
		t.Errorf("StreamMaxAge %v is less than 1 year (PCI-DSS requirement)", StreamMaxAge)
	}
}
