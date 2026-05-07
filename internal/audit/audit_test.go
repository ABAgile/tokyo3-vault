package audit

import (
	"encoding/json"
	"testing"
	"time"
)

// TestEntry_JSONMarshal tests that Entry marshals with correct omitempty behavior.
func TestEntry_JSONMarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	// Full entry.
	full := Entry{
		ID:         "e-1",
		Action:     "secret.set",
		ActorID:    "tok-1",
		ProjectID:  "proj-1",
		EnvID:      "env-1",
		Resource:   "DB_URL",
		IP:         "127.0.0.1",
		Metadata:   `{"key":"val"}`,
		OccurredAt: now,
	}

	data, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("Marshal full: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "action", "actor_id", "project_id", "env_id", "resource", "ip", "metadata", "occurred_at"} {
		if _, ok := m[field]; !ok {
			t.Errorf("expected field %q in JSON", field)
		}
	}

	// Minimal entry — optional fields should be omitted.
	minimal := Entry{
		ID:         "e-2",
		Action:     "auth.login",
		OccurredAt: now,
	}
	data, err = json.Marshal(minimal)
	if err != nil {
		t.Fatalf("Marshal minimal: %v", err)
	}
	var m2 map[string]any
	if err := json.Unmarshal(data, &m2); err != nil {
		t.Fatal(err)
	}
	for _, omitted := range []string{"actor_id", "project_id", "env_id", "resource", "ip", "metadata"} {
		if _, ok := m2[omitted]; ok {
			t.Errorf("field %q should be omitted from minimal entry JSON", omitted)
		}
	}
}
