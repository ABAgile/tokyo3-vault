package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// makeTestServer creates an httptest.Server that responds per the handler function.
func makeTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// TestNew tests that New constructs a client correctly.
func TestNew(t *testing.T) {
	c := New("https://vault.example.com/", "my-token")
	if c == nil {
		t.Fatal("New returned nil")
	}
	if c.base != "https://vault.example.com" {
		t.Errorf("base = %q, want trailing slash stripped", c.base)
	}
	if c.token != "my-token" {
		t.Errorf("token = %q, want my-token", c.token)
	}
}

// TestDo_Success tests a successful JSON request.
func TestDo_Success(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"key": "value"})
	})

	c := New(srv.URL, "test-token")
	var out map[string]string
	if err := c.Do(http.MethodGet, "/test", nil, &out); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if out["key"] != "value" {
		t.Errorf("out[key] = %q, want value", out["key"])
	}
}

// TestDo_HTTP4xxWithErrorJSON tests that 4xx with error JSON is decoded.
func TestDo_HTTP4xxWithErrorJSON(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	})

	c := New(srv.URL, "bad-token")
	err := c.Do(http.MethodGet, "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("error = %q, want 'unauthorized'", err.Error())
	}
}

// TestDo_HTTP4xxWithoutJSON tests that 4xx without JSON body falls back to HTTP status.
func TestDo_HTTP4xxWithoutJSON(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	c := New(srv.URL, "tok")
	err := c.Do(http.MethodGet, "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error for 403")
	}
	if err.Error() != "HTTP 403" {
		t.Errorf("error = %q, want 'HTTP 403'", err.Error())
	}
}

// TestGet tests the Get convenience wrapper.
func TestGet(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]int{"count": 42})
	})

	c := New(srv.URL, "tok")
	var out map[string]int
	if err := c.Get("/items", &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out["count"] != 42 {
		t.Errorf("count = %d, want 42", out["count"])
	}
}

// TestPost tests the Post convenience wrapper.
func TestPost(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "new-1"})
	})

	c := New(srv.URL, "tok")
	var out map[string]string
	if err := c.Post("/items", map[string]string{"name": "item"}, &out); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if out["id"] != "new-1" {
		t.Errorf("id = %q, want new-1", out["id"])
	}
}

// TestPut tests the Put convenience wrapper.
func TestPut(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %q, want PUT", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	c := New(srv.URL, "tok")
	var out map[string]string
	if err := c.Put("/items/1", map[string]string{"name": "updated"}, &out); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

// TestDelete tests the Delete convenience wrapper.
func TestDelete(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	c := New(srv.URL, "tok")
	if err := c.Delete("/items/1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestPostText_Success tests PostText success.
func TestPostText_Success(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		json.NewEncoder(w).Encode(map[string]int{"imported": 3})
	})

	c := New(srv.URL, "tok")
	var out map[string]int
	if err := c.PostText("/upload", "KEY=value\n", &out); err != nil {
		t.Fatalf("PostText: %v", err)
	}
	if out["imported"] != 3 {
		t.Errorf("imported = %d, want 3", out["imported"])
	}
}

// TestPostText_Error tests PostText with a 4xx error.
func TestPostText_Error(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "bad input"})
	})

	c := New(srv.URL, "tok")
	err := c.PostText("/upload", "bad", nil)
	if err == nil {
		t.Fatal("expected error for 400")
	}
}

// TestGetText_Success tests GetText success.
func TestGetText_Success(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("KEY=value\nOTHER=x\n"))
	})

	c := New(srv.URL, "tok")
	body, err := c.GetText("/envfile")
	if err != nil {
		t.Fatalf("GetText: %v", err)
	}
	if body != "KEY=value\nOTHER=x\n" {
		t.Errorf("body = %q", body)
	}
}

// TestGetText_Error tests GetText with a 4xx error.
func TestGetText_Error(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	})

	c := New(srv.URL, "tok")
	_, err := c.GetText("/envfile")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

// TestNoAuth tests the NoAuth function completes a request successfully.
// Note: NoAuth uses the same Do() internals which always sends "Bearer <token>".
// When token is empty, the header is "Bearer " — this is the current implementation behavior.
func TestNoAuth(t *testing.T) {
	srv := makeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"token": "sess-tok"})
	})

	var out map[string]string
	if err := NoAuth(srv.URL, http.MethodPost, "/auth/login", map[string]string{"email": "a@b.com"}, &out); err != nil {
		t.Fatalf("NoAuth: %v", err)
	}
	if out["token"] != "sess-tok" {
		t.Errorf("token = %q, want sess-tok", out["token"])
	}
}
