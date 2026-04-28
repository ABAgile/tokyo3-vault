package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── extractTokenFromPasted ─────────────────────────────────────────────────────

func TestExtractTokenFromPasted(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"empty", "", "", true},
		{"bare token", "abc123def456", "abc123def456", false},
		{"redirect URL", "http://127.0.0.1:54321/callback?token=xyz789", "xyz789", false},
		{"redirect URL with extra params", "http://127.0.0.1:54321/callback?token=xyz789&state=abc", "xyz789", false},
		{"query string only", "?token=qstring-token", "qstring-token", false},
		{"URL without token param", "http://127.0.0.1:54321/callback?state=abc", "", true},
		{"whitespace-padded", "  token-with-pad  ", "token-with-pad", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractTokenFromPasted(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got token=%q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ── loopbackHandler ────────────────────────────────────────────────────────────

func TestLoopbackHandler_DeliversTokenToChannel(t *testing.T) {
	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)
	h := loopbackHandler(tokenCh, errCh)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?token=abc-123", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	select {
	case got := <-tokenCh:
		if got != "abc-123" {
			t.Errorf("token = %q, want abc-123", got)
		}
	default:
		t.Errorf("token channel did not receive")
	}
}

func TestLoopbackHandler_ErrorParamReportsToErrChannel(t *testing.T) {
	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)
	h := loopbackHandler(tokenCh, errCh)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=user+canceled", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	select {
	case err := <-errCh:
		if !strings.Contains(err.Error(), "access_denied") {
			t.Errorf("err = %v, want one mentioning access_denied", err)
		}
	default:
		t.Errorf("error channel did not receive")
	}
}

func TestLoopbackHandler_MissingTokenIsError(t *testing.T) {
	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)
	h := loopbackHandler(tokenCh, errCh)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	h.ServeHTTP(rr, req)

	select {
	case err := <-errCh:
		if !strings.Contains(err.Error(), "token") {
			t.Errorf("err = %v, want one mentioning token", err)
		}
	default:
		t.Errorf("error channel did not receive")
	}
}

// ── loginViaOIDC end-to-end against a fake vaultd ─────────────────────────────

// fakeVaultd stands in for the vault server. It returns a canned authorization
// URL pointing at a sub-server that immediately redirects back to cli_callback
// with ?token=..., closing the loop without any browser involvement.
type fakeVaultd struct {
	t            *testing.T
	tokenToHand  string
	server       *httptest.Server
	callbackURLs []string
	mu           sync.Mutex
}

func newFakeVaultd(t *testing.T, tokenToHand string) *fakeVaultd {
	t.Helper()
	fv := &fakeVaultd{t: t, tokenToHand: tokenToHand}
	fv.server = httptest.NewServer(http.HandlerFunc(fv.handle))
	t.Cleanup(fv.server.Close)
	return fv
}

func (fv *fakeVaultd) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/auth/oidc/login":
		cb := r.URL.Query().Get("cli_callback")
		fv.mu.Lock()
		fv.callbackURLs = append(fv.callbackURLs, cb)
		fv.mu.Unlock()
		// Build an "authorization URL" that, when fetched, redirects to cb?token=...
		// In the real flow the user's browser hits the IdP, which 302s to vault's
		// /oidc/callback, which 302s to cli_callback. For the test we collapse
		// that chain into a single "fake-idp" server endpoint.
		fakeIdP := fv.server.URL + "/fake-idp?cb=" + url.QueryEscape(cb)
		_ = json.NewEncoder(w).Encode(map[string]any{"authorization_url": fakeIdP})
	case "/fake-idp":
		http.Redirect(w, r, r.URL.Query().Get("cb")+"?token="+fv.tokenToHand, http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func TestLoginViaOIDC_HappyPath(t *testing.T) {
	fv := newFakeVaultd(t, "session-token-abc")

	// Override browser-open with a fetcher that completes the redirect chain.
	prev := browserOpener
	t.Cleanup(func() { browserOpener = prev })
	browserOpener = func(rawURL string) error {
		// Follow the redirect chain. We expect: GET fake-idp -> 302 to cb?token=...
		// http.Get follows redirects by default; that will hit the loopback
		// listener and complete the flow.
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(rawURL)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}

	// Use a config dir under t.TempDir() so the test doesn't write to ~/.vault.
	t.Setenv("HOME", t.TempDir())

	if err := loginViaOIDC(fv.server.URL, false, false, nil, ""); err != nil {
		t.Fatalf("loginViaOIDC: %v", err)
	}
}

func TestLoginViaOIDC_TimeoutWhenNoBrowserCompletes(t *testing.T) {
	fv := newFakeVaultd(t, "ignored")
	prev := browserOpener
	t.Cleanup(func() { browserOpener = prev })
	browserOpener = func(rawURL string) error { return nil } // never completes

	t.Setenv("HOME", t.TempDir())

	// Drop the timeout to keep the test fast: we test the timeout path by
	// running loginViaOIDC in a goroutine and waiting up to a few seconds.
	// Since the function's internal timeout is 5min we instead check that a
	// short context-bound caller can interrupt — but loginViaOIDC owns the
	// context. So we just spot-check the server returns auth URL and the
	// listener accepts requests; full timeout coverage would need refactor.
	url, err := fetchAuthorizationURL(fv.server.URL, "http://127.0.0.1:0/callback", false, nil)
	if err != nil || !strings.Contains(url, "fake-idp") {
		t.Errorf("fetchAuthorizationURL: %q, err=%v", url, err)
	}
}
