package commands

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
)

// loginViaOIDC drives the OAuth 2.0 loopback-redirect flow:
//
//  1. Bind a one-shot listener on 127.0.0.1:0.
//  2. Ask vaultd for an authorization_url (passing cli_callback as the listener).
//  3. Open the user's browser at the authorization_url (or print it for headless).
//  4. The listener receives ?token=... when vault completes the OIDC dance and
//     redirects back to the cli_callback URL.
//
// manual = true skips steps 1+4 (no listener) and asks the user to paste the
// final redirect URL after completing login in a browser elsewhere.
func loginViaOIDC(serverURL string, manual, insecure bool, caCert []byte, caCertFile string) error {
	if manual {
		return loginViaOIDCManual(serverURL, insecure, caCert, caCertFile)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("bind loopback listener: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	cliCallback := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	authzURL, err := fetchAuthorizationURL(serverURL, cliCallback, insecure, caCert)
	if err != nil {
		return err
	}

	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{
		Handler:           loopbackHandler(tokenCh, errCh),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	if err := openBrowser(authzURL); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open browser automatically. Please open this URL in a browser:\n  %s\n", authzURL)
	} else {
		fmt.Printf("Opening browser for SSO login...\n  If it didn't open, visit: %s\n", authzURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	var token string
	select {
	case token = <-tokenCh:
	case err := <-errCh:
		return fmt.Errorf("loopback listener: %w", err)
	case <-ctx.Done():
		return fmt.Errorf("login timed out after 5 minutes — try again or use --manual")
	}
	if token == "" {
		return fmt.Errorf("login completed but no token was received")
	}
	return persistOIDCLogin(serverURL, token, insecure, caCertFile)
}

// loopbackHandler returns the single-shot HTTP handler for the loopback URL.
// It captures ?token=... or ?error=... from the redirect and signals tokenCh /
// errCh accordingly.
func loopbackHandler(tokenCh chan<- string, errCh chan<- error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			errCh <- fmt.Errorf("auth error: %s — %s", e, q.Get("error_description"))
			http.Error(w, "Login failed: "+e, http.StatusBadRequest)
			return
		}
		token := q.Get("token")
		if token == "" {
			errCh <- fmt.Errorf("callback received without token")
			http.Error(w, "Missing token", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(loopbackSuccessHTML))
		tokenCh <- token
	})
	return mux
}

const loopbackSuccessHTML = `<!doctype html>
<html><head><title>Vault — Login successful</title>
<style>body{font-family:sans-serif;text-align:center;padding-top:4em;color:#333}
h1{color:#0a7}</style></head>
<body><h1>Login successful</h1>
<p>You can close this window and return to the terminal.</p>
</body></html>`

// fetchAuthorizationURL calls vault's /api/v1/auth/oidc/login endpoint with the
// cli_callback parameter and parses out the authorization_url to redirect to.
func fetchAuthorizationURL(serverURL, cliCallback string, insecure bool, caCert []byte) (string, error) {
	q := url.Values{}
	q.Set("cli_callback", cliCallback)
	var resp struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := client.NoAuth(serverURL, "GET", "/api/v1/auth/oidc/login?"+q.Encode(),
		nil, &resp, insecure, caCert); err != nil {
		return "", fmt.Errorf("get authorization url: %w", err)
	}
	if resp.AuthorizationURL == "" {
		return "", fmt.Errorf("server returned empty authorization_url — is OIDC enabled? (set VAULT_OIDC_ISSUER etc on the server)")
	}
	return resp.AuthorizationURL, nil
}

// loginViaOIDCManual handles the SSH/headless case. The CLI prints the auth URL,
// the user completes login in any browser, and pastes the final redirect URL
// (which contains ?token=...). This needs no loopback listener.
func loginViaOIDCManual(serverURL string, insecure bool, caCert []byte, caCertFile string) error {
	authzURL, err := fetchAuthorizationURL(serverURL, "", insecure, caCert)
	if err != nil {
		return err
	}
	fmt.Println("Open this URL in any browser to complete the OIDC login:")
	fmt.Println("  " + authzURL)
	fmt.Println()
	fmt.Println("After login, your browser will be redirected to a URL containing ?token=...")
	fmt.Println("Paste that full URL (or just the token) here.")
	pasted := promptLine("Redirect URL or token: ")
	token, err := extractTokenFromPasted(pasted)
	if err != nil {
		return err
	}
	return persistOIDCLogin(serverURL, token, insecure, caCertFile)
}

// extractTokenFromPasted parses a pasted redirect URL or bare token, returning
// just the session token. Empty input returns an error.
func extractTokenFromPasted(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("no input provided")
	}
	if !strings.Contains(s, "://") && !strings.Contains(s, "?") {
		// Looks like a bare token.
		return s, nil
	}
	if !strings.Contains(s, "?") {
		// URL with no query string.
		return "", fmt.Errorf("pasted URL has no ?token= query parameter")
	}
	// Parse as URL or just as query params after "?".
	parsed, err := url.Parse(s)
	if err != nil || parsed.RawQuery == "" {
		// Try treating s as bare query string (after "?").
		_, after, ok := strings.Cut(s, "?")
		if !ok {
			return "", fmt.Errorf("could not parse: %w", err)
		}
		q, perr := url.ParseQuery(after)
		if perr != nil {
			return "", fmt.Errorf("parse query: %w", perr)
		}
		token := q.Get("token")
		if token == "" {
			return "", fmt.Errorf("query has no token parameter")
		}
		return token, nil
	}
	token := parsed.Query().Get("token")
	if token == "" {
		return "", fmt.Errorf("URL has no token parameter")
	}
	return token, nil
}

// persistOIDCLogin saves the session token to the global config — same place
// the email/password login path writes.
func persistOIDCLogin(serverURL, token string, insecure bool, caCertFile string) error {
	if err := config.SaveGlobal(config.Global{
		ServerURL:     strings.TrimRight(serverURL, "/"),
		Token:         token,
		TLSSkipVerify: insecure,
		CACertPath:    caCertFile,
	}); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Println("Logged in via SSO.")
	return nil
}

// openBrowser opens the user's default browser at url. Indirected through
// browserOpener so tests can substitute a no-op.
var browserOpener = realBrowserOpener

func openBrowser(rawURL string) error { return browserOpener(rawURL) }

func realBrowserOpener(rawURL string) error {
	// Skip auto-open in obviously-headless environments — the caller will print
	// the URL instead.
	if isHeadless() {
		return fmt.Errorf("no display detected (headless session)")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default: // linux, *bsd
		cmd = exec.Command("xdg-open", rawURL)
	}
	return cmd.Start()
}

func isHeadless() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// On Linux, no DISPLAY/WAYLAND_DISPLAY usually means SSH or container.
	return os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
}
