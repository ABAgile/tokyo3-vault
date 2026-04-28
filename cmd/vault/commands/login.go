package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func loginSessionName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "login"
}

func NewLoginCmd() *cobra.Command {
	var serverURL string
	var insecure bool
	var caCertFile string
	var clientCertFile string
	var clientKeyFile string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the Vault server",
		Long: `Authenticate with the Vault server.

Two authentication modes:

  Email/password (default):
    vault login --server https://vault.example.com

  Principal certificate (no password):
    vault login --server https://vault.example.com \
                --cert /path/to/client.crt \
                --key  /path/to/client.key

The certificate must have been registered server-side via:
    vault principals register --spiffe-id <URI> --project <slug>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverURL == "" {
				g, _ := config.LoadGlobal()
				serverURL = g.ServerURL
			}
			if serverURL == "" {
				serverURL = promptLine("Server URL: ")
			}
			serverURL = strings.TrimRight(serverURL, "/")

			var caCert []byte
			if caCertFile != "" {
				abs, err := filepath.Abs(caCertFile)
				if err != nil {
					return fmt.Errorf("resolve --cacert path: %w", err)
				}
				caCertFile = abs
				caCert, err = os.ReadFile(caCertFile)
				if err != nil {
					return fmt.Errorf("read --cacert: %w", err)
				}
			}

			// Cert-based login: save paths and exit — no password needed.
			if clientCertFile != "" || clientKeyFile != "" {
				if clientCertFile == "" || clientKeyFile == "" {
					return fmt.Errorf("--cert and --key must both be set")
				}
				certAbs, err := filepath.Abs(clientCertFile)
				if err != nil {
					return fmt.Errorf("resolve --cert path: %w", err)
				}
				keyAbs, err := filepath.Abs(clientKeyFile)
				if err != nil {
					return fmt.Errorf("resolve --key path: %w", err)
				}
				if err := config.SaveGlobal(config.Global{
					ServerURL:      serverURL,
					TLSSkipVerify:  insecure,
					CACertPath:     caCertFile,
					ClientCertPath: certAbs,
					ClientKeyPath:  keyAbs,
				}); err != nil {
					return fmt.Errorf("save config: %w", err)
				}
				fmt.Println("Certificate auth configured.")
				return nil
			}

			email := promptLine("Email: ")
			password, err := promptPassword("Password: ")
			if err != nil {
				return err
			}

			var resp struct {
				Token string `json:"token"`
			}
			err = client.NoAuth(serverURL, "POST", "/api/v1/auth/login",
				map[string]any{"email": email, "password": password, "name": loginSessionName()},
				&resp,
				insecure,
				caCert,
			)
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			if err := config.SaveGlobal(config.Global{
				ServerURL:     serverURL,
				Token:         resp.Token,
				TLSSkipVerify: insecure,
				CACertPath:    caCertFile,
			}); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Println("Logged in successfully.")
			return nil
		},
	}
	cmd.Flags().StringVar(&serverURL, "server", "", "Vault server URL (e.g. https://vault.example.com)")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "Skip TLS certificate verification (dev only)")
	cmd.Flags().StringVar(&caCertFile, "cacert", "", "Path to CA certificate PEM for TLS verification")
	cmd.Flags().StringVar(&clientCertFile, "cert", "", "Path to client certificate PEM for principal auth")
	cmd.Flags().StringVar(&clientKeyFile, "key", "", "Path to client key PEM for principal auth")
	return cmd
}

func NewSignupCmd() *cobra.Command {
	var serverURL string
	var insecure bool
	var caCertFile string

	cmd := &cobra.Command{
		Use:   "signup",
		Short: "Create a new account on the Vault server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverURL == "" {
				serverURL = promptLine("Server URL: ")
			}
			serverURL = strings.TrimRight(serverURL, "/")

			var caCert []byte
			if caCertFile != "" {
				abs, err := filepath.Abs(caCertFile)
				if err != nil {
					return fmt.Errorf("resolve --cacert path: %w", err)
				}
				caCertFile = abs
				caCert, err = os.ReadFile(caCertFile)
				if err != nil {
					return fmt.Errorf("read --cacert: %w", err)
				}
			}

			email := promptLine("Email: ")
			password, err := promptPassword("Password: ")
			if err != nil {
				return err
			}

			var resp struct {
				Token string `json:"token"`
			}
			err = client.NoAuth(serverURL, "POST", "/api/v1/auth/signup",
				map[string]any{"email": email, "password": password, "name": loginSessionName()},
				&resp,
				insecure,
				caCert,
			)
			if err != nil {
				return fmt.Errorf("signup failed: %w", err)
			}

			if err := config.SaveGlobal(config.Global{
				ServerURL:     serverURL,
				Token:         resp.Token,
				TLSSkipVerify: insecure,
				CACertPath:    caCertFile,
			}); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Println("Account created and logged in.")
			return nil
		},
	}
	cmd.Flags().StringVar(&serverURL, "server", "", "Vault server URL")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "Skip TLS certificate verification (dev only)")
	cmd.Flags().StringVar(&caCertFile, "cacert", "", "Path to CA certificate PEM for TLS verification")
	return cmd
}

func NewLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the current session token",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token, g.TLSSkipVerify, g.CACertPEM(), g.ClientCert())
			if err := c.Delete("/api/v1/auth/logout"); err != nil {
				return fmt.Errorf("logout: %w", err)
			}
			if err := config.SaveGlobal(config.Global{ServerURL: g.ServerURL}); err != nil {
				return err
			}
			fmt.Println("Logged out.")
			return nil
		},
	}
}

// ── prompt helpers ────────────────────────────────────────────────────────────

func promptLine(prompt string) string {
	fmt.Print(prompt)
	var s string
	fmt.Scanln(&s)
	return strings.TrimSpace(s)
}

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(b), nil
}
