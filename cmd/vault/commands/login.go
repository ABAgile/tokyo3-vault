package commands

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func NewLoginCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the Vault server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverURL == "" {
				g, _ := config.LoadGlobal()
				serverURL = g.ServerURL
			}
			if serverURL == "" {
				serverURL = promptLine("Server URL: ")
			}
			serverURL = strings.TrimRight(serverURL, "/")

			email := promptLine("Email: ")
			password, err := promptPassword("Password: ")
			if err != nil {
				return err
			}

			var resp struct {
				Token string `json:"token"`
			}
			err = client.NoAuth(serverURL, "POST", "/api/v1/auth/login",
				map[string]string{"email": email, "password": password},
				&resp,
			)
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			if err := config.SaveGlobal(config.Global{
				ServerURL: serverURL,
				Token:     resp.Token,
			}); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Println("Logged in successfully.")
			return nil
		},
	}
	cmd.Flags().StringVar(&serverURL, "server", "", "Vault server URL (e.g. https://vault.example.com)")
	return cmd
}

func NewSignupCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "signup",
		Short: "Create a new account on the Vault server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverURL == "" {
				serverURL = promptLine("Server URL: ")
			}
			serverURL = strings.TrimRight(serverURL, "/")

			email := promptLine("Email: ")
			password, err := promptPassword("Password: ")
			if err != nil {
				return err
			}

			var resp struct {
				Token string `json:"token"`
			}
			err = client.NoAuth(serverURL, "POST", "/api/v1/auth/signup",
				map[string]string{"email": email, "password": password},
				&resp,
			)
			if err != nil {
				return fmt.Errorf("signup failed: %w", err)
			}

			if err := config.SaveGlobal(config.Global{
				ServerURL: serverURL,
				Token:     resp.Token,
			}); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Println("Account created and logged in.")
			return nil
		},
	}
	cmd.Flags().StringVar(&serverURL, "server", "", "Vault server URL")
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
			c := client.New(g.ServerURL, g.Token)
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
