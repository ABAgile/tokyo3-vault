package commands

import (
	"fmt"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

type tokenListItem struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Kind      string  `json:"kind"`
	ProjectID *string `json:"project_id,omitempty"`
	EnvID     *string `json:"env_id,omitempty"`
	ReadOnly  bool    `json:"read_only"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	CreatedAt string  `json:"created_at"`
}

type createTokenResp struct {
	Token string        `json:"token"`
	Meta  tokenListItem `json:"meta"`
}

func NewTokensCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "Manage machine tokens",
	}
	cmd.AddCommand(
		newTokensListCmd(),
		newTokensCreateCmd(),
		newTokensDeleteCmd(),
	)
	return cmd
}

func newTokensListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tokens for the current user",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token, g.TLSSkipVerify, g.CACertPEM(), g.ClientCert())
			var tokens []tokenListItem
			if err := c.Get("/api/v1/tokens", &tokens); err != nil {
				return err
			}
			if len(tokens) == 0 {
				fmt.Println("No tokens found.")
				return nil
			}
			fmt.Printf("%-36s  %-7s  %-20s  %-5s  %-25s  %s\n", "ID", "KIND", "NAME", "R/O", "EXPIRES", "CREATED")
			for _, t := range tokens {
				ro := "no"
				if t.ReadOnly {
					ro = "yes"
				}
				expires := "-"
				if t.ExpiresAt != nil {
					expires = fmtTime(*t.ExpiresAt)
				}
				fmt.Printf("%-36s  %-7s  %-20s  %-5s  %-25s  %s\n", t.ID, t.Kind, t.Name, ro, expires, fmtTime(t.CreatedAt))
			}
			return nil
		},
	}
}

func newTokensCreateCmd() *cobra.Command {
	var project, env, expiresIn string
	var readOnly bool
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a machine token (optionally scoped to a project+env)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token, g.TLSSkipVerify, g.CACertPEM(), g.ClientCert())
			body := map[string]any{
				"name":       args[0],
				"project":    project,
				"env":        env,
				"read_only":  readOnly,
				"expires_in": expiresIn,
			}
			var resp createTokenResp
			if err := c.Post("/api/v1/tokens", body, &resp); err != nil {
				return err
			}
			fmt.Printf("Token created. Copy it now — it will not be shown again:\n\n  %s\n\n", resp.Token)
			fmt.Printf("ID: %s  Name: %s\n", resp.Meta.ID, resp.Meta.Name)
			if resp.Meta.ProjectID != nil {
				fmt.Printf("Scoped to project: %s\n", *resp.Meta.ProjectID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "Scope to a project (slug, e.g. my-app)")
	cmd.Flags().StringVar(&env, "env", "", "Scope to an environment slug within --project (e.g. production)")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "Create a read-only token (cannot write secrets)")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Token TTL as a Go duration, e.g. 24h, 168h, 30m")
	return cmd
}

func newTokensDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Revoke a machine token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token, g.TLSSkipVerify, g.CACertPEM(), g.ClientCert())
			if err := c.Delete("/api/v1/tokens/" + args[0]); err != nil {
				return err
			}
			fmt.Printf("Token %s revoked.\n", args[0])
			return nil
		},
	}
}
