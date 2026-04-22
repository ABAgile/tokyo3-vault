package commands

import (
	"fmt"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

// ── response types ────────────────────────────────────────────────────────────

type certPrincipalResp struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	SPIFFEID    string  `json:"spiffe_id"`
	ProjectID   *string `json:"project_id,omitempty"`
	EnvID       *string `json:"env_id,omitempty"`
	ReadOnly    bool    `json:"read_only"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// ── top-level command ─────────────────────────────────────────────────────────

func NewPrincipalsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "principals",
		Short: "Manage SPIFFE/mTLS certificate principals",
		Long: `Register SPIFFE IDs that can authenticate to vault via mTLS client certificates.

When the vault server is configured with VAULT_TLS_CLIENT_CA, any client presenting
a certificate signed by that CA whose SPIFFE URI SAN matches a registered principal
is authorized — no bearer token required.

Example (Teleport / tbot):
  vault principals register "myapp-server" \
    --spiffe-id spiffe://cluster.local/ns/myapp/sa/server \
    --project myapp --env production`,
	}
	cmd.AddCommand(
		newPrincipalsRegisterCmd(),
		newPrincipalsListCmd(),
		newPrincipalsRevokeCmd(),
	)
	return cmd
}

// ── register ──────────────────────────────────────────────────────────────────

func newPrincipalsRegisterCmd() *cobra.Command {
	var project, env, spiffeID, expiresIn string
	var readOnly bool

	cmd := &cobra.Command{
		Use:   "register <description>",
		Short: "Register a SPIFFE ID as a vault principal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			if spiffeID == "" {
				return fmt.Errorf("--spiffe-id is required")
			}
			body := map[string]any{
				"description": args[0],
				"spiffe_id":   spiffeID,
				"read_only":   readOnly,
			}
			if project != "" {
				body["project"] = project
			}
			if env != "" {
				body["env"] = env
			}
			if expiresIn != "" {
				body["expires_in"] = expiresIn
			}
			c := client.New(g.ServerURL, g.Token)
			var resp certPrincipalResp
			if err := c.Post("/api/v1/cert-principals", body, &resp); err != nil {
				return err
			}
			fmt.Printf("id:          %s\n", resp.ID)
			fmt.Printf("spiffe_id:   %s\n", resp.SPIFFEID)
			fmt.Printf("description: %s\n", resp.Description)
			if resp.ProjectID != nil {
				fmt.Printf("project_id:  %s\n", *resp.ProjectID)
			}
			if resp.EnvID != nil {
				fmt.Printf("env_id:      %s\n", *resp.EnvID)
			}
			fmt.Printf("read_only:   %v\n", resp.ReadOnly)
			if resp.ExpiresAt != nil {
				fmt.Printf("expires_at:  %s\n", fmtTime(*resp.ExpiresAt))
			}
			fmt.Printf("created_at:  %s\n", fmtTime(resp.CreatedAt))
			return nil
		},
	}
	cmd.Flags().StringVar(&spiffeID, "spiffe-id", "", "SPIFFE URI SAN to match (required), e.g. spiffe://cluster.local/ns/myapp/sa/server")
	cmd.Flags().StringVar(&project, "project", "", "Scope to a project slug")
	cmd.Flags().StringVar(&env, "env", "", "Scope to an environment slug (requires --project)")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "Restrict to read-only operations")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Mapping expiry as a Go duration, e.g. 8760h (1 year)")
	return cmd
}

// ── list ──────────────────────────────────────────────────────────────────────

func newPrincipalsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered SPIFFE principals",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			var principals []certPrincipalResp
			if err := c.Get("/api/v1/cert-principals", &principals); err != nil {
				return err
			}
			if len(principals) == 0 {
				fmt.Println("No principals registered.")
				return nil
			}
			fmt.Printf("%-36s  %-50s  %-8s  %s\n", "ID", "SPIFFE ID", "READ_ONLY", "CREATED")
			for _, p := range principals {
				fmt.Printf("%-36s  %-50s  %-8v  %s\n",
					p.ID, p.SPIFFEID, p.ReadOnly, fmtTime(p.CreatedAt))
			}
			return nil
		},
	}
}

// ── revoke ────────────────────────────────────────────────────────────────────

func newPrincipalsRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Remove a registered SPIFFE principal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			if err := c.Delete("/api/v1/cert-principals/" + args[0]); err != nil {
				return err
			}
			fmt.Printf("Principal %s revoked.\n", args[0])
			return nil
		},
	}
}
