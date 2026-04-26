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
	SPIFFEID    *string `json:"spiffe_id,omitempty"`
	EmailSAN    *string `json:"email_san,omitempty"`
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
		Short: "Manage mTLS certificate principals",
		Long: `Register certificate identities that can authenticate to vault via mTLS.

Two identifier types are supported:

  --spiffe-id  URI SAN with spiffe:// scheme (SPIFFE workload identity, e.g. from Teleport tbot)
  --email-san  Email SAN (rfc822Name) for human users with corporate PKI certificates

When the vault server is configured with VAULT_TLS_CLIENT_CA, any client presenting
a certificate signed by that CA whose SAN matches a registered principal is authorized
without a bearer token. SPIFFE URI SANs are checked before email SANs.

Examples:
  vault principals register "myapp-server" \
    --spiffe-id spiffe://cluster.local/ns/myapp/sa/server \
    --project myapp --env production

  vault principals register "alice workstation" \
    --email-san alice@corp.example.com \
    --project myapp`,
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
	var project, env, spiffeID, emailSAN, expiresIn string
	var readOnly bool

	cmd := &cobra.Command{
		Use:   "register <description>",
		Short: "Register a certificate principal (SPIFFE ID or email SAN)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			if spiffeID == "" && emailSAN == "" {
				return fmt.Errorf("one of --spiffe-id or --email-san is required")
			}
			if spiffeID != "" && emailSAN != "" {
				return fmt.Errorf("only one of --spiffe-id or --email-san may be set")
			}
			body := buildCertPrincipalBody(args[0], spiffeID, emailSAN, project, env, expiresIn, readOnly)
			c := client.New(g.ServerURL, g.Token)
			var resp certPrincipalResp
			if err := c.Post("/api/v1/cert-principals", body, &resp); err != nil {
				return err
			}
			printCertPrincipal(resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&spiffeID, "spiffe-id", "", "SPIFFE URI SAN, e.g. spiffe://cluster.local/ns/myapp/sa/server")
	cmd.Flags().StringVar(&emailSAN, "email-san", "", "Email SAN (rfc822Name), e.g. alice@corp.example.com")
	cmd.Flags().StringVar(&project, "project", "", "Scope to a project slug")
	cmd.Flags().StringVar(&env, "env", "", "Scope to an environment slug (requires --project)")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "Restrict to read-only operations")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Mapping expiry as a Go duration, e.g. 8760h (1 year)")
	return cmd
}

func buildCertPrincipalBody(description, spiffeID, emailSAN, project, env, expiresIn string, readOnly bool) map[string]any {
	body := map[string]any{"description": description, "read_only": readOnly}
	if spiffeID != "" {
		body["spiffe_id"] = spiffeID
	}
	if emailSAN != "" {
		body["email_san"] = emailSAN
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
	return body
}

func printCertPrincipal(resp certPrincipalResp) {
	fmt.Printf("id:          %s\n", resp.ID)
	if resp.SPIFFEID != nil {
		fmt.Printf("spiffe_id:   %s\n", *resp.SPIFFEID)
	}
	if resp.EmailSAN != nil {
		fmt.Printf("email_san:   %s\n", *resp.EmailSAN)
	}
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
}

// ── list ──────────────────────────────────────────────────────────────────────

func newPrincipalsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered cert principals",
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
			fmt.Printf("%-36s  %-8s  %-50s  %s\n", "ID", "TYPE", "IDENTIFIER", "CREATED")
			for _, p := range principals {
				typ, id := "spiffe", ""
				if p.SPIFFEID != nil {
					id = *p.SPIFFEID
				} else if p.EmailSAN != nil {
					typ, id = "email", *p.EmailSAN
				}
				fmt.Printf("%-36s  %-8s  %-50s  %s\n", p.ID, typ, id, fmtTime(p.CreatedAt))
			}
			return nil
		},
	}
}

// ── revoke ────────────────────────────────────────────────────────────────────

func newPrincipalsRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Remove a registered cert principal",
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
