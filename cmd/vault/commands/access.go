package commands

import (
	"fmt"
	"net/url"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

type accessMemberEntry struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

type accessTokenEntry struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	OwnerEmail string  `json:"owner_email"`
	Scope      string  `json:"scope"`
	ReadOnly   bool    `json:"read_only"`
	ExpiresAt  *string `json:"expires_at"`
}

type accessPrincipalEntry struct {
	ID          string  `json:"id"`
	SPIFFEID    string  `json:"spiffe_id"`
	Description string  `json:"description"`
	OwnerEmail  string  `json:"owner_email"`
	Scope       string  `json:"scope"`
	ReadOnly    bool    `json:"read_only"`
	ExpiresAt   *string `json:"expires_at"`
}

type accessResponse struct {
	Members    []accessMemberEntry    `json:"members"`
	Tokens     []accessTokenEntry     `json:"tokens"`
	Principals []accessPrincipalEntry `json:"principals"`
}

func NewAccessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Inspect access to a project environment",
	}
	cmd.AddCommand(newAccessListCmd())
	return cmd
}

func newAccessListCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all identities that can access a project environment",
		Long: `Lists every identity with effective access to the specified project+environment:

  • Project members  — users with a project role (owner/editor/viewer)
  • Machine tokens   — scoped to this env, scoped to the project (any env),
                       or unscoped tokens owned by project members
  • SPIFFE principals — same scoping as tokens; expired principals are excluded

The SCOPE column shows how the token or principal was scoped:
  env       — explicitly scoped to this exact project+environment
  project   — scoped to the project, any environment
  unscoped  — no project/env restriction; access comes from the owner's membership`,
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			project, env, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}

			c := client.New(g.ServerURL, g.Token)
			path := fmt.Sprintf("/api/v1/projects/%s/envs/%s/access",
				url.PathEscape(project), url.PathEscape(env))

			var resp accessResponse
			if err := c.Get(path, &resp); err != nil {
				return err
			}

			total := len(resp.Members) + len(resp.Tokens) + len(resp.Principals)
			if total == 0 {
				fmt.Println("No identities found.")
				return nil
			}

			fmt.Printf("%-12s  %-42s  %-10s  %-12s  %-24s  %s\n",
				"TYPE", "IDENTITY", "SCOPE", "ACCESS", "OWNER", "EXPIRES")

			for _, m := range resp.Members {
				access := roleAccess(m.Role)
				fmt.Printf("%-12s  %-42s  %-10s  %-12s  %-24s  %s\n",
					"user", m.Email, "project", access, "—", "—")
			}

			for _, t := range resp.Tokens {
				access := "read-write"
				if t.ReadOnly {
					access = "read-only"
				}
				expires := "—"
				if t.ExpiresAt != nil {
					expires = fmtTime(*t.ExpiresAt)
				}
				fmt.Printf("%-12s  %-42s  %-10s  %-12s  %-24s  %s\n",
					"token", t.Name, t.Scope, access, t.OwnerEmail, expires)
			}

			for _, p := range resp.Principals {
				access := "read-write"
				if p.ReadOnly {
					access = "read-only"
				}
				expires := "—"
				if p.ExpiresAt != nil {
					expires = fmtTime(*p.ExpiresAt)
				}
				identity := p.SPIFFEID
				if p.Description != "" {
					identity = fmt.Sprintf("%s (%s)", p.SPIFFEID, p.Description)
				}
				fmt.Printf("%-12s  %-42s  %-10s  %-12s  %-24s  %s\n",
					"principal", identity, p.Scope, access, p.OwnerEmail, expires)
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "Project slug")
	cmd.Flags().StringVar(&env, "env", "", "Environment slug")
	return cmd
}

func roleAccess(role string) string {
	if role == "viewer" {
		return "read-only"
	}
	return "read-write"
}
