package commands

import (
	"fmt"
	"os"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

// ── response types ────────────────────────────────────────────────────────────

type dynamicBackendResp struct {
	Slug       string `json:"slug"`
	ProjectID  string `json:"project_id"`
	EnvID      string `json:"env_id"`
	Type       string `json:"type"`
	DefaultTTL int    `json:"default_ttl"`
	MaxTTL     int    `json:"max_ttl"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type dynamicRoleResp struct {
	Name           string `json:"name"`
	CreationTmpl   string `json:"creation_tmpl"`
	RevocationTmpl string `json:"revocation_tmpl"`
	TTL            *int   `json:"ttl,omitempty"`
	CreatedAt      string `json:"created_at"`
}

type issuedCredsResp struct {
	LeaseID   string `json:"lease_id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ExpiresAt string `json:"expires_at"`
}

type leaseResp struct {
	ID        string  `json:"id"`
	RoleName  string  `json:"role_name"`
	Username  string  `json:"username"`
	ExpiresAt string  `json:"expires_at"`
	RevokedAt *string `json:"revoked_at,omitempty"`
	CreatedAt string  `json:"created_at"`
}

// ── top-level command tree ────────────────────────────────────────────────────

func NewDynamicCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dynamic",
		Short: "Manage dynamic secret backends",
	}
	cmd.AddCommand(
		newDynBackendCmd(),
		newDynRolesCmd(),
		newDynIssueCmd(),
		newDynLeasesCmd(),
	)
	return cmd
}

// ── backend subcommands ───────────────────────────────────────────────────────

func newDynBackendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backend",
		Short: "Configure dynamic secret backends",
	}
	cmd.AddCommand(
		newDynBackendSetCmd(),
		newDynBackendGetCmd(),
		newDynBackendDeleteCmd(),
	)
	return cmd
}

func newDynBackendSetCmd() *cobra.Command {
	var project, env, backendType, dsn string
	var defaultTTL, maxTTL int
	var clientCertFile, clientKeyFile, caCertFile string
	cmd := &cobra.Command{
		Use:   "set <slug>",
		Short: "Configure (or update) a dynamic backend for a project+env",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			project, envSlug, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}
			if backendType == "" {
				return fmt.Errorf("--type is required")
			}
			if dsn == "" {
				return fmt.Errorf("--dsn is required")
			}
			if (clientCertFile == "") != (clientKeyFile == "") {
				return fmt.Errorf("--client-cert-file and --client-key-file must both be provided")
			}

			cfg := map[string]any{"dsn": dsn}

			if clientCertFile != "" {
				certPEM, err := os.ReadFile(clientCertFile)
				if err != nil {
					return fmt.Errorf("read --client-cert-file: %w", err)
				}
				keyPEM, err := os.ReadFile(clientKeyFile)
				if err != nil {
					return fmt.Errorf("read --client-key-file: %w", err)
				}
				cfg["client_cert"] = string(certPEM)
				cfg["client_key"] = string(keyPEM)
			}
			if caCertFile != "" {
				caPEM, err := os.ReadFile(caCertFile)
				if err != nil {
					return fmt.Errorf("read --ca-cert-file: %w", err)
				}
				cfg["ca_cert"] = string(caPEM)
			}

			body := map[string]any{
				"type":        backendType,
				"config":      cfg,
				"default_ttl": defaultTTL,
				"max_ttl":     maxTTL,
			}
			c := client.New(g.ServerURL, g.Token)
			var resp dynamicBackendResp
			if err := c.Put(dynPath(project, envSlug, args[0]), body, &resp); err != nil {
				return err
			}
			fmt.Printf("backend %q (%s) configured for %s/%s\n", resp.Slug, resp.Type, resp.ProjectID, resp.EnvID)
			fmt.Printf("  default_ttl: %ds  max_ttl: %ds\n", resp.DefaultTTL, resp.MaxTTL)
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().StringVar(&backendType, "type", "", "Backend type (required): postgresql")
	cmd.Flags().StringVar(&dsn, "dsn", "", "Admin DSN (required)")
	cmd.Flags().IntVar(&defaultTTL, "default-ttl", 0, "Default credential TTL in seconds (0 = server default 3600)")
	cmd.Flags().IntVar(&maxTTL, "max-ttl", 0, "Maximum credential TTL in seconds (0 = server default 86400)")
	cmd.Flags().StringVar(&clientCertFile, "client-cert-file", "", "Path to client certificate PEM for vault_admin cert auth (optional)")
	cmd.Flags().StringVar(&clientKeyFile, "client-key-file", "", "Path to client key PEM (required when --client-cert-file is set)")
	cmd.Flags().StringVar(&caCertFile, "ca-cert-file", "", "Path to CA certificate PEM for server verification (optional)")
	return cmd
}

func newDynBackendGetCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "get <slug>",
		Short: "Show a dynamic backend configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			project, envSlug, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			var resp dynamicBackendResp
			if err := c.Get(dynPath(project, envSlug, args[0]), &resp); err != nil {
				return err
			}
			fmt.Printf("slug:        %s\n", resp.Slug)
			fmt.Printf("type:        %s\n", resp.Type)
			fmt.Printf("project:     %s\n", resp.ProjectID)
			fmt.Printf("env:         %s\n", resp.EnvID)
			fmt.Printf("default_ttl: %ds\n", resp.DefaultTTL)
			fmt.Printf("max_ttl:     %ds\n", resp.MaxTTL)
			fmt.Printf("created_at:  %s\n", fmtTime(resp.CreatedAt))
			fmt.Printf("updated_at:  %s\n", fmtTime(resp.UpdatedAt))
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func newDynBackendDeleteCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "delete <slug>",
		Short: "Remove a dynamic backend configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			var err2 error
			project, envSlug, err2 = resolveProjectEnv(project, env)
			if err2 != nil {
				return err2
			}
			c := client.New(g.ServerURL, g.Token)
			if err := c.Delete(dynPath(project, envSlug, args[0])); err != nil {
				return err
			}
			fmt.Printf("Backend %q deleted.\n", args[0])
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

// ── roles subcommands ─────────────────────────────────────────────────────────

func newDynRolesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "Manage dynamic role templates",
	}
	cmd.AddCommand(
		newDynRoleSetCmd(),
		newDynRoleListCmd(),
		newDynRoleDeleteCmd(),
	)
	return cmd
}

func newDynRoleSetCmd() *cobra.Command {
	var project, env, creationTmpl, revocationTmpl string
	var ttl int
	cmd := &cobra.Command{
		Use:   "set <backend-slug> <role-name>",
		Short: "Create or update a dynamic role template",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			project, envSlug, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}
			if creationTmpl == "" || revocationTmpl == "" {
				return fmt.Errorf("--creation-tmpl and --revocation-tmpl are required")
			}
			body := map[string]any{
				"creation_tmpl":   creationTmpl,
				"revocation_tmpl": revocationTmpl,
			}
			if ttl > 0 {
				body["ttl"] = ttl
			}
			c := client.New(g.ServerURL, g.Token)
			var resp dynamicRoleResp
			if err := c.Put(dynRolePath(project, envSlug, args[0], args[1]), body, &resp); err != nil {
				return err
			}
			fmt.Printf("Role %q saved for backend %q.\n", resp.Name, args[0])
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().StringVar(&creationTmpl, "creation-tmpl", "", "SQL template to create the credential (required)")
	cmd.Flags().StringVar(&revocationTmpl, "revocation-tmpl", "", "SQL template to revoke the credential (required)")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "Role-specific TTL in seconds (0 = use backend default)")
	return cmd
}

func newDynRoleListCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "list <backend-slug>",
		Short: "List all role templates for a backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			project, envSlug, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			var roles []dynamicRoleResp
			if err := c.Get(dynPath(project, envSlug, args[0])+"/roles", &roles); err != nil {
				return err
			}
			if len(roles) == 0 {
				fmt.Println("No roles defined.")
				return nil
			}
			fmt.Printf("%-20s  %-8s  %s\n", "NAME", "TTL", "CREATED")
			for _, r := range roles {
				ttl := "default"
				if r.TTL != nil {
					ttl = fmt.Sprintf("%ds", *r.TTL)
				}
				fmt.Printf("%-20s  %-8s  %s\n", r.Name, ttl, fmtTime(r.CreatedAt))
			}
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func newDynRoleDeleteCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "delete <backend-slug> <role-name>",
		Short: "Delete a role template",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			var err2 error
			project, envSlug, err2 = resolveProjectEnv(project, env)
			if err2 != nil {
				return err2
			}
			c := client.New(g.ServerURL, g.Token)
			if err := c.Delete(dynRolePath(project, envSlug, args[0], args[1])); err != nil {
				return err
			}
			fmt.Printf("Role %q deleted from backend %q.\n", args[1], args[0])
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

// ── issue credentials ─────────────────────────────────────────────────────────

func newDynIssueCmd() *cobra.Command {
	var project, env string
	var ttl int
	cmd := &cobra.Command{
		Use:   "issue <backend-slug> <role-name>",
		Short: "Issue ephemeral credentials for a role",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			project, envSlug, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}
			body := map[string]any{"ttl": ttl}
			c := client.New(g.ServerURL, g.Token)
			var resp issuedCredsResp
			if err := c.Post(dynCredsPath(project, envSlug, args[0], args[1]), body, &resp); err != nil {
				return err
			}
			fmt.Printf("lease_id:   %s\n", resp.LeaseID)
			fmt.Printf("username:   %s\n", resp.Username)
			fmt.Printf("password:   %s\n", resp.Password)
			fmt.Printf("expires_at: %s\n", fmtTime(resp.ExpiresAt))
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().IntVar(&ttl, "ttl", 0, "Credential TTL in seconds (0 = use role/backend default)")
	return cmd
}

// ── leases subcommands ────────────────────────────────────────────────────────

func newDynLeasesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "leases",
		Short: "Manage dynamic credential leases",
	}
	cmd.AddCommand(
		newDynLeasesListCmd(),
		newDynLeaseRevokeCmd(),
	)
	return cmd
}

func newDynLeasesListCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all leases for a project+env",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			project, envSlug, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			var leases []leaseResp
			if err := c.Get(dynLeasesPath(project, envSlug), &leases); err != nil {
				return err
			}
			if len(leases) == 0 {
				fmt.Println("No leases found.")
				return nil
			}
			fmt.Printf("%-36s  %-16s  %-20s  %-20s  %s\n", "ID", "ROLE", "USERNAME", "EXPIRES", "REVOKED")
			for _, l := range leases {
				revoked := "-"
				if l.RevokedAt != nil {
					revoked = fmtTime(*l.RevokedAt)
				}
				fmt.Printf("%-36s  %-16s  %-20s  %-20s  %s\n",
					l.ID, l.RoleName, l.Username, fmtTime(l.ExpiresAt), revoked)
			}
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func newDynLeaseRevokeCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "revoke <lease-id>",
		Short: "Immediately revoke a lease and drop the credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			var err2 error
			project, envSlug, err2 = resolveProjectEnv(project, env)
			if err2 != nil {
				return err2
			}
			c := client.New(g.ServerURL, g.Token)
			if err := c.Delete(dynLeasesPath(project, envSlug) + "/" + args[0]); err != nil {
				return err
			}
			fmt.Printf("Lease %s revoked.\n", args[0])
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

// ── path helpers ──────────────────────────────────────────────────────────────

func dynPath(project, env, backendName string) string {
	return fmt.Sprintf("/api/v1/projects/%s/envs/%s/dynamic/%s", project, env, backendName)
}

func dynRolePath(project, env, backendName, role string) string {
	return dynPath(project, env, backendName) + "/roles/" + role
}

func dynCredsPath(project, env, backendName, role string) string {
	return dynPath(project, env, backendName) + "/" + role + "/creds"
}

func dynLeasesPath(project, env string) string {
	return fmt.Sprintf("/api/v1/projects/%s/envs/%s/dynamic/leases", project, env)
}
