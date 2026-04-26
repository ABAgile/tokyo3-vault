package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

type secretMeta struct {
	Key       string `json:"key"`
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
}

type secretFull struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
}

type versionItem struct {
	ID        string  `json:"id"`
	Version   int     `json:"version"`
	CreatedAt string  `json:"created_at"`
	CreatedBy *string `json:"created_by,omitempty"`
}

func NewSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage secrets",
	}
	cmd.AddCommand(
		newSecretsListCmd(),
		newSecretsGetCmd(),
		newSecretsSetCmd(),
		newSecretsDeleteCmd(),
		newSecretsVersionsCmd(),
		newSecretsRollbackCmd(),
		newSecretsImportCmd(),
		newSecretsUploadCmd(),
		newSecretsDownloadCmd(),
	)
	return cmd
}

func newSecretsListCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets (keys only) for a project+env",
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
			var secrets []secretMeta
			if err := c.Get(secretsPath(project, env), &secrets); err != nil {
				return err
			}
			if len(secrets) == 0 {
				fmt.Println("No secrets found.")
				return nil
			}
			fmt.Printf("%-30s  %-8s  %s\n", "KEY", "VERSION", "UPDATED")
			for _, s := range secrets {
				fmt.Printf("%-30s  %-8d  %s\n", s.Key, s.Version, fmtTime(s.UpdatedAt))
			}
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func newSecretsGetCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "get <KEY>",
		Short: "Fetch and print a secret's value",
		Args:  cobra.ExactArgs(1),
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
			var s secretFull
			if err := c.Get(secretsPath(project, env)+"/"+args[0], &s); err != nil {
				return err
			}
			fmt.Println(s.Value)
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func newSecretsSetCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "set <KEY> <value>",
		Short: "Create or update a secret",
		Args:  cobra.ExactArgs(2),
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
			var resp versionItem
			err = c.Put(secretsPath(project, env)+"/"+args[0],
				map[string]string{"value": args[1]}, &resp)
			if err != nil {
				return err
			}
			fmt.Printf("Set %s = *** (version %d)\n", args[0], resp.Version)
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func newSecretsDeleteCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "delete <KEY>",
		Short: "Delete a secret (all versions)",
		Args:  cobra.ExactArgs(1),
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
			if err := c.Delete(secretsPath(project, env) + "/" + args[0]); err != nil {
				return err
			}
			fmt.Printf("Deleted secret %s.\n", args[0])
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func newSecretsVersionsCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "versions <KEY>",
		Short: "List all versions of a secret",
		Args:  cobra.ExactArgs(1),
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
			var versions []versionItem
			if err := c.Get(secretsPath(project, env)+"/"+args[0]+"/versions", &versions); err != nil {
				return err
			}
			fmt.Printf("%-5s  %-36s  %s\n", "VER", "ID", "CREATED")
			for _, v := range versions {
				fmt.Printf("%-5d  %-36s  %s\n", v.Version, v.ID, fmtTime(v.CreatedAt))
			}
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func newSecretsRollbackCmd() *cobra.Command {
	var project, env string
	cmd := &cobra.Command{
		Use:   "rollback <KEY> <version-id>",
		Short: "Roll back a secret to a previous version",
		Args:  cobra.ExactArgs(2),
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
			var resp map[string]any
			err = c.Post(
				secretsPath(project, env)+"/"+args[0]+"/rollback",
				map[string]string{"version_id": args[1]},
				&resp,
			)
			if err != nil {
				return err
			}
			fmt.Printf("Rolled back %s to version %v (id: %s)\n", args[0], resp["version"], args[1])
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func newSecretsImportCmd() *cobra.Command {
	var project, env, fromProject, fromEnv string
	var overwrite bool
	cmd := &cobra.Command{
		Use:   "import [KEY...]",
		Short: "Import secrets from another project+environment",
		Long: `Copies secrets from a source project+environment into the current one.
If --from-project is omitted, the current project (from .vault.toml) is used,
making it easy to copy between environments of the same project.
Optionally specify individual keys to import; omit to import all.

Examples:
  vault secrets import --from-env dev                         # same project, from dev
  vault secrets import --from-project myapp --from-env dev    # cross-project import
  vault secrets import --from-env dev DATABASE_URL REDIS_URL  # specific keys only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			project, env, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}
			if fromProject == "" {
				fromProject = project // default to the current project
			}
			if fromEnv == "" {
				return fmt.Errorf("--from-env is required")
			}
			c := client.New(g.ServerURL, g.Token)
			body := map[string]any{
				"from_project": fromProject,
				"from_env":     fromEnv,
				"overwrite":    overwrite,
				"keys":         args,
			}
			var resp map[string]any
			if err := c.Post(secretsPath(project, env)+"/import", body, &resp); err != nil {
				return err
			}
			fmt.Printf("Imported %v secrets, skipped %v (already exist).\n", resp["imported"], resp["skipped"])
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().StringVar(&fromProject, "from-project", "", "Source project slug (default: current project)")
	cmd.Flags().StringVar(&fromEnv, "from-env", "", "Source environment slug (required)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing secrets in destination")
	return cmd
}

func newSecretsUploadCmd() *cobra.Command {
	var project, env string
	var overwrite bool
	cmd := &cobra.Command{
		Use:   "upload [file]",
		Short: "Upload secrets from a .env file into the current project+env",
		Long: `Parses a .env file and stores each key as a secret.
Comments and blank lines preceding a key are preserved and restored on download.
Omit the file argument or pass '-' to read from stdin.

Example:
  vault secrets upload .env
  vault secrets upload .env --overwrite
  cat .env | vault secrets upload -`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			project, env, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}

			var content []byte
			if len(args) == 0 || args[0] == "-" {
				content, err = io.ReadAll(os.Stdin)
			} else {
				content, err = os.ReadFile(args[0])
			}
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}

			path := secretsPath(project, env) + "/envfile"
			if overwrite {
				path += "?overwrite=true"
			}
			c := client.New(g.ServerURL, g.Token)
			var resp map[string]any
			if err := c.PostText(path, string(content), &resp); err != nil {
				return err
			}
			fmt.Printf("Uploaded %v secrets, skipped %v (already exist).\n", resp["uploaded"], resp["skipped"])
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite secrets that already exist")
	return cmd
}

func newSecretsDownloadCmd() *cobra.Command {
	var project, env string
	var force bool
	cmd := &cobra.Command{
		Use:   "download [file]",
		Short: "Download secrets as a .env file from the current project+env",
		Long: `Fetches all secrets and writes them as a .env file, preserving
insertion order and any comments stored with each key.
Omit the file argument or pass '-' to print to stdout.

Example:
  vault secrets download .env
  vault secrets download          # prints to stdout
  vault secrets download - > .env`,
		Args: cobra.MaximumNArgs(1),
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
			content, err := c.GetText(secretsPath(project, env) + "/envfile")
			if err != nil {
				return err
			}

			if len(args) == 0 || args[0] == "-" {
				fmt.Print(content)
				return nil
			}
			if !force {
				if _, statErr := os.Stat(args[0]); statErr == nil {
					return fmt.Errorf("file %s already exists; use --force to overwrite", args[0])
				}
			}
			if err := os.WriteFile(args[0], []byte(content), 0600); err != nil {
				return fmt.Errorf("write file: %w", err)
			}
			fmt.Printf("Written to %s.\n", args[0])
			return nil
		},
	}
	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite the output file if it already exists")
	return cmd
}

// ── helpers ───────────────────────────────────────────────────────────────────

func secretsPath(project, env string) string {
	return fmt.Sprintf("/api/v1/projects/%s/envs/%s/secrets", project, env)
}

func addProjectEnvFlags(cmd *cobra.Command, project, env *string) {
	cmd.Flags().StringVar(project, "project", "", "Project slug (default: from .vault.toml)")
	cmd.Flags().StringVar(env, "env", "", "Environment slug (default: from .vault.toml)")
}

func resolveProjectEnv(projectFlag, envFlag string) (project, env string, err error) {
	r, err := config.LoadRepo()
	if err != nil {
		return "", "", err
	}
	project = projectFlag
	if project == "" {
		project = r.Project
	}
	env = envFlag
	if env == "" {
		env = r.Env
	}
	if project == "" {
		return "", "", fmt.Errorf("--project required (or run 'vault projects link')")
	}
	if env == "" {
		return "", "", fmt.Errorf("--env required (or run 'vault projects link')")
	}
	return project, env, nil
}
