package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

func NewRunCmd() *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Run a command with secrets injected as environment variables",
		Long: `Fetches all secrets for the resolved project+environment and injects
them as environment variables before executing the given command.

The child process inherits the current environment plus the injected secrets.
Secrets overwrite any existing env vars with the same name.

Example:
  vault run -- npm start
  vault run --env prod -- ./bin/server`,
		// Allow flag-like args after --
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("command is required after --")
			}

			g, err := config.MustToken()
			if err != nil {
				return err
			}
			project, env, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}

			// Fetch secrets list (metadata only — no values)
			c := client.New(g.ServerURL, g.Token)
			var metas []secretMeta
			if err := c.Get(secretsPath(project, env), &metas); err != nil {
				return fmt.Errorf("fetch secrets: %w", err)
			}

			// Fetch each secret value.
			// For large secret sets this could be batched; MVP fetches individually.
			injected := make([]string, 0, len(metas))
			for _, m := range metas {
				var s secretFull
				if err := c.Get(secretsPath(project, env)+"/"+m.Key, &s); err != nil {
					return fmt.Errorf("fetch secret %s: %w", m.Key, err)
				}
				injected = append(injected, m.Key+"="+s.Value)
			}

			// Build env: current env, strip vault CLI vars, inject secrets.
			// Stripping ensures VAULT_TOKEN and VAULT_SERVER_URL are never
			// inherited by the child even if they were set to drive this command.
			filtered := make([]string, 0, len(os.Environ()))
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "VAULT_TOKEN=") && !strings.HasPrefix(kv, "VAULT_SERVER_URL=") {
					filtered = append(filtered, kv)
				}
			}
			env := append(filtered, injected...)

			// Resolve the binary path.
			binary, err := exec.LookPath(args[0])
			if err != nil {
				return fmt.Errorf("command not found: %s", args[0])
			}

			// Replace the current process (Unix exec).
			// On Linux/macOS this is clean — the child is the only process.
			return syscall.Exec(binary, args, env)
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

func NewExportCmd() *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print secrets as export KEY=value statements for shell sourcing",
		Long: `Prints all secrets as shell export statements. Useful for:
  eval $(vault export)
  source <(vault export)`,
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
			var metas []secretMeta
			if err := c.Get(secretsPath(project, env), &metas); err != nil {
				return fmt.Errorf("fetch secrets: %w", err)
			}

			for _, m := range metas {
				var s secretFull
				if err := c.Get(secretsPath(project, env)+"/"+m.Key, &s); err != nil {
					return fmt.Errorf("fetch secret %s: %w", m.Key, err)
				}
				// Shell-quote the value to handle special characters.
				fmt.Printf("export %s=%s\n", s.Key, shellQuote(s.Value))
			}
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

// shellQuote wraps v in single quotes, escaping any embedded single quotes.
func shellQuote(v string) string {
	// Replace ' with '\'' (end quote, escaped quote, reopen quote).
	var quoted strings.Builder
	quoted.WriteString("'")
	for _, c := range v {
		if c == '\'' {
			quoted.WriteString(`'\''`)
		} else {
			quoted.WriteString(string(c))
		}
	}
	return quoted.String() + "'"
}
