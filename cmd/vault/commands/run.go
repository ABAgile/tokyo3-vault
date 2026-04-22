package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

var dynVarReplacer = strings.NewReplacer("-", "_", ".", "_")

func NewRunCmd() *cobra.Command {
	var project, env string
	var dynamicFlags []string

	cmd := &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Run a command with secrets injected as environment variables",
		Long: `Fetches all secrets for the resolved project+environment and injects
them as environment variables before executing the given command.

Dynamic backends declared in .vault.toml [[dynamic]] blocks (or via --dynamic)
are issued first. Their credentials are available as VAULT_DYN_<NAME>_USERNAME,
VAULT_DYN_<NAME>_PASSWORD, and VAULT_DYN_<NAME>_EXPIRES_AT during static secret
value expansion, then stripped from the final environment.

Static secret values may reference dynamic vars using $VAULT_DYN_<NAME>_USERNAME
syntax — they are expanded before the child process starts.

Example:
  vault run -- npm start
  vault run --env prod -- ./bin/server
  vault run --dynamic primary:readonly -- ./bin/server`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("command is required after --")
			}

			g, err := config.MustToken()
			if err != nil {
				return err
			}
			var envSlug string
			project, envSlug, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}

			// Collect dynamic runs: .vault.toml blocks + --dynamic flags.
			repo, _ := config.LoadRepo()
			dynRuns := append([]config.DynamicRun(nil), repo.Dynamic...)
			for _, f := range dynamicFlags {
				dr, err := parseDynamicFlag(f)
				if err != nil {
					return fmt.Errorf("--dynamic %q: %w", f, err)
				}
				dynRuns = append(dynRuns, dr)
			}

			c := client.New(g.ServerURL, g.Token)

			// Issue dynamic creds first; build prefix-keyed map for expansion.
			dynVars := make(map[string]string)
			for _, dr := range dynRuns {
				var creds issuedCredsResp
				if err := c.Post(dynCredsPath(project, envSlug, dr.Slug, dr.Role),
					map[string]any{"ttl": dr.TTL}, &creds); err != nil {
					return fmt.Errorf("issue dynamic creds %s/%s: %w", dr.Slug, dr.Role, err)
				}
				pfx := dynVarPrefix(dr.Slug)
				dynVars[pfx+"USERNAME"] = creds.Username
				dynVars[pfx+"PASSWORD"] = creds.Password
				dynVars[pfx+"EXPIRES_AT"] = creds.ExpiresAt
			}

			// Fetch static secrets and expand their values against dynVars + OS env.
			var metas []secretMeta
			if err := c.Get(secretsPath(project, envSlug), &metas); err != nil {
				return fmt.Errorf("fetch secrets: %w", err)
			}
			injected := make([]string, 0, len(metas))
			for _, m := range metas {
				var s secretFull
				if err := c.Get(secretsPath(project, envSlug)+"/"+m.Key, &s); err != nil {
					return fmt.Errorf("fetch secret %s: %w", m.Key, err)
				}
				expanded := os.Expand(s.Value, func(key string) string {
					if v, ok := dynVars[key]; ok {
						return v
					}
					return os.Getenv(key)
				})
				injected = append(injected, m.Key+"="+expanded)
			}

			// Build final env: inherit OS env, strip vault CLI and VAULT_DYN_* vars,
			// append dynamic vars (for potential inter-secret references), then static secrets.
			// VAULT_DYN_* are appended temporarily then stripped so the child never sees raw creds.
			filtered := make([]string, 0, len(os.Environ()))
			for _, kv := range os.Environ() {
				if strings.HasPrefix(kv, "VAULT_TOKEN=") ||
					strings.HasPrefix(kv, "VAULT_SERVER_URL=") ||
					strings.HasPrefix(kv, "VAULT_DYN_") {
					continue
				}
				filtered = append(filtered, kv)
			}
			finalEnv := append(filtered, injected...)

			binary, err := exec.LookPath(args[0])
			if err != nil {
				return fmt.Errorf("command not found: %s", args[0])
			}
			return syscall.Exec(binary, args, finalEnv)
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().StringArrayVar(&dynamicFlags, "dynamic", nil, "Issue dynamic creds: slug:role or slug:role:ttl (repeatable)")
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
			var envSlug string
			project, envSlug, err = resolveProjectEnv(project, env)
			if err != nil {
				return err
			}

			c := client.New(g.ServerURL, g.Token)
			var metas []secretMeta
			if err := c.Get(secretsPath(project, envSlug), &metas); err != nil {
				return fmt.Errorf("fetch secrets: %w", err)
			}

			for _, m := range metas {
				var s secretFull
				if err := c.Get(secretsPath(project, envSlug)+"/"+m.Key, &s); err != nil {
					return fmt.Errorf("fetch secret %s: %w", m.Key, err)
				}
				fmt.Printf("export %s=%s\n", s.Key, shellQuote(s.Value))
			}
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

// dynVarPrefix converts a backend slug to its VAULT_DYN_ env var prefix.
// "primary-db" → "VAULT_DYN_PRIMARY_DB_"
func dynVarPrefix(backendName string) string {
	up := strings.ToUpper(dynVarReplacer.Replace(backendName))
	return "VAULT_DYN_" + up + "_"
}

// parseDynamicFlag parses "name:role" or "name:role:ttl" into a DynamicRun.
func parseDynamicFlag(s string) (config.DynamicRun, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return config.DynamicRun{}, fmt.Errorf("format must be slug:role or slug:role:ttl")
	}
	dr := config.DynamicRun{Slug: parts[0], Role: parts[1]}
	if len(parts) == 3 && parts[2] != "" {
		ttl, err := strconv.Atoi(parts[2])
		if err != nil {
			return config.DynamicRun{}, fmt.Errorf("ttl must be an integer")
		}
		dr.TTL = ttl
	}
	return dr, nil
}

// shellQuote wraps v in single quotes, escaping any embedded single quotes.
func shellQuote(v string) string {
	var quoted strings.Builder
	quoted.WriteString("'")
	for _, c := range v {
		if c == '\'' {
			quoted.WriteString(`'\''`)
		} else {
			quoted.WriteRune(c)
		}
	}
	return quoted.String() + "'"
}
