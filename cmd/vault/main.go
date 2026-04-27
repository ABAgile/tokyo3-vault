package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/commands"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "vault",
		Short: "Vault — minimal self-hosted secret manager",
		Long: `Vault is a minimal secret manager CLI.

Getting started:
  vault login                        Authenticate with the server
  vault projects create myapp        Create a project
  vault envs create dev              Create an environment
  vault projects link myapp --env dev  Link this directory
  vault secrets set DATABASE_URL postgres://...
  vault run -- npm start             Run with secrets injected`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		commands.NewLoginCmd(),
		commands.NewSignupCmd(),
		commands.NewLogoutCmd(),
		commands.NewProjectsCmd(),
		commands.NewEnvsCmd(),
		commands.NewSecretsCmd(),
		commands.NewRunCmd(),
		commands.NewExportCmd(),
		commands.NewTokensCmd(),
		commands.NewKeygenCmd(),
		commands.NewVersionCmd(),
		commands.NewMembersCmd(),
		commands.NewUsersCmd(),
		commands.NewChangePasswordCmd(),
		commands.NewDynamicCmd(),
		commands.NewPrincipalsCmd(),
		commands.NewAccessCmd(),
	)

	if err := root.Execute(); err != nil {
		if errors.Is(err, client.ErrUnauthorized) {
			// Session was revoked (e.g. password change). Wipe the stale token so
			// subsequent commands give "not logged in" instead of repeated 401s.
			if g, loadErr := config.LoadGlobal(); loadErr == nil && g.Token != "" {
				_ = config.SaveGlobal(config.Global{
					ServerURL: g.ServerURL,
					CACert:    g.CACert,
				})
			}
			fmt.Fprintln(os.Stderr, "Error: session expired — run: vault login")
		} else {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		os.Exit(1)
	}
}
