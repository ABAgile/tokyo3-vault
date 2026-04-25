package main

import (
	"fmt"
	"os"

	"github.com/abagile/tokyo3-vault/cmd/vault/commands"
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
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
