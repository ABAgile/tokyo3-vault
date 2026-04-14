package commands

import (
	"fmt"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

type envItem struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"created_at"`
}

func NewEnvsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "envs",
		Short: "Manage environments",
	}
	cmd.AddCommand(
		newEnvsListCmd(),
		newEnvsCreateCmd(),
		newEnvsDeleteCmd(),
	)
	return cmd
}

func newEnvsListCmd() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List environments for a project",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			project, err = resolveProject(project)
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			var envs []envItem
			if err := c.Get("/api/v1/projects/"+project+"/envs", &envs); err != nil {
				return err
			}
			if len(envs) == 0 {
				fmt.Println("No environments found.")
				return nil
			}
			fmt.Printf("%-20s  %-20s  %s\n", "NAME", "SLUG", "CREATED")
			for _, e := range envs {
				fmt.Printf("%-20s  %-20s  %s\n", e.Name, e.Slug, fmtTime(e.CreatedAt))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "Project slug (default: from .vault.toml)")
	return cmd
}

func newEnvsCreateCmd() *cobra.Command {
	var project, slug string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			project, err = resolveProject(project)
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			body := map[string]string{"name": args[0], "slug": slug}
			var e envItem
			if err := c.Post("/api/v1/projects/"+project+"/envs", body, &e); err != nil {
				return err
			}
			fmt.Printf("Created environment %q (slug: %s)\n", e.Name, e.Slug)
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "Project slug")
	cmd.Flags().StringVar(&slug, "slug", "", "Custom slug")
	return cmd
}

func newEnvsDeleteCmd() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "delete <env-slug>",
		Short: "Delete an environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			envSlug := args[0]
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			project, err = resolveProject(project)
			if err != nil {
				return err
			}
			fmt.Printf("This will permanently delete environment %q and all its secrets.\n", envSlug)
			confirm := promptLine("Type the environment slug to confirm: ")
			if confirm != envSlug {
				return fmt.Errorf("confirmation did not match — aborted")
			}
			c := client.New(g.ServerURL, g.Token)
			if err := c.Delete("/api/v1/projects/" + project + "/envs/" + envSlug); err != nil {
				return err
			}
			fmt.Printf("Deleted environment %q.\n", envSlug)
			if r, ok := config.LoadRepoLocal(); ok && r.Project == project && r.Env == envSlug {
				_ = config.RemoveRepo()
				fmt.Println("Unlinked — .vault.toml removed (environment deleted).")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "Project slug")
	return cmd
}

// resolveProject returns the provided slug or falls back to .vault.toml.
func resolveProject(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	r, err := config.LoadRepo()
	if err != nil {
		return "", err
	}
	if r.Project == "" {
		return "", fmt.Errorf("--project flag required (or run 'vault projects link' in this directory)")
	}
	return r.Project, nil
}
