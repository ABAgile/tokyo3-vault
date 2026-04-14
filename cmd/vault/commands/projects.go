package commands

import (
	"fmt"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

type projectItem struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"created_at"`
}

func NewProjectsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "Manage projects",
	}
	cmd.AddCommand(
		newProjectsListCmd(),
		newProjectsCreateCmd(),
		newProjectsDeleteCmd(),
		newLinkCmd(),
		newUnlinkCmd(),
	)
	return cmd
}

func newProjectsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all projects",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			var projects []projectItem
			if err := c.Get("/api/v1/projects", &projects); err != nil {
				return err
			}
			if len(projects) == 0 {
				fmt.Println("No projects found.")
				return nil
			}
			fmt.Printf("%-20s  %-20s  %s\n", "NAME", "SLUG", "CREATED")
			for _, p := range projects {
				fmt.Printf("%-20s  %-20s  %s\n", p.Name, p.Slug, fmtTime(p.CreatedAt))
			}
			return nil
		},
	}
}

func newProjectsCreateCmd() *cobra.Command {
	var slug string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			body := map[string]string{"name": args[0], "slug": slug}
			var p projectItem
			if err := c.Post("/api/v1/projects", body, &p); err != nil {
				return err
			}
			fmt.Printf("Created project %q (slug: %s)\n", p.Name, p.Slug)
			return nil
		},
	}
	cmd.Flags().StringVar(&slug, "slug", "", "Custom slug (default: derived from name)")
	return cmd
}

func newProjectsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <slug>",
		Short: "Delete a project and all its data",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slug := args[0]
			fmt.Printf("This will permanently delete project %q and all its environments and secrets.\n", slug)
			confirm := promptLine("Type the project slug to confirm: ")
			if confirm != slug {
				return fmt.Errorf("confirmation did not match — aborted")
			}
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			if err := c.Delete("/api/v1/projects/" + slug); err != nil {
				return err
			}
			fmt.Printf("Deleted project %q.\n", slug)
			if r, ok := config.LoadRepoLocal(); ok && r.Project == slug {
				_ = config.RemoveRepo()
				fmt.Println("Unlinked — .vault.toml removed (project deleted).")
			}
			return nil
		},
	}
}

func newUnlinkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlink",
		Short: "Remove .vault.toml from the current directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := config.RemoveRepo(); err != nil {
				return err
			}
			fmt.Println("Unlinked — .vault.toml removed.")
			return nil
		},
	}
}

// newLinkCmd writes .vault.toml in the current directory.
// If project-slug is omitted, the project from an existing .vault.toml is reused,
// making it easy to switch environment without retyping the project name.
func newLinkCmd() *cobra.Command {
	var envSlug string
	cmd := &cobra.Command{
		Use:   "link [project-slug]",
		Short: "Link the current directory to a project+environment",
		Long: `Writes .vault.toml in the current directory.
If project-slug is omitted, the project from the existing .vault.toml is used,
allowing you to switch environment without re-specifying the project.

Examples:
  vault projects link myapp --env dev    # link to myapp / dev
  vault projects link --env staging      # switch to staging, keep current project`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectSlug := ""
			if len(args) > 0 {
				projectSlug = args[0]
			} else {
				// Fall back to the project already configured in this directory.
				if r, err := config.LoadRepo(); err == nil {
					projectSlug = r.Project
				}
			}
			if projectSlug == "" {
				return fmt.Errorf("project slug required: pass it as an argument or run from an already-linked directory")
			}
			if envSlug == "" {
				envSlug = promptLine("Environment slug: ")
			}
			r := config.Repo{Project: projectSlug, Env: envSlug}
			if err := config.SaveRepo(r); err != nil {
				return err
			}
			fmt.Printf("Linked to project=%s env=%s — wrote .vault.toml\n", projectSlug, envSlug)
			return nil
		},
	}
	cmd.Flags().StringVar(&envSlug, "env", "", "Environment slug")
	return cmd
}
