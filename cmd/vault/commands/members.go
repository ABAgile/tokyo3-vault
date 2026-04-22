package commands

import (
	"fmt"
	"net/url"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

type memberItem struct {
	UserID    string  `json:"user_id"`
	Email     string  `json:"email"`
	Role      string  `json:"role"`
	Scope     string  `json:"scope"`
	EnvID     *string `json:"env_id,omitempty"`
	CreatedAt string  `json:"created_at"`
}

type userLookup struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func NewMembersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "members",
		Short: "Manage project members",
	}
	cmd.AddCommand(
		newMembersListCmd(),
		newMembersAddCmd(),
		newMembersUpdateCmd(),
		newMembersRemoveCmd(),
	)
	return cmd
}

func newMembersListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <project-slug>",
		Short: "List all members of a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			var members []memberItem
			if err := c.Get("/api/v1/projects/"+args[0]+"/members", &members); err != nil {
				return err
			}
			if len(members) == 0 {
				fmt.Println("No members found.")
				return nil
			}
			fmt.Printf("%-36s  %-30s  %-8s  %-9s  %s\n", "USER ID", "EMAIL", "ROLE", "SCOPE", "ADDED")
			for _, m := range members {
				scope := m.Scope
				if scope == "" {
					scope = "project"
				}
				fmt.Printf("%-36s  %-30s  %-8s  %-9s  %s\n", m.UserID, m.Email, m.Role, scope, fmtTime(m.CreatedAt))
			}
			return nil
		},
	}
}

func newMembersAddCmd() *cobra.Command {
	var email, role, envID string
	cmd := &cobra.Command{
		Use:   "add <project-slug>",
		Short: "Add a user to a project (owner only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)

			// Resolve email → user ID.
			var u userLookup
			if err := c.Get("/api/v1/users/lookup?email="+url.QueryEscape(email), &u); err != nil {
				return fmt.Errorf("user lookup: %w", err)
			}

			body := map[string]any{"user_id": u.ID, "role": role}
			if envID != "" {
				body["env_id"] = envID
			}
			if err := c.Post("/api/v1/projects/"+args[0]+"/members", body, nil); err != nil {
				return err
			}
			scope := "project"
			if envID != "" {
				scope = "env " + envID
			}
			fmt.Printf("Added %s to %s as %s (%s scope).\n", email, args[0], role, scope)
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "Email address of the user to add (required)")
	cmd.Flags().StringVar(&role, "role", "viewer", "Role to assign: viewer, editor, or owner")
	cmd.Flags().StringVar(&envID, "env-id", "", "Scope membership to this environment ID (omit for project-level)")
	_ = cmd.MarkFlagRequired("email")
	return cmd
}

func newMembersUpdateCmd() *cobra.Command {
	var role, envID string
	cmd := &cobra.Command{
		Use:   "update <project-slug> <user-id>",
		Short: "Change a member's role (owner only)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			body := map[string]any{"role": role}
			if envID != "" {
				body["env_id"] = envID
			}
			path := "/api/v1/projects/" + args[0] + "/members/" + args[1]
			if err := c.Put(path, body, nil); err != nil {
				return err
			}
			fmt.Printf("Updated %s to role %s.\n", args[1], role)
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "New role: viewer, editor, or owner (required)")
	cmd.Flags().StringVar(&envID, "env-id", "", "Target env-scoped membership (omit for project-level)")
	_ = cmd.MarkFlagRequired("role")
	return cmd
}

func newMembersRemoveCmd() *cobra.Command {
	var envID string
	cmd := &cobra.Command{
		Use:   "remove <project-slug> <user-id>",
		Short: "Remove a member from a project (owner only)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			path := "/api/v1/projects/" + args[0] + "/members/" + args[1]
			if envID != "" {
				path += "?env_id=" + url.QueryEscape(envID)
			}
			if err := c.Delete(path); err != nil {
				return err
			}
			fmt.Printf("Removed %s from %s.\n", args[1], args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&envID, "env-id", "", "Target env-scoped membership (omit for project-level)")
	return cmd
}
