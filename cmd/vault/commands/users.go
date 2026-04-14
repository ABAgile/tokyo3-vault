package commands

import (
	"fmt"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

type userItem struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

func NewUsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage server users (admin only)",
	}
	cmd.AddCommand(
		newUsersListCmd(),
		newUsersCreateCmd(),
	)
	return cmd
}

func newUsersListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all users on the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)
			var users []userItem
			if err := c.Get("/api/v1/users", &users); err != nil {
				return err
			}
			if len(users) == 0 {
				fmt.Println("No users found.")
				return nil
			}
			fmt.Printf("%-36s  %-30s  %-8s  %s\n", "ID", "EMAIL", "ROLE", "CREATED")
			for _, u := range users {
				fmt.Printf("%-36s  %-30s  %-8s  %s\n", u.ID, u.Email, u.Role, fmtTime(u.CreatedAt))
			}
			return nil
		},
	}
}

func newUsersCreateCmd() *cobra.Command {
	var role string
	cmd := &cobra.Command{
		Use:   "create <email>",
		Short: "Create a new user (admin only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			password, err := promptPassword("Password for new user: ")
			if err != nil {
				return err
			}
			if len(password) < 8 {
				return fmt.Errorf("password must be at least 8 characters")
			}
			c := client.New(g.ServerURL, g.Token)
			body := map[string]string{
				"email":    args[0],
				"password": password,
				"role":     role,
			}
			var u userItem
			if err := c.Post("/api/v1/users", body, &u); err != nil {
				return err
			}
			fmt.Printf("Created user %s (role: %s)\n", u.Email, u.Role)
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "member", "Role to assign: member or admin")
	return cmd
}

func NewChangePasswordCmd() *cobra.Command {
	var email string
	cmd := &cobra.Command{
		Use:   "change-password",
		Short: "Change your own password, or reset another user's password (admin only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}
			c := client.New(g.ServerURL, g.Token)

			if email != "" {
				// Admin resetting another user's password — no current password needed.
				var u userLookup
				if err := c.Get("/api/v1/users/lookup?email="+email, &u); err != nil {
					return fmt.Errorf("user lookup: %w", err)
				}
				newPw, err := promptPassword("New password for " + email + ": ")
				if err != nil {
					return err
				}
				confirm, err := promptPassword("Confirm new password: ")
				if err != nil {
					return err
				}
				if newPw != confirm {
					return fmt.Errorf("passwords do not match")
				}
				if err := c.Put("/api/v1/users/"+u.ID+"/password", map[string]string{"password": newPw}, nil); err != nil {
					return err
				}
				fmt.Printf("Password reset for %s.\n", email)
				return nil
			}

			// Changing own password — current password required.
			current, err := promptPassword("Current password: ")
			if err != nil {
				return err
			}
			newPw, err := promptPassword("New password: ")
			if err != nil {
				return err
			}
			confirm, err := promptPassword("Confirm new password: ")
			if err != nil {
				return err
			}
			if newPw != confirm {
				return fmt.Errorf("passwords do not match")
			}
			body := map[string]string{
				"current_password": current,
				"new_password":     newPw,
			}
			if err := c.Put("/api/v1/auth/password", body, nil); err != nil {
				return err
			}
			fmt.Println("Password changed successfully.")
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "Email of user whose password to reset (admin only)")
	return cmd
}
