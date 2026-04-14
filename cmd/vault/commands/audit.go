package commands

import (
	"fmt"

	"github.com/abagile/tokyo3-vault/cmd/vault/client"
	"github.com/abagile/tokyo3-vault/cmd/vault/config"
	"github.com/spf13/cobra"
)

type auditEntry struct {
	ID        string  `json:"id"`
	Action    string  `json:"action"`
	ActorID   *string `json:"actor_id,omitempty"`
	ProjectID *string `json:"project_id,omitempty"`
	Resource  *string `json:"resource,omitempty"`
	IP        *string `json:"ip,omitempty"`
	CreatedAt string  `json:"created_at"`
}

func NewAuditCmd() *cobra.Command {
	var project, action string
	var limit int

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show audit log entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := config.MustToken()
			if err != nil {
				return err
			}

			path := "/api/v1/audit?"
			if project != "" {
				path += "project=" + project + "&"
			}
			if action != "" {
				path += "action=" + action + "&"
			}
			if limit > 0 {
				path += fmt.Sprintf("limit=%d", limit)
			}

			c := client.New(g.ServerURL, g.Token)
			var entries []auditEntry
			if err := c.Get(path, &entries); err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("No audit entries found.")
				return nil
			}

			fmt.Printf("%-22s  %-24s  %-30s  %s\n", "TIME", "ACTION", "RESOURCE", "ACTOR")
			for _, e := range entries {
				resource := "-"
				if e.Resource != nil {
					resource = *e.Resource
				}
				actor := "-"
				if e.ActorID != nil {
					actor = (*e.ActorID)[:8] + "…"
				}
				fmt.Printf("%-22s  %-24s  %-30s  %s\n", fmtTime(e.CreatedAt), e.Action, resource, actor)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "Filter by project slug")
	cmd.Flags().StringVar(&action, "action", "", "Filter by action (e.g. secret.set)")
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum entries to return (1-500)")
	return cmd
}
