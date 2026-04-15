package commands

import (
	"fmt"
	"time"

	"github.com/abagile/tokyo3-vault/internal/build"
	"github.com/spf13/cobra"
)

func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			commitTime := build.CommitTime
			if t, err := time.Parse(time.RFC3339, build.CommitTime); err == nil {
				commitTime = t.Local().Format("2006-01-02 15:04:05 MST")
			}
			fmt.Printf("vault %s (commit %s, committed %s)\n", build.Version, build.Commit, commitTime)
		},
	}
}
