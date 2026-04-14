package commands

import (
	"fmt"

	"github.com/abagile/tokyo3-vault/internal/build"
	"github.com/spf13/cobra"
)

func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("vault %s (commit %s, built %s)\n", build.Version, build.Commit, build.BuildTime)
		},
	}
}
