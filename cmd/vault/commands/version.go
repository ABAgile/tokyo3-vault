package commands

import (
	"fmt"

	"github.com/abagile/tokyo3-base/version"
	"github.com/spf13/cobra"
)

// NewVersionCmd prints the resolved build version. v is the main package's
// linker-injected Version ("dev" until -ldflags "-X main.Version=..." sets it).
func NewVersionCmd(v string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("vault %s\n", version.Resolve(v))
		},
	}
}
