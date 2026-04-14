package commands

import (
	"fmt"

	"github.com/abagile/tokyo3-vault/internal/crypto"
	"github.com/spf13/cobra"
)

// NewKeygenCmd prints a fresh random KEK for use as VAULT_MASTER_KEY.
func NewKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "Generate a random master key for use as VAULT_MASTER_KEY",
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := crypto.GenerateKEK()
			if err != nil {
				return err
			}
			fmt.Println(key)
			return nil
		},
	}
}
