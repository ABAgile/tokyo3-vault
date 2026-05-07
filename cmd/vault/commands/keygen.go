package commands

import (
	"fmt"

	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/spf13/cobra"
)

// NewKeygenCmd prints a fresh random KEK for use as VAULT_MASTER_KEY.
func NewKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "Generate a random master key for use as VAULT_MASTER_KEY",
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := bcrypto.GenerateKEK()
			if err != nil {
				return err
			}
			fmt.Println(key)
			return nil
		},
	}
}
