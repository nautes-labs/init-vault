package cmd

import (
	"os"

	vault "github.com/nautes-labs/init-vault/pkg/vault"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/yaml"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Init the specify vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultYaml, err := os.ReadFile(vaultCFG)
		if err != nil {
			return err
		}

		vaultIns := &vault.NautesVault{}
		err = yaml.Unmarshal(vaultYaml, vaultIns)
		if err != nil {
			return err
		}

		err = vaultIns.SetupNautesVault()
		if err != nil {
			return err
		}

		kubeConfigStr := GetKubeConfig(kubeCFG)
		for i := 0; i < len(vaultIns.AuthList); i++ {
			if vaultIns.AuthList[i].Kubeconfig == "" {
				vaultIns.AuthList[i].Kubeconfig = kubeConfigStr
			}
		}

		vaultIns.InitVault()
		return nil
	},
}
