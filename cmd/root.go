package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	kubeCFG  string
	vaultCFG string

	rootCmd = &cobra.Command{}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeCFG, "kubeconfig", "", "the path of kubeconfig file (default is %HOME/.kube/config)")
	rootCmd.PersistentFlags().StringVar(&vaultCFG, "vault-config", "./vault.yaml", "the path of vault setting file (default is ./vault.yaml)")

	initClean()
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(cleanUpCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

func GetKubeConfig(path string) string {
	var kubeConfigPath string

	if path != "" {
		kubeConfigPath = path
	} else {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		kubeConfigPath = fmt.Sprintf("%s/.kube/config", userHome)
	}

	kubeCFG, err := os.ReadFile(kubeConfigPath)
	if err != nil {
		return ""
	}

	return string(kubeCFG)
}
