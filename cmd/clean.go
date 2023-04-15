// Copyright 2023 Nautes Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"os"

	vault "github.com/nautes-labs/init-vault/pkg/vault"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/yaml"
)

var (
	cleanK8s        bool
	removeNamespace bool
)

func initClean() {
	cleanUpCmd.Flags().BoolVar(&cleanK8s, "clean-k8s", false, "Remove the k8s resources")
	cleanUpCmd.Flags().BoolVar(&removeNamespace, "remove-namespace", false, "Remove the k8s namespace when deleting role")
}

var cleanUpCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean up the specify vault",
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

		err = vaultIns.SetupNautesVault("")
		if err != nil {
			return err
		}

		if kubeCFG != "" {
			for i := 0; i < len(vaultIns.AuthList); i++ {
				if vaultIns.AuthList[i].KubeconfigPath == "" {
					vaultIns.AuthList[i].KubeconfigPath = kubeCFG
				}
			}
		}

		cleanOpts := vault.CleanOption{
			CleanKubernetes:    cleanK8s,
			CleanRoleNamespace: removeNamespace,
		}
		vaultIns.CleanUP(cleanOpts)
		return nil
	},
}
