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
	"io/ioutil"
	"os"

	vault "github.com/nautes-labs/init-vault/pkg/vault"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var initK8s bool
var initExportPath string
var unsealExportPath string

func initInit() {
	initCmd.PersistentFlags().BoolVar(&initK8s, "init-k8s", false, "Wheather create resource in k8s (default is false)")
	initCmd.PersistentFlags().StringVar(&initExportPath, "export-path", "/tmp/vault-init-out.yaml", "App roles secret id export to")
	vaultInit.PersistentFlags().StringVar(&unsealExportPath, "export-path", "/tmp/vault-unseal-out.yaml", "Unseal keys and root token export to")
}

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

		err = vaultIns.SetupNautesVault(initExportPath)
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

		vaultIns.InitVault(vault.CreateOption{
			InitKubernetes: initK8s,
		})
		return nil
	},
}

var vaultInit = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal Vault",
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

		err = vaultIns.SetCA()
		if err != nil {
			return err
		}

		err = vaultIns.SetClientWithOutLogin()
		if err != nil {
			return err
		}

		unsealKeys, rootToken, err := vaultIns.Unseal()
		if err != nil {
			return err
		}

		out := &unsealOutput{
			UnsealKeys: unsealKeys,
			Token:      rootToken,
		}

		data, err := yaml.Marshal(&out)
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(unsealExportPath, data, 0600)
		if err != nil {
			return err
		}

		return nil
	},
}

type unsealOutput struct {
	UnsealKeys []string `yaml:"vault_unseal_keys"`
	Token      string   `yaml:"vault_root_token"`
}
