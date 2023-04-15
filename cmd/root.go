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
	"github.com/spf13/cobra"
)

var (
	kubeCFG  string
	vaultCFG string

	rootCmd = &cobra.Command{}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeCFG, "kubeconfig", "", "The path of kubeconfig file (default is %HOME/.kube/config)")
	rootCmd.PersistentFlags().StringVar(&vaultCFG, "vault-config", "./vault.yaml", "The path of vault setting file")

	initInit()
	initClean()
	rootCmd.AddCommand(vaultInit)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(cleanUpCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
