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

package vault

import (
	"fmt"
	"os"

	. "github.com/nautes-labs/init-vault/pkg/public"
)

type VaultAuth struct {
	Name               string `yaml:"name"`
	Kubeconfig         string `yaml:"kubeconfig"`
	KubeconfigPath     string `yaml:"kubeconfigPath"`
	KubernetesHost     string
	KubernetesCABundle string
	K8sServiceAccount  KubernetesServiceAccount `yaml:"k8sServiceAccount"`
}

// Load kubeconfig priority: write kubeconfig in vault > give a kubeconfig path > read from user home
func (self *VaultAuth) SetKubeConfig() error {
	if self.Kubeconfig != "" {
		return nil
	}

	if self.KubeconfigPath != "" {
		kubeCFG, err := os.ReadFile(self.KubeconfigPath)
		if err != nil {
			return err
		}
		self.Kubeconfig = string(kubeCFG)
		return nil
	}

	userHome, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	kubeCFG, err := os.ReadFile(fmt.Sprintf("%s/.kube/config", userHome))
	if err != nil {
		return err
	}
	self.Kubeconfig = string(kubeCFG)
	return nil

}

func (self *VaultAuth) GetKubernetesHost() string {
	apiCFG, err := ConvertStringToRawConfig(self.Kubeconfig)
	if err != nil {
		return ""
	}
	return apiCFG.Clusters[apiCFG.CurrentContext].Server
}

func (self *VaultAuth) GetKubernetesCABundle() string {
	apiCFG, err := ConvertStringToRawConfig(self.Kubeconfig)
	if err != nil {
		return ""
	}
	return string(apiCFG.Clusters[apiCFG.CurrentContext].CertificateAuthorityData)
}

func (self *VaultAuth) GetVaultUserToken() string {
	client, err := ConvertStringToKubeClient(self.Kubeconfig)
	if err != nil {
		return ""
	}
	return GetToken(client, self.K8sServiceAccount)
}
