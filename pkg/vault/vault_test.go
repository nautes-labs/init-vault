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

package vault_test

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/nautes-labs/init-vault/pkg/public"
	. "github.com/nautes-labs/init-vault/pkg/vault"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var vaultServer *exec.Cmd
var _ = BeforeSuite(func() {
	vaultServer = exec.Command("vault", "server", "-dev", "-dev-root-token-id=test")
	err := vaultServer.Start()
	Expect(err).Should(BeNil())
})

var _ = AfterSuite(func() {
	err := vaultServer.Process.Kill()
	Expect(err).Should(BeNil())
})

var _ = Describe("Vault", func() {
	var tVault *NautesVault
	BeforeEach(func() {
		tVault = &NautesVault{
			Client: nil,
			Host:   "http://127.0.0.1:8200",
			Token:  "test",
			KVEngineList: []VaultKVEngine{
				{
					Name: "t-Engine",
					KVList: []VaultKV{
						{
							Path: "git/is/good",
							KVs: map[string]interface{}{
								"key01": "this is key one",
								"key02": "this is key two",
							},
						},
					},
				},
			},
			AuthList: []VaultAuth{
				{
					Name:           "t-auth",
					KubeconfigPath: "/root/.kube/config",
					K8sServiceAccount: public.KubernetesServiceAccount{
						Name:      "vault-test-user",
						Namespace: "t-vault",
					},
				},
			},
			RoleList: []VaultRole{
				{
					AuthName: "t-auth",
					Name:     "t-role",
					NamespaceList: []string{
						"t-ns-01",
						"t-ns-02",
					},
					ServiceAccountList: []string{
						"t-sa-01",
						"t-sa-02",
					},
					Policies: []string{
						"t-pl-01",
						"t-pl-02",
					},
				},
			},
			PolicyList: []VaultPolicy{},
		}

		err := tVault.SetupNautesVault("")
		Expect(err).Should(BeNil())

	})
	Context("Create KV", func() {
		var engineName string
		var kvPath string
		BeforeEach(func() {
			engineName = tVault.KVEngineList[0].Name
			kvPath = tVault.KVEngineList[0].KVList[0].Path

			err := tVault.CreateKVEngineByName(engineName, CreateOption{})
			Expect(err).Should(BeNil())
		})

		It("new", func() {
			want := map[string]interface{}{
				"key01": "this is key one",
				"key02": "this is key two",
			}
			kvList, err := tVault.Client.KVv2(engineName).Get(context.Background(), kvPath)
			Expect(err).Should(BeNil())
			for k, v := range want {
				Expect(kvList.Data[k]).Should(Equal(v))
			}
		})

		It("append", func() {
			want := map[string]interface{}{
				"key01": "this is key one",
				"key03": "this is key three",
			}
			tVault.KVEngineList[0].KVList[0].KVs = map[string]interface{}{
				"key01": "this is key one",
				"key03": "this is key three",
			}

			err := tVault.CreateKVEngineByName(engineName, CreateOption{})
			Expect(err).Should(BeNil())

			kvList, err := tVault.Client.KVv2(engineName).Get(context.Background(), kvPath)
			Expect(err).Should(BeNil())
			for k, v := range want {
				Expect(kvList.Data[k]).Should(Equal(v))
			}

		})
	})

	Context("Role", func() {
		var roleName string
		var authName string
		var roleConfigPath string

		BeforeEach(func() {
			roleName = tVault.RoleList[0].Name
			authName = tVault.GetRole(roleName).AuthName
			err := tVault.CreateAuthByName(authName, CreateOption{
				InitKubernetes: true,
			})
			Expect(err).Should(BeNil())

			err = tVault.CreateRoleByName(roleName, CreateOption{})
			Expect(err).Should(BeNil())

			roleConfigPath = fmt.Sprintf("auth/%s/role/%s", authName, roleName)
		})

		It("create new role", func() {
			roleCFG, err := tVault.Client.Logical().Read(roleConfigPath)
			Expect(err).Should(BeNil())
			fmt.Println(roleCFG.Data)
		})

		It("append role config", func() {
			wantNS := []string{"t-ns-01", "t-ns-02", "t-ns-03", "t-ns-04"}
			wantSA := []string{"t-sa-01", "t-sa-02", "t-sa-03", "t-sa-04"}
			wantPL := []string{"t-pl-01", "t-pl-02", "t-pl-03"}
			tVault.RoleList[0].NamespaceList = []string{"t-ns-01", "t-ns-03"}
			tVault.RoleList[0].ServiceAccountList = []string{"t-sa-01", "t-sa-03"}
			tVault.RoleList[0].Policies = []string{"t-pl-01", "t-pl-03"}
			tVault.RoleList[0].K8sServiceAccountList = []public.KubernetesServiceAccount{
				{
					Name:      "t-sa-04",
					Namespace: "t-ns-04",
				},
			}

			err := tVault.CreateRoleByName(roleName, CreateOption{})
			Expect(err).Should(BeNil())

			roleCFG, err := tVault.Client.Logical().Read(roleConfigPath)
			Expect(err).Should(BeNil())

			for i, ns := range wantNS {
				Expect(roleCFG.Data[ROLE_NAMESPACE_KEY].([]interface{})[i]).Should(Equal(ns))
			}
			for i, sa := range wantSA {
				Expect(roleCFG.Data[ROLE_SERVICE_ACCOUNT_KEY].([]interface{})[i]).Should(Equal(sa))
			}
			for i, pl := range wantPL {
				Expect(roleCFG.Data[ROLE_POLICY_KEY].([]interface{})[i]).Should(Equal(pl))
			}
		})
	})

})
