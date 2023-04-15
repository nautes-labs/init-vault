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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	. "github.com/nautes-labs/init-vault/pkg/public"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

const (
	ROLE_POLICY_KEY          = "token_policies"
	ROLE_NAMESPACE_KEY       = "bound_service_account_namespaces"
	ROLE_SERVICE_ACCOUNT_KEY = "bound_service_account_names"
)

type CreateOption struct {
	InitKubernetes bool
}

type CleanOption struct {
	CleanKubernetes    bool
	CleanRoleNamespace bool
}

type VaultKVEngine struct {
	Name   string    `yaml:"name"`
	KVList []VaultKV `yaml:"kvList"`
}

type VaultKV struct {
	Path string                 `yaml:"path"`
	KVs  map[string]interface{} `yaml:"kvs"`
}

type VaultPolicy struct {
	Name  string `yaml:"name"`
	Rules string `yaml:"rules"`
}

type NautesVault struct {
	Client       *vault.Client
	exportPath   string
	Host         string             `yaml:"host"`
	CA           string             `yaml:"ca"`
	CAPath       string             `yaml:"capath"`
	Token        string             `yaml:"token"`
	KVEngineList []VaultKVEngine    `yaml:"kvEngineList"`
	AppRoleList  []VaultAuthAppRole `yaml:"appRoleList"`
	AuthList     []VaultAuth        `yaml:"authList"`
	RoleList     []VaultRole        `yaml:"roleList"`
	PolicyList   []VaultPolicy      `yaml:"policyList"`
}

// Make the NautesVault to be usable , must run once befor use it
func (vc *NautesVault) SetupNautesVault(path string) error {
	for i := 0; i < len(vc.AuthList); i++ {
		err := vc.AuthList[i].SetKubeConfig()
		if err != nil {
			return err
		}
	}

	err := vc.SetCA()
	if err != nil {
		return err
	}

	err = vc.SetClient()
	if err != nil {
		return err
	}

	vc.exportPath = path

	return nil
}

func (vc *NautesVault) SetCA() error {
	if vc.CA != "" {
		return nil
	}

	if vc.CAPath != "" {
		CAByte, err := os.ReadFile(vc.CAPath)
		if err != nil {
			return err
		}
		vc.CA = string(CAByte)
		return nil
	}

	return nil
}

func (self *NautesVault) SetClientWithOutLogin() error {
	config := vault.DefaultConfig()

	config.Address = self.Host
	caCertPool := x509.NewCertPool()
	if self.CA != "" {
		caCertPool.AppendCertsFromPEM([]byte(self.CA))
	}
	config.HttpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	client, err := vault.NewClient(config)
	if err != nil {
		return err
	}

	self.Client = client
	return nil
}

func (self *NautesVault) SetClient() error {
	config := vault.DefaultConfig()

	config.Address = self.Host
	caCertPool := x509.NewCertPool()
	if self.CA != "" {
		caCertPool.AppendCertsFromPEM([]byte(self.CA))
	}
	config.HttpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	client, err := vault.NewClient(config)
	if err != nil {
		return err
	}

	client.SetToken(self.Token)
	self.Client = client

	return nil
}

func (self *NautesVault) GetClient(role *VaultRole, kubeconfig string) (*vault.Client, error) {
	config := vault.DefaultConfig()

	config.Address = self.Host
	caCertPool := x509.NewCertPool()
	if self.CA != "" {
		caCertPool.AppendCertsFromPEM([]byte(self.CA))
	}
	config.HttpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}

	sa := role.K8sServiceAccountList[0]
	k8sClient, err := ConvertStringToKubeClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	k8sAuth, err := auth.NewKubernetesAuth(
		role.Name,
		auth.WithMountPath(role.AuthName),
		auth.WithServiceAccountToken(GetToken(k8sClient, sa)),
	)
	if err != nil {
		return nil, err
	}

	authInfo, err := client.Auth().Login(context.Background(), k8sAuth)
	if err != nil {
		return nil, err
	}
	if authInfo == nil {
		return nil, fmt.Errorf("can not login vault with role %s", role.Name)
	}

	return client, nil
}

func (self *NautesVault) GetSecretEngine(kvName string) *VaultKVEngine {
	for i := 0; i < len(self.KVEngineList); i++ {
		if self.KVEngineList[i].Name == kvName {
			return &self.KVEngineList[i]
		}
	}
	return nil
}

func (self *NautesVault) CreateKVEngine(secEngine *VaultKVEngine, opt CreateOption) error {
	kvEngineInfo, err := self.Client.Logical().Read(fmt.Sprintf("%s/config", secEngine.Name))
	if err != nil {
		return err
	}
	if kvEngineInfo == nil {
		mountInput := &vault.MountInput{
			Type:                  "kv",
			Description:           "",
			Config:                vault.MountConfigInput{},
			Local:                 false,
			SealWrap:              false,
			ExternalEntropyAccess: false,
			Options: map[string]string{
				"version": "2",
			},
			PluginName: "",
		}

		err = self.Client.Sys().Mount(secEngine.Name, mountInput)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("kv engine %s is already exist, skip create kv engine\n", secEngine.Name)
	}

	for _, kv := range secEngine.KVList {
		kvList, err := self.Client.KVv2(secEngine.Name).Get(context.Background(), kv.Path)
		if err != nil || !self.isKVsEqual(kvList.Data, kv.KVs) {
			err := self.createKVSecret(secEngine.Name, kv)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func (self *NautesVault) DeleteKVEngine(secEngine *VaultKVEngine, opt CleanOption) error {
	err := self.Client.Sys().Unmount(secEngine.Name)
	if err != nil {
		return err
	}
	return nil
}

func (self *NautesVault) isKVsEqual(src, dst map[string]interface{}) bool {
	if len(src) != len(dst) {
		return false
	}

	// loop src array, find the key in the source is also in the dest
	// if found the same key, compare the vaule is the same
	// if can not find the key in the dest or vault not same, return true
	// if dest is a superset of src, it should be return true in the length compare
	for srcKey, srcVar := range src {
		hasKey := false
		for dstKey, dstVar := range dst {
			if srcKey == dstKey {
				if srcVar != dstVar {
					return false
				}

				hasKey = true
				break
			}
		}
		if !hasKey {
			return false
		}
	}

	return true
}

func (self *NautesVault) createKVSecret(engineName string, kv VaultKV) error {
	_, err := self.Client.KVv2(engineName).Put(context.Background(), kv.Path, kv.KVs)
	if err != nil {
		return err
	}
	return nil
}

func (self *NautesVault) GetAuth(name string) *VaultAuth {
	for i := 0; i < len(self.AuthList); i++ {
		if self.AuthList[i].Name == name {
			return &self.AuthList[i]
		}
	}
	return nil
}

// 1. Get auth from auth list
// 2. Create vault sa and rolebinding in k8s
// 3. Create auth in vault
func (self *NautesVault) CreateAuth(auth *VaultAuth, opt CreateOption) error {
	kubeconfig := auth.Kubeconfig
	path := auth.Name
	sa := auth.K8sServiceAccount

	k8sClient, err := ConvertStringToKubeClient(kubeconfig)
	if err != nil {
		return err
	}

	if opt.InitKubernetes {
		fmt.Printf("create service account %s in namespace %s\n", sa.Name, sa.Namespace)

		err = CreateServiceAccount(k8sClient, auth.K8sServiceAccount)
		if err != nil {
			return err
		}
		roleBindingName := fmt.Sprintf("role-%s-binding", sa.Namespace)
		err = CreateClusterRoleBinding(k8sClient, roleBindingName, "system:auth-delegator", auth.K8sServiceAccount)
	}

	apiConfig, err := ConvertStringToRawConfig(kubeconfig)
	if err != nil {
		return err
	}
	context := apiConfig.Contexts[apiConfig.CurrentContext]
	host := apiConfig.Clusters[context.Cluster].Server
	cacert := apiConfig.Clusters[context.Cluster].CertificateAuthorityData
	token := GetToken(k8sClient, sa)
	self.createK8sAuth(path, host, string(cacert), token)

	return nil
}

func (self *NautesVault) createK8sAuth(path, host, cacert, token string) error {
	authInfo, err := self.Client.Logical().Read(fmt.Sprintf("auth/%s/config", path))
	if err != nil {
		return err
	}

	if authInfo == nil {
		authType := &vault.MountInput{
			Type: "kubernetes",
		}
		err := self.Client.Sys().EnableAuthWithOptions(path, authType)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("%s is found in auth list, skip create auth\n", path)
	}

	authOpts := map[string]interface{}{
		"kubernetes_host":    host,
		"kubernetes_ca_cert": cacert,
		"token_reviewer_jwt": token,
	}
	_, err = self.Client.Logical().Write(fmt.Sprintf("auth/%s/config", path), authOpts)
	if err != nil {
		return err
	}

	return nil
}

func (self *NautesVault) DeleteAuth(auth *VaultAuth, opt CleanOption) error {
	err := self.Client.Sys().DisableAuth(auth.Name)
	if err != nil {
		return err
	}

	k8sClient, err := ConvertStringToKubeClient(auth.Kubeconfig)
	if err != nil {
		return err
	}

	if opt.CleanKubernetes {
		err = DeleteServiceAccount(k8sClient, auth.K8sServiceAccount, opt.CleanRoleNamespace)
		if err != nil {
			return err
		}
	}

	return nil
}

func (self *NautesVault) GetRole(roleName string) *VaultRole {
	for i := 0; i < len(self.RoleList); i++ {
		if self.RoleList[i].Name == roleName {
			return &self.RoleList[i]
		}
	}
	return nil
}

func (self *NautesVault) CreateRole(role *VaultRole, kubeconfig string, opt CreateOption) error {
	path := fmt.Sprintf("auth/%s/role/%s", role.AuthName, role.Name)

	namespaces := []interface{}{}
	serviceAccounts := []interface{}{}
	policies := []interface{}{}

	if role.NamespaceList != nil {
		namespaces = append(namespaces, ConvertStringArrayToInterfaceArray(role.NamespaceList)...)
	}
	if role.ServiceAccountList != nil {
		serviceAccounts = append(serviceAccounts, ConvertStringArrayToInterfaceArray(role.ServiceAccountList)...)
	}
	if role.Policies != nil {
		policies = append(policies, ConvertStringArrayToInterfaceArray(role.Policies)...)
	}

	for _, sa := range role.K8sServiceAccountList {
		namespaces = AppendElements(namespaces, sa.Namespace)
		serviceAccounts = AppendElements(serviceAccounts, sa.Name)
	}

	roleOpts := map[string]interface{}{
		ROLE_NAMESPACE_KEY:       namespaces,
		ROLE_SERVICE_ACCOUNT_KEY: serviceAccounts,
		ROLE_POLICY_KEY:          policies,
	}
	_, err := self.Client.Logical().Write(path, self.PatchRoleConfig(path, roleOpts))
	if err != nil {
		return err
	}

	if opt.InitKubernetes {
		k8sClient, err := ConvertStringToKubeClient(kubeconfig)
		if err != nil {
			return err
		}

		for _, sa := range role.K8sServiceAccountList {
			fmt.Printf("create service account %s in namespace %s\n", sa.Name, sa.Namespace)

			err := CreateServiceAccount(k8sClient, sa)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (self *NautesVault) PatchRoleConfig(path string, newConfig map[string]interface{}) map[string]interface{} {
	roleCfg, err := self.Client.Logical().Read(path)
	if err != nil {
		return newConfig
	}
	if roleCfg == nil {
		return newConfig
	} else {
		fmt.Printf("find exist role config in %s, append opts\n", path)
	}

	policies := roleCfg.Data[ROLE_POLICY_KEY].([]interface{})
	if val, ok := newConfig[ROLE_POLICY_KEY]; ok {
		policies = AppendElements(policies, val.([]interface{})...)
	}

	namespaces := roleCfg.Data[ROLE_NAMESPACE_KEY].([]interface{})
	if val, ok := newConfig[ROLE_NAMESPACE_KEY]; ok {
		namespaces = AppendElements(namespaces, val.([]interface{})...)
	}

	serviceAccounts := roleCfg.Data[ROLE_SERVICE_ACCOUNT_KEY].([]interface{})
	if val, ok := newConfig[ROLE_SERVICE_ACCOUNT_KEY]; ok {
		serviceAccounts = AppendElements(serviceAccounts, val.([]interface{})...)
	}

	return map[string]interface{}{
		ROLE_NAMESPACE_KEY:       namespaces,
		ROLE_SERVICE_ACCOUNT_KEY: serviceAccounts,
		ROLE_POLICY_KEY:          policies,
	}
}

func ConvertStringArrayToInterfaceArray(in []string) []interface{} {
	out := make([]interface{}, 0)
	for _, v := range in {
		out = append(out, v)
	}
	return out
}

func AppendElements(old []interface{}, new ...interface{}) []interface{} {
	newElementList := make([]interface{}, 0)
	for _, i := range new {
		isNew := true
		for _, j := range old {
			if i == j {
				isNew = false
				break
			}
		}
		if isNew {
			fmt.Printf("append %s\n", i)
			newElementList = append(newElementList, i)
		}
	}
	return append(old, newElementList...)
}

func (self *NautesVault) DeleteRole(role *VaultRole, kubeconfig string, opt CleanOption) error {
	auth, err := self.Client.Logical().Read(fmt.Sprintf("auth/%s", role.AuthName))
	if err != nil {
		fmt.Printf("failed to get auth info from role %s", role.Name)
		return err
	}
	if auth != nil {
		rolePath := fmt.Sprintf("auth/%s/role/%s", role.AuthName, role.Name)
		fmt.Printf("delete role %s", role.Name)
		_, err = self.Client.Logical().Delete(rolePath)
		if err != nil {
			return err
		}
	}

	if opt.CleanKubernetes {
		client, err := ConvertStringToKubeClient(kubeconfig)
		if err != nil {
			return err
		}

		for _, sa := range role.K8sServiceAccountList {
			err := DeleteServiceAccount(client, sa, opt.CleanRoleNamespace)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (self *NautesVault) GetPolicy(name string) *VaultPolicy {
	for i := 0; i < len(self.PolicyList); i++ {
		if self.PolicyList[i].Name == name {
			return &self.PolicyList[i]
		}

	}
	return nil
}

func (self *NautesVault) CreatePolicy(policy *VaultPolicy, opt CreateOption) error {
	err := self.Client.Sys().PutPolicy(policy.Name, policy.Rules)
	if err != nil {
		return err
	}
	return nil
}

func (self *NautesVault) DeletePolicy(policy *VaultPolicy, opt CleanOption) error {
	err := self.Client.Sys().DeletePolicy(policy.Name)
	if err != nil {
		return err
	}

	return nil
}
