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
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CreateOption struct{}

type CleanOption struct {
	CleanRoleNamespace bool
}

type VaultAuth struct {
	Name           string `yaml:"name"`
	Namespace      string `yaml:"namespace"`
	ServiceAccount string `yaml:"serviceAccount"`
	Kubeconfig     string `yaml:"kubeconfig"`
	KubeconfigPath string `yaml:"kubeconfigPath"`
}

type VaultRole struct {
	AuthName       string   `yaml:"authName"`
	Name           string   `yaml:"name"`
	Namespace      string   `yaml:"namespace"`
	ServiceAccount string   `yaml:"serviceAccount"`
	Policies       []string `yaml:"policies"`
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
	Host         string          `yaml:"host"`
	CA           string          `yaml:"ca"`
	CAPath       string          `yaml:"capath"`
	Token        string          `yaml:"token"`
	KVEngineList []VaultKVEngine `yaml:"kvEngineList"`
	AuthList     []VaultAuth     `yaml:"authList"`
	RoleList     []VaultRole     `yaml:"roleList"`
	PolicyList   []VaultPolicy   `yaml:"policyList"`
}

// Make the NautesVault to be usable , must run once befor use it
func (vc *NautesVault) SetupNautesVault() error {
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

func (vc *NautesVault) SetClient() error {
	config := vault.DefaultConfig()

	config.Address = vc.Host
	caCertPool := x509.NewCertPool()
	if vc.CA != "" {
		caCertPool.AppendCertsFromPEM([]byte(vc.CA))
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
	client.SetToken(vc.Token)
	vc.Client = client

	return nil
}

func (vc *NautesVault) GetClient(roleName string) (*vault.Client, error) {
	config := vault.DefaultConfig()

	config.Address = vc.Host
	caCertPool := x509.NewCertPool()
	if vc.CA != "" {
		caCertPool.AppendCertsFromPEM([]byte(vc.CA))
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

	vcRole := vc.GetRole(roleName)
	kubeconfig := vc.GetAuth(vcRole.AuthName).Kubeconfig
	ns := vcRole.Namespace
	sa := vcRole.ServiceAccount

	k8sAuth, err := auth.NewKubernetesAuth(
		vcRole.Name,
		auth.WithMountPath(vcRole.AuthName),
		auth.WithServiceAccountToken(GetToken(kubeconfig, ns, sa)),
	)
	if err != nil {
		return nil, err
	}

	authInfo, err := client.Auth().Login(context.Background(), k8sAuth)
	if err != nil {
		return nil, err
	}
	if authInfo == nil {
		return nil, fmt.Errorf("can not login vault with role %s", vcRole.Name)
	}

	return client, nil
}

func (vc *NautesVault) GetSecretEngine(kvName string) *VaultKVEngine {
	for i := 0; i < len(vc.KVEngineList); i++ {
		if vc.KVEngineList[i].Name == kvName {
			return &vc.KVEngineList[i]
		}
	}
	return nil
}

func (vc *NautesVault) CreateSecretEngine(name string, opts CreateOption) error {
	secEngine := vc.GetSecretEngine(name)
	if secEngine == nil {
		return fmt.Errorf("can not find secret engine %s", name)
	}

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

	err := vc.Client.Sys().Mount(secEngine.Name, mountInput)
	if err != nil {
		return err
	}

	for _, kv := range secEngine.KVList {
		err := vc.createKVSecret(secEngine.Name, kv)
		if err != nil {
			return err
		}
	}

	return nil
}

func (vc *NautesVault) DeleteSecretEngine(path string, opt CleanOption) error {
	err := vc.Client.Sys().Unmount(path)
	if err != nil {
		return err
	}
	return nil
}

func (vc *NautesVault) createKVSecret(engineName string, kv VaultKV) error {
	_, err := vc.Client.KVv2(engineName).Put(context.Background(), kv.Path, kv.KVs)
	if err != nil {
		return err
	}
	return nil
}

func (vc *NautesVault) GetAuth(authName string) *VaultAuth {
	for _, auth := range vc.AuthList {
		if auth.Name == authName {
			return &VaultAuth{
				Name:           auth.Name,
				Namespace:      auth.Namespace,
				ServiceAccount: auth.ServiceAccount,
				Kubeconfig:     auth.Kubeconfig,
			}
		}
	}
	return nil
}

// 1. Get auth from auth list
// 2. Create vault sa and rolebinding in k8s
// 3. Create auth in vault
func (vc *NautesVault) CreateAuth(authName string, opts CreateOption) error {
	auth := vc.GetAuth(authName)
	if auth == nil {
		return fmt.Errorf("can not find the auth %s", authName)
	}
	kubeconfig := auth.Kubeconfig
	path := auth.Name
	ns := auth.Namespace
	sa := auth.ServiceAccount

	k8s, err := ConvertStringToKubeClient(kubeconfig)
	if err != nil {
		return err
	}

	_, err = k8s.CoreV1().Namespaces().Create(context.Background(), &v1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: ns,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	_, err = k8s.CoreV1().ServiceAccounts(ns).Create(context.Background(), &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sa,
			Namespace: ns,
		},
		AutomountServiceAccountToken: new(bool),
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	k8s.RbacV1().ClusterRoleBindings().Create(context.Background(), &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("role-%s-binding", ns),
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      sa,
			Namespace: ns,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:auth-delegator",
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	apiConfig, err := ConvertStringToRawConfig(kubeconfig)
	if err != nil {
		return err
	}

	authType := &vault.MountInput{
		Type: "kubernetes",
	}
	err = vc.Client.Sys().EnableAuthWithOptions(path, authType)
	if err != nil {
		return err
	}

	authOpts := map[string]interface{}{
		"kubernetes_host":    apiConfig.Clusters[apiConfig.CurrentContext].Server,
		"kubernetes_ca_cert": apiConfig.Clusters[apiConfig.CurrentContext].CertificateAuthorityData,
		"token_reviewer_jwt": GetToken(kubeconfig, ns, sa),
	}
	_, err = vc.Client.Logical().Write(fmt.Sprintf("auth/%s/config", path), authOpts)
	if err != nil {
		return err
	}

	return nil
}

func (vc *NautesVault) DeleteAuth(name string, opt CleanOption) error {
	auth := vc.GetAuth(name)
	if auth == nil {
		return fmt.Errorf("can not find auth %s", name)
	}

	err := vc.Client.Sys().DisableAuth(auth.Name)
	if err != nil {
		return err
	}

	k8sClient, err := ConvertStringToKubeClient(auth.Kubeconfig)
	if err != nil {
		return err
	}

	err = k8sClient.CoreV1().Namespaces().Delete(context.Background(), auth.Namespace, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (vc *NautesVault) GetRole(roleName string) *VaultRole {
	for _, role := range vc.RoleList {
		if role.Name == roleName {
			vr := &VaultRole{
				AuthName:       role.AuthName,
				Name:           role.Name,
				Namespace:      role.Namespace,
				ServiceAccount: role.ServiceAccount,
				Policies:       make([]string, len(role.Policies)),
			}
			copy(vr.Policies, role.Policies)
			return vr
		}
	}
	return nil
}

func (vc *NautesVault) GetRoleKubeConfig(name string) string {
	role := vc.GetRole(name)
	if role == nil {
		return ""
	}
	auth := vc.GetAuth(role.AuthName)
	if auth == nil {
		return ""
	}
	return auth.Kubeconfig
}

func (vc *NautesVault) CreateRole(name string, opts CreateOption) error {
	role := vc.GetRole(name)
	if role == nil {
		return fmt.Errorf("can not find role %s", name)
	}
	path := fmt.Sprintf("auth/%s/role/%s", role.AuthName, role.Name)
	roleOpts := map[string]interface{}{
		"bound_service_account_namespaces": role.Namespace,
		"bound_service_account_names":      role.ServiceAccount,
		"token_policies":                   role.Policies,
	}
	_, err := vc.Client.Logical().Write(path, roleOpts)
	if err != nil {
		return err
	}

	kubeconfig := vc.GetRoleKubeConfig(name)
	if kubeconfig == "" {
		return fmt.Errorf("can not get kubeconfig of role %s", name)
	}

	client, err := ConvertStringToKubeClient(kubeconfig)
	if err != nil {
		return err
	}

	client.CoreV1().Namespaces().Create(context.Background(), &v1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: role.Namespace,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	client.CoreV1().ServiceAccounts(role.Namespace).Create(context.Background(), &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      role.ServiceAccount,
			Namespace: role.Namespace,
		},
		AutomountServiceAccountToken: new(bool),
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (vc *NautesVault) DeleteRole(name string, opt CleanOption) error {
	role := vc.GetRole(name)
	if role == nil {
		return fmt.Errorf("can not find role %s", name)
	}

	auth := vc.GetAuth(role.AuthName)
	if auth == nil {
		return fmt.Errorf("can not find auth of role %s", role.Name)
	}

	client, err := ConvertStringToKubeClient(auth.Kubeconfig)
	if err != nil {
		return err
	}

	err = client.CoreV1().ServiceAccounts(role.Namespace).Delete(context.Background(), role.ServiceAccount, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	if opt.CleanRoleNamespace {
		err := client.CoreV1().Namespaces().Delete(context.Background(), role.Namespace, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func (vc *NautesVault) GetPolicy(policyName string) *VaultPolicy {
	for _, policy := range vc.PolicyList {
		if policy.Name == policyName {
			return &VaultPolicy{
				Name:  policy.Name,
				Rules: policy.Rules,
			}
		}
	}
	return nil
}

func (vc *NautesVault) CreatePolicy(name string, opts CreateOption) error {
	policy := vc.GetPolicy(name)
	if policy == nil {
		return fmt.Errorf("can not find policy %s", name)
	}
	err := vc.Client.Sys().PutPolicy(policy.Name, policy.Rules)
	if err != nil {
		return err
	}
	return nil
}

func (vc *NautesVault) DeletePolicy(name string, opt CleanOption) error {
	policy := vc.GetPolicy(name)
	if policy == nil {
		return fmt.Errorf("can not find policy %s", name)
	}

	err := vc.Client.Sys().DeletePolicy(policy.Name)
	if err != nil {
		return err
	}

	return nil
}

func (vc *NautesVault) InitVault() (map[string]error, error) {
	report := map[string]error{}

	for _, kv := range vc.KVEngineList {
		fmt.Printf("creating kv engine %s.\n", kv.Name)
		err := vc.CreateSecretEngine(kv.Name, CreateOption{})
		if err != nil {
			fmt.Printf("%s: %s\n", report[kv.Name], err)
			report[kv.Name] = err
		}
	}

	for _, policy := range vc.PolicyList {
		fmt.Printf("creating policy %s.\n", policy.Name)
		err := vc.CreatePolicy(policy.Name, CreateOption{})
		if err != nil {
			fmt.Printf("%s: %s\n", report[policy.Name], err)
			report[policy.Name] = err
		}
	}

	for _, auth := range vc.AuthList {
		fmt.Printf("creating auth %s.\n", auth.Name)
		err := vc.CreateAuth(auth.Name, CreateOption{})
		if err != nil {
			fmt.Printf("%s: %s\n", report[auth.Name], err)
			report[auth.Name] = err
		}
	}

	for _, role := range vc.RoleList {
		fmt.Printf("creating role %s.\n", role.Name)
		err := vc.CreateRole(role.Name, CreateOption{})
		if err != nil {
			fmt.Printf("%s: %s\n", report[role.Name], err)
			report[role.Name] = err
		}
	}

	if len(report) != 0 {
		return report, fmt.Errorf("there are some error in init")
	}

	return map[string]error{}, nil
}

func (vc *NautesVault) CleanUP(opt CleanOption) (map[string]error, error) {
	report := map[string]error{}

	for _, kv := range vc.KVEngineList {
		fmt.Printf("deleting kv engine %s.\n", kv.Name)
		err := vc.DeleteSecretEngine(kv.Name, CleanOption{})
		if err != nil {
			fmt.Printf("%s: %s\n", report[kv.Name], err)
			report[kv.Name] = err
		}
	}

	for _, role := range vc.RoleList {
		fmt.Printf("deleting role %s.\n", role.Name)
		err := vc.DeleteRole(role.Name, opt)
		if err != nil {
			fmt.Printf("%s: %s\n", report[role.Name], err)
			report[role.Name] = err
		}
	}

	for _, auth := range vc.AuthList {
		fmt.Printf("deleting auth %s.\n", auth.Name)
		err := vc.DeleteAuth(auth.Name, CleanOption{})
		if err != nil {
			fmt.Printf("%s: %s\n", report[auth.Name], err)
			report[auth.Name] = err
		}
	}

	for _, policy := range vc.PolicyList {
		fmt.Printf("deleting policy %s.\n", policy.Name)
		err := vc.DeletePolicy(policy.Name, CleanOption{})
		if err != nil {
			fmt.Printf("%s: %s\n", report[policy.Name], err)
			report[policy.Name] = err
		}
	}

	if len(report) != 0 {
		return report, fmt.Errorf("there are some error in cleanup")
	}

	return map[string]error{}, nil
}

func (va *VaultAuth) SetKubeConfig() error {

	if va.Kubeconfig != "" {
		return nil
	}

	if va.KubeconfigPath != "" {
		kubeCFG, err := os.ReadFile(va.KubeconfigPath)
		if err != nil {
			return err
		}
		va.Kubeconfig = string(kubeCFG)
		return nil
	}

	return nil
}
