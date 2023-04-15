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

package public

import (
	"context"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type KubernetesServiceAccount struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

func GetToken(client *kubernetes.Clientset, sa KubernetesServiceAccount) string {

	for i := 0; i < 5; i++ {
		usr, err := client.CoreV1().ServiceAccounts(sa.Namespace).Get(context.Background(), sa.Name, metav1.GetOptions{})
		if err != nil {
			fmt.Print(err.Error())
			return ""
		}

		// to avoid service account is created but token is still creating, wait for 10s
		if len(usr.Secrets) == 0 {
			time.Sleep(time.Second * 2)
			continue
		}

		secret, err := client.CoreV1().Secrets(sa.Namespace).Get(context.Background(), usr.Secrets[0].Name, metav1.GetOptions{})
		if err != nil {
			fmt.Print(err.Error())
			return ""
		}
		return string(secret.Data["token"])
	}

	return ""
}

func ConvertStringToRawConfig(kubeconfig string) (clientcmdapi.Config, error) {
	clientConfig, err := clientcmd.NewClientConfigFromBytes([]byte(kubeconfig))
	if err != nil {
		return clientcmdapi.Config{}, err
	}
	return clientConfig.RawConfig()
}

func ConvertStringToRestConfig(kubeconfig string) (*rest.Config, error) {
	clientConfig, err := clientcmd.NewClientConfigFromBytes([]byte(kubeconfig))
	if err != nil {
		return nil, err
	}

	return clientConfig.ClientConfig()
}

func ConvertStringToKubeClient(kubeconfig string) (*kubernetes.Clientset, error) {
	restConfig, err := ConvertStringToRestConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(restConfig)
}

func CreateServiceAccount(client *kubernetes.Clientset, sa KubernetesServiceAccount) error {
	_, err := client.CoreV1().Namespaces().Get(context.Background(), sa.Namespace, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = client.CoreV1().Namespaces().Create(context.Background(), &v1.Namespace{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Namespace",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: sa.Namespace,
				},
			}, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		} else {
			return nil
		}
	}

	_, err = client.CoreV1().ServiceAccounts(sa.Namespace).Get(context.Background(), sa.Name, metav1.GetOptions{})
	if err == nil {
		return nil
	}

	_, err = client.CoreV1().ServiceAccounts(sa.Namespace).Create(context.Background(), &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sa.Name,
			Namespace: sa.Namespace,
		},
		AutomountServiceAccountToken: new(bool),
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func DeleteServiceAccount(client *kubernetes.Clientset, sa KubernetesServiceAccount, removeNameSpace bool) error {
	if removeNameSpace {
		err := client.CoreV1().Namespaces().Delete(context.Background(), sa.Namespace, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	} else {
		err := client.CoreV1().ServiceAccounts(sa.Namespace).Delete(context.Background(), sa.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func CreateClusterRoleBinding(client *kubernetes.Clientset, roleBindingName string, roleName string, sa KubernetesServiceAccount) error {
	_, err := client.RbacV1().ClusterRoleBindings().Create(context.Background(), &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: roleBindingName,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      sa.Name,
			Namespace: sa.Namespace,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleName,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func DeleteClusterRoleBinding(client *kubernetes.Clientset, roleBindingName string) error {
	err := client.RbacV1().ClusterRoleBindings().Delete(context.Background(), roleBindingName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	return nil
}
