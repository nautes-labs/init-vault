package public

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func GetToken(kubeconfig, namespace, serviceAccount string) string {
	client, err := ConvertStringToKubeClient(kubeconfig)
	if err != nil {
		fmt.Print(err.Error())
		return ""
	}

	for i := 0; i < 5; i++ {
		usr, err := client.CoreV1().ServiceAccounts(namespace).Get(context.Background(), serviceAccount, metav1.GetOptions{})
		if err != nil {
			fmt.Print(err.Error())
			return ""
		}

		// to avoid service account is created but token is still creating, wait for 10s
		if len(usr.Secrets) == 0 {
			time.Sleep(time.Second * 2)
			continue
		}

		secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), usr.Secrets[0].Name, metav1.GetOptions{})
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
