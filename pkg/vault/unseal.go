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

	vault "github.com/hashicorp/vault/api"
)

func (self *NautesVault) Unseal() ([]string, string, error) {
	initResp, err := self.Client.Sys().Init(&vault.InitRequest{
		SecretShares:    3,
		SecretThreshold: 2,
	})
	if err != nil {
		return nil, "", err
	}

	for _, key := range initResp.Keys {
		resp, err := self.Client.Sys().Unseal(key)
		if err != nil {
			return nil, "", err
		}
		if !resp.Sealed {
			return initResp.Keys, initResp.RootToken, nil
		}
	}

	return nil, "", fmt.Errorf("vault is not sealed")
}
