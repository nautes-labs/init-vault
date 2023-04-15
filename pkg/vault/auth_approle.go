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

type VaultAuthAppRole struct {
	Name      string `yaml:"name"`
	RoleName  string `yaml:"roleName"`
	Policy    string `yaml:"policy"`
	BoundCIDR string `yaml:"boundCIDR"`
}

type roleAccessInfo struct {
	Name     string `yaml:"name"`
	RoleID   string `yaml:"roleID"`
	SecretID string `yaml:"secretID"`
}

// Only support one role in app role now
func (vc *NautesVault) CreateAppRole(auth VaultAuthAppRole) (*roleAccessInfo, error) {
	var err error

	err = vc.Client.Sys().DisableAuth(auth.Name)
	if err != nil {
		return nil, err
	}

	err = vc.Client.Sys().EnableAuthWithOptions(auth.Name, &vault.MountInput{
		Type: "approle",
	})
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("auth/%s/role/%s", auth.Name, auth.RoleName)
	sec, err := vc.Client.Logical().Write(path, map[string]interface{}{
		"secret_id_bound_cidrs": auth.BoundCIDR,
	})
	if err != nil {
		return nil, err
	}

	policyPath := fmt.Sprintf("%s/policies", path)
	sec, err = vc.Client.Logical().Write(policyPath, map[string]interface{}{
		"token_policies": auth.Policy,
	})
	if err != nil {
		return nil, err
	}

	roleIDPath := fmt.Sprintf("%s/role-id", path)
	sec, err = vc.Client.Logical().Read(roleIDPath)
	if err != nil {
		return nil, err
	}

	roleID := fmt.Sprint(sec.Data["role_id"])

	secretIDPath := fmt.Sprintf("%s/secret-id", path)
	sec, err = vc.Client.Logical().Write(secretIDPath, map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	secretID := fmt.Sprint(sec.Data["secret_id"])

	return &roleAccessInfo{
		Name:     auth.RoleName,
		RoleID:   roleID,
		SecretID: secretID,
	}, nil
}
