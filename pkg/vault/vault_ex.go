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
	"io/ioutil"

	vault "github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

func (self *NautesVault) GetClientByName(roleName string) (*vault.Client, error) {
	role := self.GetRole(roleName)
	auth := self.GetAuth(role.AuthName)

	return self.GetClient(role, auth.Kubeconfig)
}

func (self *NautesVault) CreateKVEngineByName(name string, opt CreateOption) error {
	secEngine := self.GetSecretEngine(name)
	if secEngine == nil {
		return fmt.Errorf("can not find secret engine %s", name)
	}

	err := self.CreateKVEngine(secEngine, opt)
	if err != nil {
		return err
	}

	return nil
}

func (self *NautesVault) DeleteKVEngineByName(name string, opt CleanOption) error {
	secEngine := self.GetSecretEngine(name)
	if secEngine == nil {
		return fmt.Errorf("can not find secret engine %s", name)
	}

	err := self.DeleteKVEngine(secEngine, opt)
	if err != nil {
		return err
	}

	return nil
}

func (self *NautesVault) CreateAuthByName(authName string, opt CreateOption) error {
	auth := self.GetAuth(authName)
	if auth == nil {
		return fmt.Errorf("can not find the auth %s", authName)
	}

	err := self.CreateAuth(auth, opt)
	if err != nil {
		return err
	}

	return nil
}

func (self *NautesVault) DeleteAuthByName(name string, opt CleanOption) error {
	auth := self.GetAuth(name)
	if auth == nil {
		return fmt.Errorf("can not find auth %s", name)
	}

	err := self.DeleteAuth(auth, opt)
	if err != nil {
		return err
	}

	return nil
}

func (self *NautesVault) CreateRoleByName(name string, opt CreateOption) error {
	role := self.GetRole(name)
	if role == nil {
		return fmt.Errorf("can not find role %s", name)
	}

	auth := self.GetAuth(role.AuthName)
	if auth == nil {
		return fmt.Errorf("can not find auth %s by role %s", role.AuthName, role.Name)
	}

	err := self.CreateRole(role, auth.Kubeconfig, opt)
	if err != nil {
		return err
	}

	return nil
}

func (self *NautesVault) DeleteRoleByName(name string, opt CleanOption) error {
	role := self.GetRole(name)
	if role == nil {
		return fmt.Errorf("can not find role %s", name)
	}

	auth := self.GetAuth(role.AuthName)
	if auth == nil {
		return fmt.Errorf("can not find auth of role %s", role.Name)
	}

	err := self.DeleteRole(role, auth.Kubeconfig, opt)
	if err != nil {
		return err
	}

	return nil
}

func (self *NautesVault) CreatePolicyByName(name string, opt CreateOption) error {
	policy := self.GetPolicy(name)
	if policy == nil {
		return fmt.Errorf("can not find policy %s", name)
	}

	err := self.CreatePolicy(policy, opt)
	if err != nil {
		return err
	}
	return nil
}

func (self *NautesVault) DeletePolicyByName(name string, opt CleanOption) error {
	policy := self.GetPolicy(name)
	if policy == nil {
		return fmt.Errorf("can not find policy %s", name)
	}

	err := self.DeletePolicy(policy, opt)
	if err != nil {
		return err
	}

	return nil
}

func (self *NautesVault) InitVault(opt CreateOption) (map[string]error, bool) {
	report := map[string]error{}
	accessRepo := appRolesAccessReport{
		Infos: []roleAccessInfo{},
	}

	for _, kv := range self.AppRoleList {
		fmt.Printf("creating app role %s.\n", kv.Name)
		accessInfo, err := self.CreateAppRole(kv)
		if err != nil {
			fmt.Printf("%s: %s\n", report[kv.Name], err)
			report[kv.Name] = err
		} else {
			accessRepo.Infos = append(accessRepo.Infos, *accessInfo)
		}
	}

	accessRepo.export(self.exportPath)

	for _, kv := range self.KVEngineList {
		fmt.Printf("creating kv engine %s.\n", kv.Name)
		err := self.CreateKVEngineByName(kv.Name, opt)
		if err != nil {
			fmt.Printf("%s: %s\n", report[kv.Name], err)
			report[kv.Name] = err
		}
	}

	for _, policy := range self.PolicyList {
		fmt.Printf("creating policy %s.\n", policy.Name)
		err := self.CreatePolicyByName(policy.Name, opt)
		if err != nil {
			fmt.Printf("%s: %s\n", report[policy.Name], err)
			report[policy.Name] = err
		}
	}

	for _, auth := range self.AuthList {
		fmt.Printf("creating auth %s.\n", auth.Name)
		err := self.CreateAuthByName(auth.Name, opt)
		if err != nil {
			fmt.Printf("%s: %s\n", report[auth.Name], err)
			report[auth.Name] = err
		}
	}

	for _, role := range self.RoleList {
		fmt.Printf("creating role %s.\n", role.Name)
		err := self.CreateRoleByName(role.Name, opt)
		if err != nil {
			fmt.Printf("%s: %s\n", report[role.Name], err)
			report[role.Name] = err
		}
	}

	if len(report) != 0 {
		return report, false
	}

	return map[string]error{}, true
}

func (self *NautesVault) CleanUP(opt CleanOption) (map[string]error, bool) {
	report := map[string]error{}

	for _, kv := range self.KVEngineList {
		fmt.Printf("deleting kv engine %s.\n", kv.Name)
		err := self.DeleteKVEngineByName(kv.Name, opt)
		if err != nil {
			fmt.Printf("%s: %s\n", report[kv.Name], err)
			report[kv.Name] = err
		}
	}

	for _, role := range self.RoleList {
		fmt.Printf("deleting role %s.\n", role.Name)
		err := self.DeleteRoleByName(role.Name, opt)
		if err != nil {
			fmt.Printf("%s: %s\n", report[role.Name], err)
			report[role.Name] = err
		}
	}

	for _, auth := range self.AuthList {
		fmt.Printf("deleting auth %s.\n", auth.Name)
		err := self.DeleteAuthByName(auth.Name, opt)
		if err != nil {
			fmt.Printf("%s: %s\n", report[auth.Name], err)
			report[auth.Name] = err
		}
	}

	for _, policy := range self.PolicyList {
		fmt.Printf("deleting policy %s.\n", policy.Name)
		err := self.DeletePolicyByName(policy.Name, opt)
		if err != nil {
			fmt.Printf("%s: %s\n", report[policy.Name], err)
			report[policy.Name] = err
		}
	}

	if len(report) != 0 {
		return report, false
	}

	return map[string]error{}, true
}

type appRolesAccessReport struct {
	Infos []roleAccessInfo
}

func (r *appRolesAccessReport) export(path string) error {
	data, err := yaml.Marshal(&r)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, data, 0600)
	if err != nil {
		return err
	}

	return nil
}
