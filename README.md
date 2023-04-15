# Init Vault
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![golang](https://img.shields.io/badge/golang-v1.17.13-brightgreen)](https://go.dev/doc/install)
[![version](https://img.shields.io/badge/version-v0.2.0-green)]()

Init-vault is a command line application for user to init vault data struct.

## Introduction

It will:

- auto create/remove kv engine
- auto create/remove kv under engine
- auto create/remove auth in vault and bind it to the dest kubernetes
- auto create/remove role in vault and needed namespace, service account in kubernetes
- auto create/remove policy in vault

## Quick Started

### Buiding

Clone the repo and enter the root path, run following command.
```bash
go build
```

### Usage
#### Init vault
```bash
cat <<EOT >> config.yaml
host: "vault_url"
capath: "/vault/ca/path"
EOT

./init-vault --vault-config config.yaml unseal --export-path /tmp/unseal.yml
```

#### Init vault data
```bash
# Edit this file
cp config/vault.yaml.example vault.yaml

# init the vault
./init-vault --vault-config vault.yaml init

# Clean up the vault
./init-vault --vault-config vault.yaml clean
```

### Unit Testing

```shell
go test -v ./...
```



