## What is init-vault?
Init-vault is a command line application for user to init vault data struct.
It will 
- auto create/remove kv engine
- auto create/remove kv under engine
- auto create/remove auth in vault and bind it to the dest kubernetes
- auto create/remove role in vault and needed namespace, service account in kubernetes
- auto create/remove policy in vault

## Buiding
This app is base on go 1.17.13

Clone the repo and enter the root path, run following command.
```bash
go build
```
## Usage
Modify the vault.yaml.example in config path.
```bash
cp config/vault.yaml.example vault.yaml
# Edit the file

# init the vault
./init-vault --vault-config vault.yaml init

# Clean up the vault
./init-vault --vault-config vault.yaml clean
```

