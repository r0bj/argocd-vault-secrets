# argocd-vault-secrets

## 1. Install Argo CD with plugin
1. Edit `kustomization.yaml` file, set environment variables `AVS_VAULT_URL` and `AVS_VAULT_KUBERNETES_AUTH_MOUNT_PATH`.
Plugin uses Vault kubernetes auth (https://www.vaultproject.io/docs/auth/kubernetes) so set `AVS_VAULT_KUBERNETES_AUTH_MOUNT_PATH` based on existing Vault configuration.
3. Install Argo CD with argocd-vault-secrets plugin:
```
kustomize build . | kubectl apply -f -
```
## 2. Use secret with annotation
Example secret:
```
kind: Secret
apiVersion: v1
metadata:
  name: example-secret
  annotations:
    vault-path: path/to/secret # path to secret in Vault
data:
  password: <password-key> # Vault secret key between < and >
```

Plugin fetches Vault secret available under path `path/to/secret` with key `password-key` and generates secret:
```
kind: Secret
apiVersion: v1
metadata:
  name: example-secret
  annotations:
    vault-path: path/to/secret
data:
  password: c2VjcmV0cGFzc3dvcmQK
```
Value of the key `password` comes from Vault and is base64 encoded to be able to apply to kubernetes.
