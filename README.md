# argocd-vault-secrets

1. Edit environment variables AVS_VAULT_URL and AVS_VAULT_KUBERNETES_AUTH_MOUNT_PATH in kustomization.yaml file
2. Install Argo CD with argocd-vault-secrets plugin:
```
kustomize build | kubectl apply -f -
```
