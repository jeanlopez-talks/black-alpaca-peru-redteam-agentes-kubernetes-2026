# Argo CD — propuesta 2 (duelo DevSecOps)

Todo lo de la propuesta 2 se despliega con un único paso declarativo:

```bash
kubectl apply -k .
```

| Archivo | Recurso | Qué despliega | Sync |
|---------|---------|---------------|------|
| `appproject-ai-red-vs-blue-devsecops.yaml` | AppProject `ai-red-vs-blue-devsecops` | límites de seguridad de la propuesta | — |
| `application-admission-policies.yaml` | `ai-red-vs-blue-devsecops-admission-policies` | policies Kyverno + namespace `devsecops-duel` (Pod Security) | automático, ola -1 |
| `application-devsecops-pipeline.yaml` | `ai-red-vs-blue-devsecops-pipeline` | pipeline Tekton de 8 etapas | **manual** (lanza la demo del ataque) |
| `application-backstage-devsecops-agent.yaml` | `ai-red-vs-blue-devsecops-backstage-agent` | agente human-in-the-loop + namespace `devsecops-agent` | automático, ola 1 |

## Modelo de seguridad

Quien puede escribir en el repo de la charla controla lo que Argo CD despliega. Por eso
el AppProject concede lo mínimo:

| Control | Decisión |
|---------|----------|
| Origen | un único repo (`sourceRepos`) |
| Namespaces | solo `devsecops-duel` y `devsecops-agent` |
| Ámbito de clúster | solo esos dos `Namespace`, **por nombre**. Sin ClusterRole/Binding, CRD ni policies de clúster |
| Tipos namespaced | lista explícita; **sin `Secret`** |
| Policies de Kyverno | `NamespacedValidatingPolicy` / `NamespacedImageValidatingPolicy`: no pueden afectar a otros namespaces |
| Secretos | `ExternalSecret` desde un `SecretStore` propio cuyo rol de OpenBao solo lee `apps/black-alpaca/*`, **nunca** el `ClusterSecretStore` global del homelab |
| Separación de credenciales | el pipeline (agente rojo, carga no confiable) y el agente con tokens viven en namespaces distintos |
| Pod Security | `devsecops-duel`: `baseline` (kaniko), con audit/warn `restricted`; `devsecops-agent`: `restricted` |
| Lectura de Argo CD | rol de proyecto `backstage-devsecops-agent-read` (solo `get` de las Application del proyecto); el agente no tiene RBAC en el namespace `argocd` |
| Deriva | `orphanedResources.warn` y `selfHeal` en los controles de seguridad |

## Requisitos de plataforma (repo del homelab)

- Tekton, Kyverno (v1.19, API `policies.kyverno.io/v1`), External Secrets y el registry
  publicado como `registry.labjp.xyz`.
- **OpenBao**: rol `black-alpaca-duel-agent` (auth kubernetes) ligado a la ServiceAccount
  `devsecops-agent/openbao-reader`, con una política que solo permita leer
  `homelab/data/apps/black-alpaca/*`.
- El repo es **privado**: Argo CD necesita credenciales de solo lectura para el `repoURL`.

## Pendiente recomendado

- **Commits firmados**: con GPG/SSH configurado, añadir `signatureKeys` al AppProject para
  que Argo CD solo sincronice commits firmados por claves conocidas.
