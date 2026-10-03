# Argo CD — Propuesta 2: duelo DevSecOps (k3s)

GitOps de la propuesta 2. Argo CD vive en el namespace `argocd` (k3s vanilla).

## Recursos

| Archivo | Recurso | Qué despliega |
|---------|---------|---------------|
| `appproject-ai-red-vs-blue-devsecops.yaml` | AppProject `ai-red-vs-blue-devsecops` | acota repos/namespaces/recursos de esta propuesta |
| `application-devsecops-pipeline.yaml` | Application `ai-red-vs-blue-devsecops-pipeline` | pipeline Tekton de 8 etapas + supply chain + sample-app |
| `application-kyverno-policies.yaml` | Application `ai-red-vs-blue-devsecops-kyverno-policies` | las ClusterPolicy de admission (sync-wave -1) |
| `application-backstage.yaml` | Application `ai-red-vs-blue-devsecops-backstage` | config de Backstage de la charla + agente interactivo |

## Orden (sync-waves)

```
-1  ai-red-vs-blue-devsecops-kyverno-policies   (las policies deben existir antes del deploy)
 0  ai-red-vs-blue-devsecops-pipeline, ai-red-vs-blue-devsecops-backstage
```

## Dependencias de PLATAFORMA (en el repo del homelab, no aquí)

Estas Applications asumen que ya existen (gestionadas por `labjp-homelab/homelab-gitops`):
- **Tekton** (`components/platform/tekton`)
- **Registry Zot** (`components/platform/registry`) — para push/firma/scan reales
- **Backstage** (la plataforma IDP; aquí solo va su *configuración* de la charla)
- **Kyverno** (el webhook; aquí van solo las *policies*)

Ver `../../../shared/gitops-architecture.md` para la separación plataforma (homelab) vs config de demo (este repo).

## Desplegar

```bash
kubectl apply -f appproject-ai-red-vs-blue-devsecops.yaml
kubectl apply -f application-kyverno-policies.yaml
kubectl apply -f application-devsecops-pipeline.yaml
kubectl apply -f application-backstage.yaml
```

> El repo es **privado**: Argo CD necesita credenciales de solo lectura registradas para este `repoURL`.

## Nomenclatura

- AppProject: `ai-red-vs-blue-devsecops`
- Applications: `duel-<component>` (kebab-case, inglés)
- Labels estándar: `app.kubernetes.io/part-of: black-alpaca-2026`, `black-alpaca.session: "2-duel"`
