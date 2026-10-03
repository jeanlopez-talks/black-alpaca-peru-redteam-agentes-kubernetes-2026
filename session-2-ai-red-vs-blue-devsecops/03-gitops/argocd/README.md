# Argo CD — Propuesta 2: duelo DevSecOps (k3s)

GitOps de la propuesta 2. Argo CD vive en el namespace `argocd` (k3s vanilla).

## Recursos

| Archivo | Recurso | Qué despliega |
|---------|---------|---------------|
| `appproject.yaml` | AppProject `duel-devsecops` | acota repos/namespaces/recursos de esta propuesta |
| `application-duel-pipeline.yaml` | Application `duel-pipeline` | pipeline Tekton de 8 etapas + supply chain + sample-app |
| `application-kyverno-policies.yaml` | Application `duel-kyverno-policies` | las ClusterPolicy de admission (sync-wave -1) |
| `application-backstage.yaml` | Application `duel-backstage` | config de Backstage de la charla + agente interactivo |

## Orden (sync-waves)

```
-1  duel-kyverno-policies   (las policies deben existir antes del deploy)
 0  duel-pipeline, duel-backstage
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
kubectl apply -f appproject.yaml
kubectl apply -f application-kyverno-policies.yaml
kubectl apply -f application-duel-pipeline.yaml
kubectl apply -f application-backstage.yaml
```

> La `repoURL` es placeholder al repo de la charla — ajustar al publicarlo para que Argo CD lo lea.

## Nomenclatura

- AppProject: `duel-devsecops`
- Applications: `duel-<component>` (kebab-case, inglés)
- Labels estándar: `app.kubernetes.io/part-of: black-alpaca-2026`, `black-alpaca.session: "2-duel"`
