# Argo CD — Propuesta 1: aislamiento de agentes (OpenShift)

GitOps de la propuesta 1. Argo CD = OpenShift GitOps (namespace `openshift-gitops`).

## Recursos

| Archivo | Recurso | Qué hace |
|---------|---------|----------|
| `appproject.yaml` | AppProject `black-alpaca-isolation` | acota repos/namespaces/recursos de esta propuesta |
| `applicationset.yaml` | ApplicationSet `isolation-postures` | genera una Application por postura (`isolation-bare`, `isolation-bare-np`, `isolation-ssh`, `isolation-kata`) |
| `application-sandboxed-containers.yaml` | Application `isolation-sandboxed-containers` | instala el operator Kata (sync-wave -1) |

## Orden de despliegue (sync-waves)

```
-1  isolation-sandboxed-containers   (operator Kata → crea el RuntimeClass "kata")
 0  isolation-bare, isolation-bare-np, isolation-ssh   (sin dependencias)
 1  isolation-kata   (necesita el RuntimeClass "kata" del operator)
```

## Desplegar

```bash
oc apply -f appproject.yaml
oc apply -f application-sandboxed-containers.yaml
oc apply -f applicationset.yaml
```

> ⚠️ El operator Kata aplica un `KataConfig` que **reinicia los nodos worker**. No es inocuo.
> La `repoURL` es un placeholder al repo de la charla — ajustar al publicarlo.

## Nomenclatura

- AppProject: `black-alpaca-isolation`
- Applications: `isolation-<component>` (kebab-case, inglés)
- Labels estándar: `app.kubernetes.io/part-of: black-alpaca-2026`, `black-alpaca.session: "1-isolation"`
