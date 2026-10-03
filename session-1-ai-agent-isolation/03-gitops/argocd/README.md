# Argo CD — Propuesta 1: aislamiento de agentes (OpenShift)

GitOps de la propuesta 1. Argo CD = OpenShift GitOps (namespace `openshift-gitops`).

## Recursos

| Archivo | Recurso | Qué hace |
|---------|---------|----------|
| `appproject-ai-agent-isolation.yaml` | AppProject `ai-agent-isolation` | acota repos/namespaces/recursos de esta propuesta |
| `applicationset-isolation-postures.yaml` | ApplicationSet `ai-agent-isolation-postures` | genera una Application por postura (`ai-agent-isolation-bare`, `ai-agent-isolation-bare-np`, `ai-agent-isolation-ssh`, `ai-agent-isolation-kata`) |
| `application-sandboxed-containers.yaml` | Application `ai-agent-isolation-sandboxed-containers` | instala el operator Kata (sync-wave -1) |

## Orden de despliegue (sync-waves)

```
-1  ai-agent-isolation-sandboxed-containers   (operator Kata → crea el RuntimeClass "kata")
 0  ai-agent-isolation-bare, ai-agent-isolation-bare-np, ai-agent-isolation-ssh   (sin dependencias)
 1  ai-agent-isolation-kata   (necesita el RuntimeClass "kata" del operator)
```

## Desplegar

```bash
oc apply -f appproject-ai-agent-isolation.yaml
oc apply -f application-sandboxed-containers.yaml
oc apply -f applicationset-isolation-postures.yaml
```

> ⚠️ El operator Kata aplica un `KataConfig` que **reinicia los nodos worker**. No es inocuo.
> El repo es **privado**: Argo CD necesita credenciales de solo lectura registradas para este `repoURL`.

## Nomenclatura

- AppProject: `ai-agent-isolation`
- Applications: `isolation-<component>` (kebab-case, inglés)
- Labels estándar: `app.kubernetes.io/part-of: black-alpaca-2026`, `black-alpaca.session: "1-isolation"`
