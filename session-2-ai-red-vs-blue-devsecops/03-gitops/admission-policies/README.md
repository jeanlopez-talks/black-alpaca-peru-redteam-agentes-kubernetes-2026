# Admission policies (Kyverno) — la capa que sí frena el ataque

Dos policies **namespaced** (API CEL `policies.kyverno.io/v1`) que solo aplican en
`devsecops-duel`: no pueden afectar al resto del clúster. Las sincroniza la Application
`ai-red-vs-blue-devsecops-admission-policies` (ola -1), que también crea el namespace con
Pod Security, así que las policies existen antes que cualquier pod.

| Archivo | Policy | Rol en la demo |
|---------|--------|----------------|
| `namespacedvalidatingpolicy-require-human-approval.yaml` | `duel-require-human-approval` | **Frena el ataque**: exige `duel.redteam/human-approved: "true"` en los Deployment |
| `namespacedimagevalidatingpolicy-verify-images.yaml` | `duel-verify-images` | Verifica la firma cosign de `registry.labjp.xyz/devsecops-duel/*`; **no** frena este ataque |

Ambas con `validationActions: [Deny]` y `failurePolicy: Fail` (si Kyverno no responde, se
rechaza: *fail-closed*).

## Por qué una frena y la otra no

- El PR envenenado modifica **config** (`config/deploy-notes.md`), no la imagen. La imagen
  se firma y verifica correctamente: la firma es necesaria, pero no suficiente.
- La aprobación humana es una anotación que el agente **no puede poner**: el `duel-runner`
  no tiene token de API ni RBAC (`../devsecops-pipeline/base/serviceaccount-duel-runner.yaml`).

> Una capa falla, la otra atrapa.

## Limitación documentada

La firma se hace con clave y **sin log de transparencia** (`--tlog-upload=false`), porque
el homelab no tiene un Rekor propio; la policy ignora el tlog de forma explícita. En
producción: firma *keyless* (OIDC) con Rekor.

La clave pública debe coincidir con el Secret `duel-cosign-keys` del pipeline (ver
`../devsecops-pipeline/README.md`, «Clave cosign»).
