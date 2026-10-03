# Admission policies (Kyverno) — la capa que sí frena el ataque

Dos `ClusterPolicy` que se aplican cuando Argo CD despliega la app de ejemplo en
`openclaw-duel`. Las sincroniza la Application `ai-red-vs-blue-devsecops-admission-policies`
(`../argocd/application-admission-policies.yaml`, sync-wave -1: deben existir antes del deploy).

| Archivo | Policy | Modo | Rol en la demo |
|---------|--------|------|----------------|
| `clusterpolicy-require-human-approval.yaml` | `duel-require-human-approval` | Enforce | **Frena el ataque**: exige la anotación `duel.redteam/human-approved: "true"` en los Deployment del namespace |
| `clusterpolicy-verify-images.yaml` | `duel-verify-images` | Enforce | Verifica la firma cosign de las imágenes de Zot (`zot.registry.svc.cluster.local:5000/openclaw-duel/*`); **no** frena este ataque |

## Por qué una frena y la otra no

- El PR envenenado modifica **config** (`config/deploy-notes.md`), no el código de la imagen.
  La imagen se construye, firma y verifica correctamente: `verifyImages` la **admite**.
  La firma es necesaria, pero no suficiente.
- La aprobación humana es una anotación que el agente **no puede poner**: el
  `duel-runner` no tiene token de API ni RBAC (ver `../devsecops-pipeline/base/serviceaccount-duel-runner.yaml`).
  Sin ella, Kyverno **rechaza** el Deployment aunque el azul haya aprobado.

> La firma no ayuda contra este ataque porque el atacante no tocó la imagen; lo frena la
> policy de admisión que exige aprobación humana. Una capa falla, la otra atrapa.

## Requisitos de plataforma (no se instalan desde este repo)

- **Kyverno** (webhook de admisión), gestionado por la plataforma.
- El registry Zot es HTTP interno: el `kyverno-admission-controller` necesita el flag
  `--allowInsecureRegistry=true` para que `verifyImages` lo consulte (en Kyverno 1.13
  no existe una opción por policy).
- La clave pública de `clusterpolicy-verify-images.yaml` debe coincidir con el Secret
  `duel-cosign-keys` que usa el pipeline (ver `../devsecops-pipeline/README.md`, «Clave cosign»).
