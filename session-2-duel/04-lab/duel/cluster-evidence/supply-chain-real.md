# Evidencia: supply chain REAL contra el registry Zot (k3s appserver02)

**Fecha:** 3 oct 2026. **Namespace:** openclaw-duel. **Registry:** zot.registry.svc.cluster.local:5000.

## PipelineRun duel-devsecops-poisoned → COMPLETED (8 etapas)

```
sast ✅  build ✅  sbom ✅  trivy-scan ✅  sign ✅  gate-blue ✅  verify ✅  deploy-gitops ✅
```

Todo el supply chain opera contra el REGISTRY INTERNO Zot (ya no tar/blob simulado):

## 1. build — kaniko PUSH real a Zot
kaniko construye la imagen y la empuja a zot.registry.svc:5000/openclaw-duel/sample-app:latest
(--insecure --skip-tls-verify; Zot con compat ["docker2s2"] para aceptar el manifiesto Docker v2).
Digest producido: sha256:83aed8d7f6d9f2beca98852967709c3724bf3406f1fc977b3504ae62f19e75db

## 2. sign — cosign firma la IMAGEN por digest
cosign sign ...sample-app@sha256:83aed8... con la clave del duelo. La firma se sube a Zot como
artefacto OCI. Verificado en el registry:
```
GET /v2/openclaw-duel/sample-app/tags/list
{"name":"openclaw-duel/sample-app","tags":["latest","sha256-83aed8...-.sig"]}
```
→ la imagen Y su firma (.sig) viven en el registry.

## 3. verify — cosign verifica la firma de la imagen del registry
```
Verification for zot.../sample-app@sha256:83aed8... --
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```
→ verificación REAL por digest, no blob.

## 4. gate-blue — el agente cae (el ataque pasa)
```
[blue] (A2A) motor=rules decision=APPROVE (prompt injection indirecta — fallo deliberado)
[rojo] el AZUL (A2A server) respondio: APPROVE
```

## Defensa en capas (narrativa, ahora REAL)
- La cadena de supply chain es real: push/firma/scan/verify contra el registry.
- PERO el PR envenenado toca CONFIG, no la imagen → la imagen firma y verifica OK →
  Kyverno verifyImages (Enforce) la ADMITE. La firma real NO frena este ataque.
- Lo que lo atrapa es la OTRA policy Kyverno (require-human-approval): exige una anotación
  que el agente no puede poner. Defensa en capas de verdad.

## Componentes
- Registry: Zot v2.1.21 (homelab-gitops/components/platform/registry), compat docker2s2.
- Kyverno 1.13.4 con --allowInsecureRegistry=true (registry HTTP interno).
- Tekton tip: los $(...) en COMENTARIOS de un script: también los parsea Tekton como
  variables → "non-existent variable". No poner $(...) en comentarios de scripts.
