# Red-teaming de agentes de IA en Kubernetes — Black Alpaca 2026

[![Estado](https://img.shields.io/badge/estado-propuestas%20CFP-orange)]()
[![Evento](https://img.shields.io/badge/Black%20Alpaca-2026-black)]()
[![GitOps](https://img.shields.io/badge/deploy-Argo%20CD-blue)]()

Material y laboratorio reproducible de **dos propuestas de charla** para Black Alpaca 2026
(CiberSecUNI, Lima, 14 nov 2026). El CFP permite **2 submissions por speaker** — enviamos ambas.

> **Hilo común:** el rechazo del modelo (*refusal*) no es un límite de contención. Un prompt injection
> exitoso lo salta; lo que detiene al atacante es la **infraestructura**. Este repo lo mide, no lo supone.

---

## Las dos propuestas

### 🟢 Sesión 1 — Cuando el modelo deja de rechazar *(el agente como víctima)*
Red-teaming de un agente de IA desplegado en Kubernetes. 8 vectores de escalada de privilegios × 4 posturas
de aislamiento (`bare`, `bare-np`, `ssh`, `kata`) × 6 fronteras medidas con tokens canario. Hallazgos:
la mediación de escritura falla en `ssh`/`kata`, la persistencia de workspace falla en las 4 (OWASP ASI06).
→ **[`session-1-ai-agent-isolation/`](session-1-ai-agent-isolation/)**

### 🔴🔵 Sesión 2 — Rojo vs Azul, los dos son IA *(el agente como actor en el pipeline)*
Un duelo DevSecOps: un agente rojo abre PRs maliciosos, un agente azul (revisor LLM) decide el merge.
El rojo envenena al azul con prompt injection en el diff → el defensor **aprueba el ataque solo** y GitOps lo
despliega. El cierre: qué fronteras de infraestructura lo habrían parado.
→ **[`session-2-ai-red-vs-blue-devsecops/`](session-2-ai-red-vs-blue-devsecops/)**

> **Complementarias, no redundantes:** la 1 protege al agente; la 2 muestra qué pasa cuando el agente
> defiende y lo engañan. Si el comité acepta ambas, forman una narrativa.

---

## Estructura del repo

Agrupado **por sesión**; cada sesión numerada en orden de flujo. Lo que usan ambas va en `shared/`.

```
.
├── session-1-ai-agent-isolation/            # PROPUESTA 1 — el agente como víctima
│   ├── 01-proposal/                    # sessionize-proposal.md, technical-paper.md, one-pager.md (→ PDF)
│   ├── 02-slides/                      # presentación HTML offline
│   ├── 03-gitops/                      # Argo CD: AppProject + ApplicationSet, isolation-postures/ (4), operator Kata
│   └── 04-attack-lab/                  # lab-conventions.md (contrato), privilege-escalation/ (8 vectores), boundary-probes/
│
├── session-2-ai-red-vs-blue-devsecops/                 # PROPUESTA 2 — rojo vs azul en el pipeline DevSecOps
│   ├── 01-proposal/                    # sessionize-proposal.md, concept.md (4 actos)
│   ├── 02-slides/
│   ├── 03-gitops/                      # devsecops-pipeline/ (Tekton 8 etapas, un PipelineRun por acto), admission-policies/ (Kyverno), backstage/
│   └── 04-ai-agents/                   # agentes A2A (uv): azul, rojo y aprobación + evidence/
│
├── shared/                         # común a ambas
│   ├── classifier/                     # clasificador de prompt injection (resultados propios)
│   ├── gitops-architecture.md          # plataforma (repo homelab) vs config de demo (este repo)
│   ├── platform-architecture.html      # diagrama: qué vive en el clúster y qué fuera, con los flujos
│   ├── event-research-2025.md          # contexto de la edición anterior
│   └── slides-index.html               # portada que enlaza ambas presentaciones
├── backlog.md                      # ideas y trabajo pendiente, por épica y prioridad
└── README.md
```

`03-gitops` es el estado declarativo (lo que se despliega: las víctimas y el pipeline); `04-*` es lo
imperativo: en la sesión 1 los ataques que se lanzan contra ese despliegue, en la sesión 2 el código de los agentes.

## Estado de cada pieza

| Pieza | Sesión | Estado |
|-------|:------:|--------|
| Propuesta Sessionize (campos) | 1 y 2 | ✅ lista para pegar |
| Clasificador de prompt injection | 1 y 2 | ✅ **ejecutado** — `shared/classifier/results.json` (0.999999 → 0.00048) |
| Slides HTML | 1 y 2 | ✅ offline |
| Duelo rojo vs azul + supply chain real | 2 | ✅ **corrió en k3s** (Zot + cosign + Kyverno) — `session-2-ai-red-vs-blue-devsecops/04-ai-agents/evidence/` |
| 4 posturas (manifiestos + Argo CD) | 1 | ✅ validados (kustomize + dry-run) · ⏳ falta desplegar y correr la matriz |
| Documento técnico + one-pager | 1 | ✅ escritos · ⏳ falta exportar one-pager a PDF |

> La demo de la sesión 2 la despliega el **Argo CD del homelab**: su AppProject y sus Applications
> viven en `homelab-gitops` (`bootstrap/applications/talks/black-alpaca-2026/`), para que este repo
> no pueda ampliar sus propios permisos. La sesión 1 (OpenShift) sigue solo en Git.

## Cómo reproducir

```bash
# Clasificador (laptop, sin clúster) — sesión 1 y 2
cd shared/classifier && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt && python run_classifier.py

# Duelo rojo vs azul (laptop, modo rules) — sesión 2
cd session-2-ai-red-vs-blue-devsecops/04-ai-agents && uv run run-duel   # los 4 actos por A2A

# Duelo en k3s (Tekton + Argo CD del homelab) — sesión 2: un PipelineRun por acto, sync manual.
argocd app sync ai-red-vs-blue-devsecops-pipeline-runs \
  --resource tekton.dev:PipelineRun:duel-act3-poisoned-pr

# Las 4 posturas con Argo CD — sesión 1
kubectl apply -f session-1-ai-agent-isolation/03-gitops/argocd/
for p in bare bare-np ssh kata; do session-1-ai-agent-isolation/04-attack-lab/boundary-probes/collect-results.sh "$p"; done
```

## Crédito y honestidad

Metodología de aislamiento de referencia: **Roy Belio (Red Hat)**, *"Which Controls Still Matter When the
Model Stops Refusing?"* (AGNTCon+MCPCon Europe 2026), reencuadrada en clave ofensiva **con laboratorio y
resultados propios**. El ataque de los 3,000M de tokens es caso de estudio **citado, nunca replicado**.

## Licencia

Material educativo para una charla de seguridad autorizada. Ver [`LICENSE`](LICENSE).
