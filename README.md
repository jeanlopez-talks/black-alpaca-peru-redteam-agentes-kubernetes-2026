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
│   └── 04-attack-lab/                  # ataques y medición: privilege-escalation/ (8 vectores), boundary-probes/
│
├── session-2-ai-red-vs-blue-devsecops/                 # PROPUESTA 2 — rojo vs azul en el pipeline DevSecOps
│   ├── 01-proposal/                    # sessionize-proposal.md, concept.md (4 actos)
│   ├── 02-slides/
│   ├── 03-gitops/                      # Argo CD: devsecops-pipeline/ (Tekton 8 etapas), admission-policies/ (Kyverno), backstage/
│   └── 04-ai-agents/                   # red-blue-agents/ (A2A + cluster-evidence/), backstage-agent/
│
├── shared/                         # común a ambas
│   ├── classifier/                     # clasificador de prompt injection (resultados propios)
│   ├── lab-conventions.md              # contrato de nombres/valores del laboratorio
│   ├── gitops-architecture.md          # plataforma (repo homelab) vs config de demo (este repo)
│   ├── event-research-2025.md          # contexto de la edición anterior
│   └── slides-index.html               # portada que enlaza ambas presentaciones
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
| Duelo rojo vs azul + supply chain real | 2 | ✅ **corrió en k3s** (Zot + cosign + Kyverno) — `session-2-ai-red-vs-blue-devsecops/04-ai-agents/red-blue-agents/cluster-evidence/` |
| 4 posturas (manifiestos + Argo CD) | 1 | ✅ validados (kustomize + dry-run) · ⏳ falta desplegar y correr la matriz |
| Documento técnico + one-pager | 1 | ✅ escritos · ⏳ falta exportar one-pager a PDF |

> El material de las charlas **no está desplegado en el clúster** por ahora: vive solo en Git. Las
> Applications de `03-gitops/argocd/` están listas para cuando se decida desplegarlo.

## Cómo reproducir

```bash
# Clasificador (laptop, sin clúster) — sesión 1 y 2
cd shared/classifier && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt && python run_classifier.py

# Duelo rojo vs azul (laptop, modo rules) — sesión 2
cd session-2-ai-red-vs-blue-devsecops/04-ai-agents/red-blue-agents && python3 run_duel.py

# Duelo en k3s (Tekton) — sesión 2. Requiere Tekton, Zot y Kyverno (plataforma del homelab).
kubectl create namespace openclaw-duel
cosign generate-key-pair k8s://openclaw-duel/duel-cosign-keys   # la clave nunca va a Git
kubectl apply -k session-2-ai-red-vs-blue-devsecops/03-gitops/devsecops-pipeline/

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
