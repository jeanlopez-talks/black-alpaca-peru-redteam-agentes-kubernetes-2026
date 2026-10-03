# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Nomenclatura (OBLIGATORIA para crear cualquier cosa)

Al crear carpetas, archivos, recursos de Kubernetes, namespaces, Applications de Argo CD,
pipelines, imágenes, variables, etc., usar SIEMPRE una nomenclatura **correcta, estandarizada y en inglés**:

- **Idioma: inglés** para TODO nombre de artefacto técnico (carpetas, archivos, recursos k8s, labels,
  ramas, identificadores). El contenido/documentación narrativa puede ir en español; los **nombres** no.
- **Estilo**: `kebab-case` para carpetas, archivos y nombres de recursos k8s (ej. `supply-chain`,
  `blue-agent`, `require-human-approval`). `snake_case` para variables/módulos Python. `PascalCase` para
  clases. Constantes en `SCREAMING_SNAKE_CASE`.
- **Descriptivo y consistente**: el nombre dice qué es (`pipeline-devsecops.yaml`, no `pipe2.yaml`).
  Mismo concepto → mismo nombre en todo el repo. Prefijos de orden solo si aportan (`01-`, `02-`).
- **Recursos k8s**: namespaces y objetos en kebab-case inglés; labels estándar
  `app.kubernetes.io/part-of`, `app.kubernetes.io/component`. Applications de Argo CD con nombre
  `<project>-<component>` (ej. `ai-red-vs-blue-devsecops-pipeline`, `ai-red-vs-blue-devsecops-backstage-agent`).
- **Nada de espacios, acentos, mayúsculas ni caracteres especiales** en nombres de archivos/carpetas.

> Esta regla aplica a todo lo que se cree de aquí en adelante. Si encuentras nombres viejos que no la
> cumplen, renómbralos al tocarlos (ajustando las referencias).

## Qué es este repositorio

Es el material de **dos propuestas de charla** para Black Alpaca 2026 (conferencia de seguridad ofensiva, CiberSecUNI, Lima, 14 nov 2026). Contiene propuestas y documentos (Markdown en español), slides HTML, manifiestos GitOps (Argo CD, Tekton, Kyverno) y el código del laboratorio (Python/Bash). No hay build ni tests a nivel de repo.

Charla: *"¿Qué controles siguen importando cuando el modelo deja de rechazar? Red-teaming de agentes de IA en Kubernetes"*.

## Estructura y rol de cada archivo

**SON DOS PROPUESTAS** (el CFP permite 2 por speaker). La raíz se agrupa **por sesión**; todo lo de una
propuesta vive dentro de su carpeta, y solo lo que usan ambas va en `shared/`:

```
session-1-ai-agent-isolation/      PROPUESTA 1 — agente como víctima (aislamiento, 8 vectores, 4 posturas)
  01-proposal/            sessionize-proposal.md, technical-paper.md, one-pager.md (→ PDF adjunto)
  02-slides/              index.html
  03-gitops/              argocd/, operators/sandboxed-containers/, isolation-postures/{bare,bare-np,ssh,kata}/
  04-attack-lab/          privilege-escalation/ (8 vectores), boundary-probes/ (fronteras + collect-results.sh → results/)
session-2-ai-red-vs-blue-devsecops/           PROPUESTA 2 — duelo rojo vs azul en pipeline DevSecOps
  01-proposal/            sessionize-proposal.md, concept.md (diseño en 4 actos)
  02-slides/              index.html
  03-gitops/              argocd/, devsecops-pipeline/ (base, tekton, sample-app, fixtures), admission-policies/, backstage/
  04-ai-agents/           paquete Python (uv) de los 3 agentes A2A: blue_reviewer, red_attacker,
                          approval_agent (+ duel/, tests/, evidence/, Containerfile)
shared/                   classifier/ (ambas), lab-conventions.md, gitops-architecture.md,
                          event-research-2025.md, slides-index.html (portada de ambas)
```

- Las carpetas de sesión van numeradas en orden de flujo: propuesta → slides → despliegue (`03-gitops`,
  estado declarativo: las víctimas/el pipeline) → lo imperativo (`04-attack-lab` en la sesión 1: ataques y medición;
  `04-ai-agents` en la sesión 2: código de los agentes). No duplica GitOps.
- Nombres de carpeta que digan qué contienen (`privilege-escalation`, no `escalation`; `approval-agent`, no `agent`).
- **Rutas siempre relativas** al archivo que las menciona (`../04-ai-agents/src/`), nunca desde la raíz, para que
  mover carpetas no rompa referencias. Única excepción: el campo `path:` de las Applications de Argo CD,
  que por diseño es relativo a la raíz del repo.
- Algo nuevo va en la carpeta de su sesión; a `shared/` solo si lo usan las dos.
- El material de las charlas **no se despliega en el clúster por ahora**: se versiona en Git solamente.
  La plataforma (registry, Backstage, Tekton, Kyverno) vive en el repo del homelab (ver `shared/gitops-architecture.md`).
- Secretos: nunca en Git. La clave cosign del duelo se genera fuera (`cosign generate-key-pair k8s://...`);
  copias locales van en archivos `*-secret.local.yaml` (ignorados).

## Reglas de contenido (no negociables para este repo)

- **Toda afirmación técnica se verifica contra la fuente antes de escribirla en una diapositiva o documento.** La metodología, el caso del ataque de mayo 2026, los 8 vectores de escalada y los resultados de las 4 posturas provienen del estudio de Roy Belio (Red Hat), AGNTCon+MCPCon Europe 2026 — citado como fuente primaria. Dar crédito explícito; nunca presentar ese trabajo como propio no atribuido.
- **Los números del estudio de referencia no son resultados propios hasta ejecutar el laboratorio en infraestructura propia.** Si al replicar un resultado difiere, se presenta el resultado propio, no el ajeno. El ataque de los 3,000M de tokens se narra como caso de estudio citado — nunca se replica.
- El CFP **rechaza** propuestas sin esquema detallado, descripción completa y bio completa, y **da preferencia** a quien adjunta documento técnico y diapositivas. Mantener esos cuatro elementos completos en cada `session-*/01-proposal/sessionize-proposal.md`. Campos reales del formulario (verificado logueado): Title (máx 100 car.), Description (privada), Abstract (público ≤300 palabras), Talk Teaser (≤240 car.), Supporting Files (1 archivo 50 MB), selects Session format (Session=50 min)/Track(Community)/Level/Language. NO hay campo de tags.
- Audiencia de ataque real (pentest/red team): el criterio es "esto se puede reproducir y romper algo", no "arquitectura interesante". Nivel intermedio-avanzado: no explicar Kubernetes, contenedores ni LLMs desde cero.

## Hechos técnicos de referencia rápida

- 4 posturas de aislamiento: `bare`, `bare-np` (con NetworkPolicy), `ssh` (sandbox vía SSH/runc), `kata` (OpenShift, microVM). 6 fronteras medidas por postura.
- Hallazgos incómodos (centrales a la charla): mediación de escritura de herramientas **falla en `ssh` y `kata`**; persistencia en el workspace **falla en las 4 posturas** (mapea a OWASP ASI06).
- Separación de namespaces del blueprint: `openclaw-gateway` (credenciales) vs. `openclaw-sandbox` (uid 1000, sin credenciales) — usar esos nombres al escribir manifiestos. (sesión 1)
- Sesión 2: `devsecops-duel` (pipeline + agente rojo, carga no confiable, sin credenciales) vs. `devsecops-agent` (agente con tokens). Secretos solo por `ExternalSecret` desde un `SecretStore` propio con rol de OpenBao acotado a `apps/black-alpaca/*`; nunca el `ClusterSecretStore` global ni `Secret` versionados.

## Fechas (confirmadas, no recalcular)

CFP cierra 5 oct 2026, 23:59 EDT = 10:59 PM Lima. Notificación a speakers: 12 oct 2026. Evento: 14 nov 2026.

## Convenciones

- Contenido en **español** con ortografía y acentos correctos. Identificadores técnicos (`bare-np`, `nsenter`, `CAP_SETUID`) en su forma original.
- Commits en inglés, conventional commits. Los commits son de Jean Lopez.
