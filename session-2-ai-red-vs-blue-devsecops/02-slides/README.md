# Charla 2 — Rojo vs Azul, los dos son IA

Presentación HTML autocontenida (un solo archivo, sin CDN, abre offline) para la
charla 2 de Black Alpaca 2026: _"Agentes ofensivos y defensivos en tu pipeline DevSecOps"_.

## Abrir

Doble clic en `index.html`, o:

```bash
open index.html          # macOS
xdg-open index.html      # Linux
```

No necesita servidor ni dependencias. Para proyectar: tecla `F` (pantalla completa).

## Controles

| Tecla | Acción |
|-------|--------|
| `←` / `→` (o `espacio`, `PageUp/Down`) | navegar entre slides |
| `N` | mostrar/ocultar **notas del ponente** (con reparto de tiempo) |
| `F` | pantalla completa |
| `Home` / `End` | primera / última slide |

También soporta swipe en pantalla táctil y saltar a una slide con `#N` en la URL
(ej. `index.html#5`).

## Exportar a PDF

1. Abrir `index.html` en Chrome.
2. `Cmd/Ctrl + P` → **Guardar como PDF**.
3. Recomendado: **Horizontal (Landscape)**, márgenes **Ninguno**, activar
   **Gráficos de fondo** (para que salgan los colores y el fondo negro).

El modo impresión apila automáticamente todas las slides, una por página. Las
notas del ponente no se incluyen en el PDF.

## Estructura

11 slides siguiendo el esqueleto de 50 min:
portada · pitch inocente · reglas del duelo (agentes LangChain por A2A dentro de
Tekton: rojo=client/step, azul=server/sidecar) · arquitectura de los agentes
(LangChain + A2A + AgentCard, modos `rules`/`llm`) · Acto 1 (azul gana) ·
Acto 2a (evasión del clasificador) · Acto 2b (diff envenenado) ·
Acto 3 (azul traiciona + egress 443 = nueva superficie) · Acto 4 (fronteras de
infra) · checklist + lab (ya ejecutado en OpenShift 4.22 real) · gracias.

La arquitectura reflejada es la **ya construida y probada**: agentes reales
(langgraph `create_react_agent` + tools) que se comunican por **A2A**
(`a2a-sdk`), el azul como A2A server (AgentCard skill `review-pr`) y el rojo como
A2A client, corriendo en Tekton (azul=sidecar, rojo=step; `merge-deploy` solo si
`decision == APPROVE`). Ver `../04-ai-agents/red-blue-agents/README.md` y `../03-gitops/devsecops-pipeline/README.md`.
