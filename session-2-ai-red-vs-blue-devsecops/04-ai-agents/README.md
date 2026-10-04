# Agentes del duelo (A2A)

Cuatro agentes de IA que se comunican por **A2A** (protocolo Agent2Agent, `a2a-sdk` 1.2):

| Agente | Rol A2A | Skills | Qué hace en la demo |
|--------|---------|--------|---------------------|
| `blue-reviewer` | servidor | `review-pr` | Revisa el diff de un PR y decide APPROVE o BLOCK. Postura vulnerable o endurecida (`BLUE_HARDENED`). |
| `red-attacker` | cliente | — | Abre los PRs del ataque y se los envía al azul. Fuente única de los diffs. |
| `approval-agent` | servidor | `summarize-pipeline`, `propose-actions`, `execute-action` | Asistente del humano en Backstage: resume el pipeline, propone acciones y solo ejecuta con token humano. |
| `remediation-agent` | servidor (dos puertos) | `advise` (:8081, pipeline); `latest-report`, `chat`, `confirm-action`, `cancel-action` (:8080, Backstage) | Convierte los hallazgos de Trivy en recomendaciones priorizadas con su lineamiento (leído por MCP), conversa en Backstage y solo sube la corrección a una rama `remediation/*` cuando la persona pulsa Confirmar. |

```
04-ai-agents/
├── pyproject.toml, uv.lock     dependencias (rangos) + versiones exactas
├── Containerfile               una imagen, un entrypoint por agente
├── src/devsecops_agents/
│   ├── common/                 llm.py (fábrica única), a2a_server.py, a2a_client.py
│   ├── blue_reviewer/          review.py (reglas + LLM), server.py (AgentCard + executor)
│   ├── red_attacker/           payloads.py (PRs), attacker.py (cliente A2A), CLI
│   ├── approval_agent/         cluster.py (lectura), actions.py (puerta humana), narrative.py, server.py
│   ├── remediation_agent/      analysis.py (Trivy → recomendaciones), guidelines.py (MCP), policies.py (Acto 5),
│   │                           conversation.py (chat + confirmación), apply.py (rama), request.py (CLI del pipeline)
│   └── duel/                   orquestador de los Actos 1-4, siempre por A2A
├── tests/                      reglas, puerta humana y A2A real (servidores locales)
├── results/                    duel-results.json
└── evidence/                   ejecuciones reales en clúster (no se reescriben)
```

## Uso

```bash
uv sync                          # entorno con las versiones exactas del lock
uv run pytest                    # 39 tests, incluido el ida y vuelta A2A
uv run ruff check src tests      # lint (incluye reglas de seguridad de Bandit)
uv run run-duel                  # los 4 actos por A2A -> results/duel-results.json
uv run run-duel --llm            # azul con LLM (vLLM local); sin LLM cae a reglas
```

Resultado esperado: Acto 1 BLOCK, Acto 2/3 APPROVE (el atacante gana a través del azul),
Acto 4 BLOCK (el azul endurecido trata el diff como dato no confiable).

## Publicar una versión

La imagen la construye el CI de la plataforma (homelab-pipelines) **por versión**:

```bash
# 1. Sube la versión en pyproject.toml y en los manifiestos (:0.1.0 -> :0.2.0)
# 2. Etiqueta y empuja: el webhook dispara el build
git tag agents-v0.2.0 && git push origin agents-v0.2.0
```

El CI verifica (uv, ruff, pytest), construye y publica
`ghcr.io/labjp-homelab/devsecops-agents:<versión>`, firmada y con provenance SLSA por
Tekton Chains. No escribe en este repo: no tiene ninguna credencial para hacerlo.

## Contrato A2A

- AgentCard en `/.well-known/agent-card.json`; JSON-RPC en `/`; `/healthz` para Kubernetes.
- `blue-reviewer`: el mensaje es el diff; la respuesta, el veredicto en JSON.
- `approval-agent`: el mensaje es un JSON `{"skill": ...}`. `execute-action` exige el
  esquema de seguridad `human-approval` declarado en la AgentCard: el token viaja en
  `X-Human-Approval` (Backstage ya usa `Authorization` para su usuario), **nunca** dentro del mensaje, y se compara en tiempo constante.
- `remediation-agent`: el mensaje es un JSON `{"skill": ...}` (en el puerto de Backstage, un
  texto plano es un mensaje de chat). Dos puertas separadas por NetworkPolicy: el pipeline,
  que ejecuta código no confiable del PR, solo alcanza `advise` (:8081); la conversación y
  `confirm-action` solo se alcanzan desde Backstage (:8080).
  - El análisis es determinista: versiones, CVE y conteos salen de Trivy, nunca del modelo.
  - Cada hallazgo de configuración se ata a su regla por ID (`AVD-DS-0002` → `POD-101`) y el
    agente la lee del catálogo con `backstage_catalog.get-catalog-entity`, vía agentgateway
    con su propio cliente de Keycloak y la relación `can_call` de OpenFGA.
  - Defensa del Acto 5: cada lineamiento leído del catálogo se contrasta con la
    ValidatingPolicy que Kyverno aplica (leída del clúster; qué política corresponde lo fija
    el código, no el catálogo). Si no coinciden, el informe avisa de posible envenenamiento
    y manda la política. El diff nunca sale del texto del catálogo.
  - El modelo solo conversa. Pedir "aplica R1" prepara una acción pendiente con el diff
    exacto; solo `confirm-action` (el botón de Backstage), en la misma conversación y antes
    de 15 minutos, la ejecuta. Nada del chat, del Containerfile ni de Trivy puede confirmarla.
  - Aplicar = subir la rama `remediation/<run>` con el cambio (deploy key solo de este repo;
    `main` protegida). El PR y el merge son de la persona; el despliegue sigue por GitOps.

## Seguridad

- Ningún agente tiene permisos de escritura. El de aprobación lee PipelineRun/TaskRun con
  un Role acotado al namespace del duelo, y Argo CD con un token de rol de proyecto de
  solo lectura.
- El LLM local (vLLM) no necesita clave; los proveedores externos la reciben por entorno
  desde un Secret, nunca en el código.
- Imagen: bases fijadas por digest, dependencias `--frozen`, uid 1001, compatible con
  raíz de solo lectura.
- La vulnerabilidad del azul (obedecer una nota del diff) es **deliberada**: es lo que
  demuestra la charla.
