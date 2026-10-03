# Agentes del duelo (A2A)

Tres agentes de IA que se comunican por **A2A** (protocolo Agent2Agent, `a2a-sdk` 1.2):

| Agente | Rol A2A | Skills | Qué hace en la demo |
|--------|---------|--------|---------------------|
| `blue-reviewer` | servidor | `review-pr` | Revisa el diff de un PR y decide APPROVE o BLOCK. Postura vulnerable o endurecida (`BLUE_HARDENED`). |
| `red-attacker` | cliente | — | Abre los PRs del ataque y se los envía al azul. Fuente única de los diffs. |
| `approval-agent` | servidor | `summarize-pipeline`, `propose-actions`, `execute-action` | Asistente del humano en Backstage: resume el pipeline, propone acciones y solo ejecuta con token humano. |

```
04-ai-agents/
├── pyproject.toml, uv.lock     dependencias (rangos) + versiones exactas
├── Containerfile               una imagen, un entrypoint por agente
├── src/devsecops_agents/
│   ├── common/                 llm.py (fábrica única), a2a_server.py, a2a_client.py
│   ├── blue_reviewer/          review.py (reglas + LLM), server.py (AgentCard + executor)
│   ├── red_attacker/           payloads.py (PRs), attacker.py (cliente A2A), CLI
│   ├── approval_agent/         cluster.py (lectura), actions.py (puerta humana), narrative.py, server.py
│   └── duel/                   orquestador de los Actos 1-4, siempre por A2A
├── tests/                      reglas, puerta humana y A2A real (servidores locales)
├── results/                    duel-results.json
└── evidence/                   ejecuciones reales en clúster (no se reescriben)
```

## Uso

```bash
uv sync                          # entorno con las versiones exactas del lock
uv run pytest                    # 17 tests, incluido el ida y vuelta A2A
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
