# Propuesta 2 (Sessionize) — Atacar y gobernar agentes de IA en el pipeline DevSecOps

> Segunda submission para Black Alpaca 2026 (el CFP permite 2 por speaker). Campos
> mapeados contra el formulario real de Sessionize. Diseño técnico en `concept.md`.

---

## Campos del formulario

### Session Title — *máx 100 caracteres*
```
Tu agente de IA es un insider: cómo atacarlo y cómo gobernarlo en tu pipeline DevSecOps
```

Variante:
```
Engañé a tu IA defensiva y a ti con ella: atacar y gobernar agentes en DevSecOps
```

### Description — *privada, para el comité*
```
Las empresas están metiendo agentes de IA en sus pipelines: revisores de PRs, gates de seguridad, asistentes que resumen y proponen despliegues. Cada uno es una identidad nueva con acceso a código, credenciales y producción, y casi nadie lo gobierna como tal. Esta charla lo ataca en vivo y luego muestra cómo se gobierna.

Parte ofensiva, sobre un pipeline real en Kubernetes (Tekton, Argo CD, Kyverno, cosign) con agentes que hablan por A2A. Un agente rojo abre PRs maliciosos contra un agente azul que los revisa. Primero el azul bloquea el ataque obvio. Después el rojo reencuadra el payload y el clasificador de prompt injection se desploma de 0.999999 a 0.0005 (medido por mí), e inyecta en el diff una instrucción para el revisor: el azul aprueba su propio ataque. El giro final: un tercer agente que asiste al humano en Backstage resume ese PR envenenado y le transmite la mentira, así que el "humano en el loop" también cae.

Parte defensiva: lo que aguanta no es un mejor prompt ni un humano mirando, sino gobernar a cada agente como una identidad de primera clase desde la plataforma. Cada agente corre en su propio sandbox sin token de API, con imagen firmada y verificada en admisión. Actúa con credenciales de vida corta, delegadas con token exchange (RFC 8693), y con permisos por tarea y por skill que decide OpenFGA detrás de un gateway de agentes. El atacante sigue entrando al agente, pero no tiene a dónde ir.

El laboratorio del duelo y la supply chain ya corre de punta a punta en un clúster k3s propio, con resultados medidos. Todo es GitOps y reproducible, y se publicará con la charla. La metodología de aislamiento parte del trabajo de Roy Belio (Red Hat), citado como fuente.
```

### Abstract — *público, ≤300 palabras*
```
Tu pipeline ya tiene agentes de IA: revisan PRs, deciden gates, resumen despliegues. Cada uno es una identidad con acceso a tu código y a producción. La pregunta ofensiva es obvia: ¿qué pasa cuando el atacante le habla al agente?

Lo muestro en vivo sobre un pipeline real en Kubernetes con agentes que se comunican por A2A. Un agente rojo abre pull requests maliciosos y un agente azul los revisa. Primero el azul gana. Después el rojo reencuadra el payload, el clasificador de prompt injection cae de 0.999999 a 0.0005 (números propios) y una instrucción escondida en el diff convence al revisor de aprobar su propio ataque. El cierre del ataque: el agente que asiste al humano le resume ese PR como "pre-aprobado por seguridad", y el humano en el loop también firma.

La segunda mitad responde qué aguanta, y no es un mejor prompt. Es gobernar a cada agente como una identidad de primera clase desde la plataforma: sandbox propio sin token de API, imagen firmada y verificada en admisión, credenciales de vida corta delegadas con token exchange (RFC 8693) y permisos por tarea y por skill decididos por OpenFGA detrás de un gateway de agentes. El atacante sigue convenciendo al agente, pero el agente ya no tiene a dónde ir.

Te llevas: cómo se envenena una cadena de agentes y al humano que confía en ellos, por qué los controles que leen texto del atacante son atacables, y un blueprint reproducible en GitOps para gobernar agentes en tu pipeline.

Nivel intermedio-avanzado. Se asume CI/CD y Kubernetes.
```

### Talk Teaser — *≤240 caracteres*
```
Tu revisor de PRs es una IA. Mi agente rojo lo convence de aprobar su propio ataque, y el asistente del humano le jura que es seguro. Luego lo gobierno: sandbox, identidad propia y permisos por tarea. Demo en vivo.
```

### Session format
```
Session (50 min)
```

### Track
```
Community
```

### Level
```
Intermediate / Advanced
```

### Language
```
Español
```

### Supporting Files
> El one-pager PDF de la propuesta, con enlace al repositorio del laboratorio.

---

## Esqueleto (50 min)

1. **(0-5)** Los agentes ya están en tu pipeline: cada uno es una identidad nueva.
2. **(5-10)** El escenario: pipeline DevSecOps real (Tekton, Argo CD, Kyverno, cosign) y tres agentes que hablan por A2A.
3. **(10-15)** Acto 1: el azul gana y bloquea el ataque obvio.
4. **(15-22)** Acto 2: evasión del clasificador (0.999999 → 0.0005) e inyección indirecta en el diff. El azul aprueba.
5. **(22-27)** Acto 3: la firma es válida y no ayuda, porque el ataque toca config, no la imagen.
6. **(27-32)** Acto 4: el asistente del humano en Backstage le resume la mentira y el humano aprueba.
7. **(32-45)** Gobernar agentes en vivo: sandbox e imagen firmada, identidad propia, token exchange (RFC 8693), permisos por tarea con OpenFGA detrás del gateway. El mismo ataque, ahora sin a dónde ir.
8. **(45-50)** Checklist para gobernar los agentes de tu pipeline. Preguntas.

---

## Relación con la propuesta 1

Son complementarias:
- Propuesta 1: el agente es la **víctima** a aislar (escalada, fronteras de runtime).
- Propuesta 2: el agente es una **identidad** dentro del pipeline que el atacante usa como insider, y la plataforma lo gobierna.

---

## Fuentes a citar (verificadas el 3 oct 2026)

- RFC 8693 y la cadena de actores para delegación de agentes: [AAIF, 1 oct 2026](https://aaif.io/blog/agent-identity-and-delegated-access-in-mcp-systems).
- Caso MoonPay (200+ servidores MCP, 60 000+ sesiones, gateway OAuth 2.1 + PKCE). Es un caso firmado por el proveedor Speakeasy junto a MoonPay: [AAIF, 24 sep 2026](https://aaif.io/blog/ai-governance-in-a-regulated-industry-how-moonpay-brought-mcp-sprawl-under-control).
- Docker Sandbox Kit Spec v3 (permisos del agente dentro de la imagen OCI; Docker se compromete a enviarlo a la CNCF): [AAIF, 29 sep 2026](https://aaif.io/blog/dockers-sandbox-kit-spec-puts-an-agents-permissions-inside-the-container-image).
- Apple endurece Full Disk Access: "the risks associated with this level of access will grow substantially": [MacRumors, 2 oct 2026](https://www.macrumors.com/2026/10/02/apple-announces-macos-full-disk-access-changes/).
- OpenFGA, agentes como principales y permisos por tarea: [openfga.dev](https://openfga.dev/docs/modeling/agents/overview).
