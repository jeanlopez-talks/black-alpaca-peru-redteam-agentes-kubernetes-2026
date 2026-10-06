# Propuesta 2 (Sessionize) — Atacar y gobernar agentes de IA en el pipeline DevSecOps

> Segunda submission para Black Alpaca 2026 (el CFP permite 2 por speaker). Campos
> mapeados contra el formulario real de Sessionize. Diseño técnico en `concept.md`.

---

## Campos del formulario

### Session Title — *máx 100 caracteres*
```
Engañé al gate de IA de tu pipeline: la firma seguía siendo válida y aun así no entró
```

Variante:
```
Tu agente de IA es un insider: cómo atacarlo y qué control lo frena de verdad
```

### Description — *privada, para el comité*
```
Las empresas están metiendo agentes de IA en sus pipelines: revisores de PRs, gates de seguridad, asistentes que proponen correcciones. Cada uno es una identidad nueva con acceso a código, credenciales y producción, y casi nadie lo gobierna como tal. Esta charla lo ataca en vivo sobre un laboratorio propio y muestra qué control es el que de verdad aguanta.

Parte ofensiva, sobre un pipeline DevSecOps real en Kubernetes (Tekton, Argo CD, Kyverno, cosign, registro interno) con agentes que hablan por A2A. Un agente rojo abre PRs maliciosos contra un agente azul que los revisa. El azul bloquea el ataque obvio. Después el rojo esconde una instrucción en el diff y gana el gate. La cadena de supply chain sigue intacta: la imagen se firma y se verifica correctamente, porque el PR toca la CONFIGURACIÓN, no la imagen. Firma válida, ataque vivo.

El giro es lo que NO funcionó. Con el modelo real (Qwen3-8B local) el revisor bloqueó las 5 ejecuciones: ve el comando peligroso. El engaño solo ocurre con el motor de reglas, donde obedecer la nota está programado a propósito. Lo presento tal cual, porque es el punto: un modelo mejor sube el listón, no lo convierte en un control de seguridad.

Lo que sí frena el ataque es la plataforma. El agente tiene credencial real y aun así la admisión lo rechaza dos veces: sin aprobación humana, y falsificándola tampoco, porque el cambio no viene de GitOps. Cierro con los dos agentes que sí aportan: analizan vulnerabilidades con el modelo acotado por un esquema y verificado por código (37 → 13 vulnerabilidades graves, con la app funcionando), y proponen el arreglo para que una persona lo confirme en Backstage.

Todo corre en un clúster k3s propio, es GitOps y reproducible, y se publica con la charla. La metodología de aislamiento parte del trabajo de Roy Belio (Red Hat), citado como fuente.
```

### Abstract — *público, ≤300 palabras*
```
Tu pipeline ya tiene agentes de IA: revisan PRs, deciden gates, proponen correcciones. Cada uno es una identidad con acceso a tu código y a producción. La pregunta ofensiva es obvia: ¿qué pasa cuando el atacante le habla al agente?

Lo muestro en vivo sobre un pipeline DevSecOps real en Kubernetes con agentes que se comunican por A2A. Un agente rojo abre pull requests maliciosos y un agente azul los revisa. El azul bloquea el ataque obvio. Luego el rojo esconde una instrucción en el diff y gana el gate — y la cadena de supply chain no se entera: la imagen se firma y verifica correctamente, porque el ataque toca la configuración, no la imagen. Firma válida, ataque vivo.

Después enseño lo que NO funcionó. Con el modelo real en mi clúster, el revisor bloqueó las cinco ejecuciones: ve el comando peligroso. El engaño solo ocurre con reglas fijas, donde obedecer la nota está programado. Ese es el punto: un modelo mejor sube el listón, pero no es un control.

Lo que de verdad frena el ataque es la plataforma. El agente tiene credencial y aun así la admisión lo rechaza dos veces: le falta la aprobación de una persona, y cuando se la falsifica tampoco entra, porque el cambio no viene de Git. Cierro con los agentes que sí aportan valor: analizan las vulnerabilidades con el modelo acotado por un esquema y verificado por código, bajan la imagen de 37 a 13 vulnerabilidades graves, y proponen el arreglo para que una persona lo confirme.

Te llevas: cómo se envenena un gate que lee texto del atacante, por qué firmar y escanear son necesarios pero no suficientes, y un laboratorio reproducible en GitOps para gobernar agentes en tu pipeline.

Nivel intermedio-avanzado. Se asume CI/CD y Kubernetes.
```

### Talk Teaser — *≤240 caracteres*
```
Mi agente rojo convence a tu revisor de IA de aprobar su propio ataque, y la firma de la imagen sigue siendo válida. Lo que lo frena no es el modelo: es la admisión. Laboratorio propio, resultados medidos.
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
> `dossier-session-2.pdf` — resumen técnico con el diagrama de arquitectura del
> pipeline y los agentes, los cuatro actos con su resultado real, los números
> medidos y el enlace al repositorio con el laboratorio completo.

---

## Esqueleto (50 min)

1. **(0-5)** Los agentes ya están en tu pipeline: cada uno es una identidad nueva con acceso a código y a producción.
2. **(5-12)** El escenario, en mi clúster: pipeline DevSecOps de 11 etapas (clone, pruebas, SAST, build, SBOM, escaneo, firma, procedencia, gate, verificación, despliegue) y los agentes que actúan en él.
3. **(12-18)** Acto 1: el azul bloquea el PR malicioso obvio. El control funciona cuando el ataque es evidente.
4. **(18-26)** Acto 2 y 3: el rojo esconde la instrucción en el diff y gana el gate. La firma se verifica igual, porque el ataque toca config y no la imagen — supply chain intacta, ataque vivo.
5. **(26-32)** El hallazgo incómodo: con el modelo real el azul bloqueó 5 de 5. El engaño solo ocurre donde obedecer la nota está programado. Un modelo mejor sube el listón; no es un control.
6. **(32-40)** Lo que sí frena: la admisión. El agente tiene credencial y es rechazado dos veces — sin aprobación humana, y falsificándola tampoco, porque no viene de GitOps.
7. **(40-47)** Los agentes que sí aportan: el modelo decide, el esquema acota, el código verifica. 37 → 13 vulnerabilidades graves. El agente propone y la persona confirma en Backstage.
8. **(47-50)** Checklist para gobernar los agentes de tu pipeline. Preguntas.

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
