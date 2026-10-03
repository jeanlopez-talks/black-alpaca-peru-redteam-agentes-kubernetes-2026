# Propuesta 2 (Sessionize) — Duelo de agentes IA en el pipeline DevSecOps

> **Segunda submission** para Black Alpaca 2026 (el CFP permite 2 por speaker).
> Campos mapeados contra el formulario REAL de Sessionize (mismos límites que la propuesta 1).
> Concepto técnico completo en `CONCEPTO.md`.

---

## ✅ CAMPOS DEL FORMULARIO

### Session Title — *máx 100 caracteres*
```
Rojo vs Azul, los dos son IA: agentes ofensivos y defensivos en tu pipeline DevSecOps
```
*(85 car. ✓)*

Variante:
```
Cuando el atacante convence a tu IA defensiva: red team de agentes en DevSecOps
```
*(79 car. ✓)*

### Description — *privada, para el comité*
```
Meter un agente de IA en el pipeline como revisor de PRs o auto-remediador se vende como productividad. Esta charla demuestra, en vivo, que también es una nueva superficie de ataque: si tu defensor es un LLM que lee contenido controlado por el atacante (el diff de un PR, un commit, un comentario), el atacante puede envenenarlo con prompt injection y hacer que apruebe su propio ataque.

Monto un duelo rojo-vs-azul donde ambos lados son agentes de IA. El agente rojo (ofensivo) abre pull requests maliciosos contra un pipeline real (Tekton/Argo CD en OpenShift). El agente azul (defensivo) los revisa y decide si bloquea el merge. En el primer acto, el azul funciona: detecta el PR malicioso obvio y lo bloquea. En el segundo, el rojo aprende — esconde el payload cambiando el encuadre igual que en el caso Morse clásico, de modo que el clasificador de prompt injection del azul pasa de un score de 0.999999 a 0.0005 (números que mido en vivo), e inyecta en el propio diff una instrucción dirigida al LLM revisor. En el tercer acto, el azul lee el diff, la inyección lo captura, y aprueba el PR malicioso. Argo CD lo auto-despliega. El atacante gana — a través del defensor.

El cierre es lo importante para una audiencia de red team: qué habría parado el ataque, y no es un mejor prompt del azul. Son fronteras de infraestructura — el agente defensivo sin permiso de merge directo (humano en el loop), el runner del CI aislado (uid 1000, capabilities dropped, egress deny-by-default), separación de credenciales entre el token que mergea y el que el agente toca, y tratar el contenido del atacante como dato no confiable y nunca como instrucción para el LLM.

Todo el laboratorio es reproducible, vive en un repositorio público con GitOps y ya corre de punta a punta en un clúster OpenShift real: el agente azul se ejecuta como un step de un pipeline Tekton en un runner aislado (SCC restricted-v2, capabilities dropped, egress deny), aprueba el PR envenenado, y el merge/deploy GitOps queda demostrado. Reutilizo el aislamiento de runtime y el clasificador de un estudio previo propio de red-teaming de agentes en Kubernetes; aquí lo llevo al terreno DevSecOps: el agente deja de ser solo la víctima y pasa a ser el actor — rojo y azul — dentro del pipeline. Metodología de aislamiento basada en el trabajo de Roy Belio (Red Hat), reencuadrada con laboratorio propio.
```

### Abstract — *PÚBLICO, ≤300 palabras*
```
Poner un agente de IA en tu pipeline —revisor de PRs, gate de seguridad, auto-remediador— se vende como productividad. Esta charla demuestra en vivo que también abre una puerta: si tu defensor es un LLM que lee lo que el atacante escribe (el diff de un PR, un commit, un comentario), el atacante puede envenenarlo y hacer que apruebe su propio ataque.

Monto un duelo donde los dos bandos son IA. El agente rojo abre pull requests maliciosos contra un pipeline real sobre Kubernetes. El agente azul los revisa y decide el merge. Primer acto: el azul gana, detecta el PR malicioso y lo bloquea. Segundo acto: el rojo aprende y esconde el payload cambiando solo el encuadre —el clasificador de prompt injection del azul se desploma de 0.999999 a 0.0005, lo mido en vivo— e inyecta en el diff una orden dirigida al propio revisor. Tercer acto: el azul lee el diff, cae en la inyección y aprueba el ataque. GitOps lo despliega solo. El atacante gana a través del defensor.

El cierre es lo que importa para red team: lo que habría parado esto no es un mejor prompt, son fronteras de infraestructura. El agente defensivo sin permiso de merge directo (humano en el loop), el runner aislado (uid 1000, capabilities dropped, egress deny), separación de credenciales, y tratar el input del atacante como dato y nunca como instrucción.

Te llevas: por qué un agente de IA defensivo es un blanco, no solo un escudo; cómo se envenena a un revisor LLM en un pipeline; y un blueprint de contención reproducible con GitOps. Lab público y números propios.

Nivel intermedio-avanzado. Se asume CI/CD, Kubernetes y una noción de qué es un agente de IA.
```
*(~290 palabras ✓)*

### Talk Teaser — *≤240 caracteres*
```
¿Pusiste una IA a revisar tus PRs? Monto un duelo rojo vs azul donde ambos son agentes. El rojo esconde el payload, el azul lo aprueba solo, GitOps lo despliega. El atacante gana a través del defensor. Lab reproducible.
```
*(~223 car. ✓)*

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
> Mismo repo público que la propuesta 1 (comparten lab). El one-pager PDF enlaza al repo y a la sección del duelo.

---

## Esqueleto (50 min)

1. **(0-5)** El pitch inocente: "pongamos una IA a revisar PRs / a remediar vulns". Por qué suena bien.
2. **(5-12)** El duelo, reglas: agente rojo ofensivo vs agente azul defensivo sobre un pipeline real (Tekton/Argo CD).
3. **(12-20)** Acto 1 — el azul gana: detecta y bloquea el PR malicioso obvio. Demo en vivo.
4. **(20-30)** Acto 2 — el rojo aprende: evade el clasificador (0.999999 → 0.0005, medido en vivo) + inyección dirigida al revisor en el diff.
5. **(30-38)** Acto 3 — el azul traiciona: aprueba el ataque, Argo CD lo despliega. El atacante ganó a través del defensor.
6. **(38-46)** Acto 4 — qué lo habría parado: fronteras de infraestructura (merge sin el agente, runner aislado, separación de credenciales, input como dato).
7. **(46-50)** Checklist para quien ya metió —o va a meter— IA en su pipeline. Cómo reproducir el lab.
8. Preguntas.

---

## Relación con la propuesta 1

Son **complementarias**, no redundantes:
- Propuesta 1: el agente de IA es la **víctima** a proteger (aislamiento, escalada).
- Propuesta 2: el agente de IA es el **actor** (rojo y azul) dentro del pipeline DevSecOps.

Si el comité acepta una, perfecto. Si acepta las dos, forman una narrativa: "cómo proteger un agente" + "qué pasa cuando el agente defiende y lo engañan".
