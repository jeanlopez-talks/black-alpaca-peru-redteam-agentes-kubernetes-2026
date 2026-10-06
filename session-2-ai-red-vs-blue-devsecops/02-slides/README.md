# Material visual de la sesión 2

Dos piezas independientes, ambas en HTML autocontenido: se abren con doble clic,
**no necesitan servidor ni conexión a internet**.

| Archivo | Para qué |
|---|---|
| `index.html` | Las diapositivas de la charla |
| `architecture-diagram.html` | El mapa del pipeline y los agentes, con modo presentación |

---

## `architecture-diagram.html`

Mapa navegable del pipeline DevSecOps, los cuatro agentes, el portal interno y la
admisión. Sirve para dos cosas: **explicarlo en vivo** y **consultarlo** después.

### Modo presentación

Pulsa **`p`** o el botón `▶ Presentar`. El diagrama pasa a pantalla completa, se
ocultan los controles y aparece el relato abajo en cuerpo grande.

| Tecla | Acción |
|---|---|
| `→` `espacio` | Siguiente paso |
| `←` | Paso anterior |
| `Inicio` / `Fin` | Primer / último paso |
| `Esc` | Salir |

**12 pasos**, en el orden del relato: el escenario, los cuatro actos, el hallazgo del
modelo, lo que aguanta y el cierre. Cada paso enciende solo las piezas implicadas.

> Antes de presentar: abre el archivo y pulsa `→` un par de veces para comprobar que
> el proyector lo muestra bien. No hace falta red.

### Modo exploración

Clic en cualquier caja. El panel lateral muestra, de lo general a lo concreto:

1. **Qué hace**, en una frase
2. **Y esto para qué** — la consecuencia
3. **Qué puede fallar aquí** — rojo donde se rompe, verde donde aguanta
4. **En el laboratorio** — qué es real, qué se simula y qué está pendiente
5. **Código** — la ruta exacta en este repositorio
6. **Detalle técnico** (plegable) — pasos internos y decisiones de diseño

Los botones `Solo pipeline`, `Solo agentes` y `Solo GitOps` aíslan una capa;
`Camino del ataque` recorre el acto 3.

### Qué refleja, y qué no

- Las etapas con **borde punteado** (`git-clone`, `test`, `attest`) están
  especificadas pero **aún no implementadas**. Las demás corren en el clúster.
- El **acto 2** aparece en el relato marcado como pendiente: existen `act1`, `act3`
  y `act4` como ejecuciones reales, no `act2`.
- El **merge del PR** se simula a propósito: el ejecutor no tiene permisos de merge.

---

## Regenerar el PNG para documentos

El dossier del CFP incrusta una imagen del diagrama. Para rehacerla tras cualquier
cambio:

```bash
../01-proposal/build-dossier.sh
```

Re-renderiza el diagrama y vuelve a generar el PDF, de modo que la imagen nunca
quede desfasada respecto al diagrama real.

---

## Fuente de los datos

Todo lo que afirma el diagrama está verificado contra:

- `../03-gitops/devsecops-pipeline/tekton/pipeline-devsecops.yaml` — las etapas y su orden
- `../03-gitops/backstage/devsecops-agent/` — los agentes y su configuración
- `../04-ai-agents/src/devsecops_agents/` — el código de los cuatro agentes
- `kubectl get applications -n argocd` — lo que Argo CD gobierna de verdad
