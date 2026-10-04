# Slides — Charla 1

**Cuando el modelo deja de rechazar: red-teaming de agentes de IA en Kubernetes**
Black Alpaca 2026 · Jean Paul López · Red Hat

Presentación HTML autocontenida: un solo archivo, CSS y JS inline, **sin dependencias ni CDN**. Abre offline.

## Abrir

Doble clic en `index.html` (abre en el navegador). O desde terminal:

```bash
open index.html        # macOS
```

## Navegar

| Tecla | Acción |
|-------|--------|
| `→` / `Espacio` / `PageDown` | siguiente slide |
| `←` / `PageUp` | slide anterior |
| `Home` / `End` | primera / última slide |
| `n` | mostrar/ocultar **notas del ponente** (con reparto de tiempo del esqueleto de 50 min) |
| `f` | pantalla completa |

También puedes hacer clic: mitad derecha de la pantalla avanza, mitad izquierda retrocede.
Barra de progreso arriba y contador de slide abajo a la derecha. Soporta deep-link por hash (`index.html#4`).

## Exportar a PDF

1. Abre `index.html` en Chrome.
2. Menú → **Imprimir** (`Cmd/Ctrl + P`).
3. Destino: **Guardar como PDF**. Orientación **horizontal**, márgenes **Ninguno**, activa **Gráficos de fondo**.
4. Se exportan las 10 slides, una por página (16:9), sin la barra, el contador ni las notas.

## Contenido (10 slides, mapeados al esqueleto de 50 min)

1. Portada
2. El ataque real de 3,000M de tokens (cadena de 4 pasos)
3. Tesis: el refusal no es contención
4. Demo clasificador — tabla con números reales (0.999999 → 0.003008 → 0.000480)
5. Metodología: 4 posturas × 6 fronteras, tokens canario, Argo CD
6. Los 8 vectores de escalada → mecanismo de kernel
7. Hallazgos incómodos: write-mediation y workspace-persistence FALLAN
8. Blueprint de operador
9. Checklist de cierre + cómo reproducir el lab
10. Gracias / preguntas / crédito a Roy Belio (Red Hat)
