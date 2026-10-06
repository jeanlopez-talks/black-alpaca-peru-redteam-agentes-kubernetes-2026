#!/usr/bin/env bash
# Genera el PDF que se adjunta al CFP a partir de `dossier.md`.
#
# Dos pasos:
#   1. Se re-renderiza el diagrama de arquitectura a PNG desde el HTML, para que
#      la imagen del dossier nunca quede desfasada respecto al diagrama real.
#   2. pandoc produce un HTML autocontenido y Chromium lo imprime a PDF.
#
# Chromium en vez de pandoc->LaTeX porque el diagrama es muy apaisado y necesita
# una página horizontal propia (`@page diagrama { size: A4 landscape }`).
#
# Requisitos: pandoc y el Chromium headless de Playwright (ya instalado).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIAGRAM_HTML="${HERE}/../02-slides/architecture-diagram.html"
OUT_PDF="${HERE}/dossier-session-2.pdf"
PORT=9333

CHROME="${HOME}/Library/Caches/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-mac-arm64/chrome-headless-shell"
[ -x "$CHROME" ] || { echo "No encuentro Chromium headless en $CHROME"; exit 1; }
command -v pandoc >/dev/null || { echo "Falta pandoc (brew install pandoc)"; exit 1; }

echo "[1/3] Arrancando Chromium headless..."
rm -rf /tmp/dossier-profile
"$CHROME" --remote-debugging-port=$PORT --user-data-dir=/tmp/dossier-profile \
  --no-first-run --allow-file-access-from-files >/tmp/dossier-chrome.log 2>&1 &
CHROME_PID=$!
trap 'kill $CHROME_PID 2>/dev/null; rm -rf /tmp/dossier-profile' EXIT
sleep 3

echo "[2/3] Renderizando el diagrama a PNG..."
node "${HERE}/tools/diagram-png.mjs" "file://${DIAGRAM_HTML}" \
  "${HERE}/assets/architecture-diagram.png"

echo "[3/3] Generando el PDF..."
cd "$HERE"
pandoc dossier.md -f markdown+raw_html -t html5 --standalone --embed-resources \
  --css=tools/dossier.css -o /tmp/dossier.html
node "${HERE}/tools/html-pdf.mjs" /tmp/dossier.html "$OUT_PDF"

echo
echo "Listo: $OUT_PDF"
ls -lh "$OUT_PDF" | awk '{print "   " $5}'
