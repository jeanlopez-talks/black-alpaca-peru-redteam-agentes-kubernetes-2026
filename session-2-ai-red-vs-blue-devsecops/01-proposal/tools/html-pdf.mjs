// Convierte el dossier (HTML ya renderizado por pandoc) en PDF vía Chromium.
// Se usa Chromium y no pandoc->LaTeX porque el dossier lleva una imagen muy
// apaisada que necesita control fino de la página.
import { readFileSync, writeFileSync } from 'fs';

const HTML = process.argv[2], OUT = process.argv[3];
const ver = await (await fetch('http://127.0.0.1:9333/json/version')).json();
const ws = new WebSocket(ver.webSocketDebuggerUrl);
let id = 0; const pend = new Map();
const send = (m, q = {}, s) => new Promise(r => {
  const i = ++id; pend.set(i, r);
  ws.send(JSON.stringify({ id: i, method: m, params: q, ...(s && { sessionId: s }) }));
});
await new Promise(r => ws.addEventListener('open', r, { once: true }));
ws.addEventListener('message', e => {
  const m = JSON.parse(e.data);
  if (m.id && pend.has(m.id)) { pend.get(m.id)(m.result); pend.delete(m.id); }
});

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Page.enable', {}, sessionId);
await send('Page.navigate', { url: 'file://' + HTML }, sessionId);
await new Promise(r => setTimeout(r, 2500));

const { data } = await send('Page.printToPDF', {
  printBackground: true,
  paperWidth: 8.27, paperHeight: 11.69,          // A4
  marginTop: 0.5, marginBottom: 0.5, marginLeft: 0.55, marginRight: 0.55,
  preferCSSPageSize: true,
}, sessionId);

writeFileSync(OUT, Buffer.from(data, 'base64'));
console.log('ok ->', OUT);
ws.close();
