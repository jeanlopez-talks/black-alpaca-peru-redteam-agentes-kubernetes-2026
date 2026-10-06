// Renderiza el diagrama a PNG en alta resolución para incrustarlo en el dossier.
import { writeFileSync } from 'fs';
const FILE = process.argv[2], OUT = process.argv[3];
const ver = await (await fetch('http://127.0.0.1:9333/json/version')).json();
const ws = new WebSocket(ver.webSocketDebuggerUrl);
let id=0; const p=new Map();
const send=(m,q={},s)=>new Promise(r=>{const i=++id;p.set(i,r);ws.send(JSON.stringify({id:i,method:m,params:q,...(s&&{sessionId:s})}))});
await new Promise(r=>ws.addEventListener('open',r,{once:true}));
ws.addEventListener('message',e=>{const m=JSON.parse(e.data); if(m.id&&p.has(m.id)){p.get(m.id)(m.result);p.delete(m.id)}});
const {targetId}=await send('Target.createTarget',{url:'about:blank'});
const {sessionId}=await send('Target.attachToTarget',{targetId,flatten:true});
await send('Page.enable',{},sessionId); await send('Runtime.enable',{},sessionId);
// 2x para que el texto quede nítido en el PDF.
await send('Emulation.setDeviceMetricsOverride',{width:2400,height:1200,deviceScaleFactor:2,mobile:false},sessionId);
await send('Page.navigate',{url:FILE},sessionId);
await new Promise(r=>setTimeout(r,2500));
// Oculta el panel lateral y los controles: en el PDF solo interesa el mapa.
await send('Runtime.evaluate',{expression:`
  document.querySelector('.wrap').classList.add('collapsed');
  document.querySelector('.bar').style.display='none';
  document.querySelector('footer').style.display='none';
`},sessionId);
await new Promise(r=>setTimeout(r,600));
// Recorta justo al SVG.
const {result} = await send('Runtime.evaluate',{expression:`
  (()=>{const r=document.querySelector('#d').getBoundingClientRect();
   return JSON.stringify({x:r.x,y:r.y,width:r.width,height:r.height});})()
`,returnByValue:true},sessionId);
const box = JSON.parse(result.value);
const {data}=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true,
  clip:{x:box.x,y:box.y,width:box.width,height:box.height,scale:2}},sessionId);
writeFileSync(OUT, Buffer.from(data,'base64'));
console.log('ok ->',OUT, Math.round(box.width)+'x'+Math.round(box.height));
ws.close();
