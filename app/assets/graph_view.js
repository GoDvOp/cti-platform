'use strict';
const data = JSON.parse(document.getElementById('graph-data').textContent);
const canvas = document.getElementById('graph'), ctx = canvas.getContext('2d');
const colors = {Company:'#5B9BD5', Product:'#70AD47', Vulnerability:'#ED7D31', ThreatActor:'#8064A2', Sector:'#A5A5A5', Publication:'#94A8C4', Source:'#607d8b', BugBountyProgram:'#4C8F94'};
const names = {Company:'Компания', Product:'ПО', Vulnerability:'CVE / BDU', ThreatActor:'Группировка', Sector:'Отрасль', Publication:'Публикация', Source:'Источник', BugBountyProgram:'Программа bug bounty'};
let saved = {};
try { saved = JSON.parse(sessionStorage.getItem('cti-graph-layout') || '{}'); } catch (_) {}
try {const cid=new URLSearchParams(typeof location.search==='string'?location.search:'').get('company');if(cid){saved.selected=cid;saved.search='';saved.mode='all';}}catch(_){}
const buckets = {}, positions = {ThreatActor:[-550,0], Sector:[-270,0], Company:[40,0], Product:[360,0], Vulnerability:[1000,0], Publication:[700,0], BugBountyProgram:[360,950], Source:[1050,950]};
const nodes = data.nodes.map(n => {const count = buckets[n.type] || 0; buckets[n.type] = count + 1; const a = positions[n.type] || [0,0], old = (saved.positions || {})[n.id]; return {...n, x:old ? old[0] : a[0] + (count % 3)*95, y:old ? old[1] : a[1] + Math.floor(count/3)*120, vx:0, vy:0};});
const byId = new Map(nodes.map(n => [n.id,n]));
const edges = data.edges.map(e => ({...e, a:byId.get(e.source), b:byId.get(e.target)}));
const mode = document.getElementById('mode'), search = document.getElementById('search'), labels = document.getElementById('labels'), refresh = document.getElementById('refresh');
mode.value = saved.mode || 'all'; search.value = saved.search || ''; refresh.checked = saved.refresh !== false; labels.checked = saved.labels || false;
let shownNodes = [], shownEdges = [], width = 1, height = 1, view = saved.view || {x:0,y:0,k:1}, selected = saved.selected || null, selectedEdge = null, drag = null, pan = null, frame = 0, animation = false, userMoved = false;
function persist() {try {sessionStorage.setItem('cti-graph-layout', JSON.stringify({positions:Object.fromEntries(nodes.map(n=>[n.id,[n.x,n.y]])),view,mode:mode.value,search:search.value,labels:labels.checked,refresh:refresh.checked,selected}));}catch(_) {}}
function filter() {
  const programs = new Set(['HAS_PUBLIC_BUG_BOUNTY','DESCRIBES_PROGRAM']);
  let primary = edges.filter(e => e.type !== 'PUBLISHED_BY');
  if (mode.value === 'threat') primary = primary.filter(e => !e.properties.view_layer);
  if (mode.value === 'bounty') primary = primary.filter(e => programs.has(e.type));
  if (mode.value === 'notice') {
    const products = new Set(edges.filter(e=>['SECURITY_UPDATE_FOR','SECURITY_NOTICE_FOR'].includes(e.type)).map(e=>e.target));
    primary = primary.filter(e=>['SECURITY_UPDATE_FOR','SECURITY_NOTICE_FOR','MONITORING_HYPOTHESIS','MENTIONS_CVE'].includes(e.type) || (['USES_PRODUCT','USED_PRODUCT','REPORTED_USES_PRODUCT'].includes(e.type) && products.has(e.target)));
  }
  const ids = new Set(primary.flatMap(e=>[e.source,e.target]));
  const provenance = mode.value === 'threat' ? [] : edges.filter(e=>e.type==='PUBLISHED_BY' && ids.has(e.source));
  shownEdges = [...primary,...provenance];
  const included = new Set(shownEdges.flatMap(e=>[e.source,e.target]));
  shownNodes = nodes.filter(n=>included.has(n.id));
  document.getElementById('summary').textContent = `Показано узлов: ${shownNodes.length}, связей: ${shownEdges.length}. Индексы и условные гипотезы требуют проверки применимости. Участие в bug bounty не означает угрозу.`;
  frame = 0; start();
}
function fit() {
  if (!shownNodes.length) return;
  const xs=shownNodes.map(n=>n.x), ys=shownNodes.map(n=>n.y), left=Math.min(...xs)-90, right=Math.max(...xs)+90, top=Math.min(...ys)-80, bottom=Math.max(...ys)+80;
  view.k=Math.max(.12,Math.min(2,width/(right-left),height/(bottom-top))*.9);view.x=width/2-(left+right)/2*view.k;view.y=height/2-(top+bottom)/2*view.k;draw();persist();
}
function screen(n) {return {x:n.x*view.k+view.x,y:n.y*view.k+view.y};}
function draw() {
  ctx.clearRect(0,0,width,height);const query=search.value.trim().toLocaleLowerCase();
  const neighbours = new Set(selected ? shownEdges.filter(e=>e.source===selected||e.target===selected).flatMap(e=>[e.source,e.target]) : []);
  for (const e of shownEdges) {
    const a=screen(e.a),b=screen(e.b),dx=b.x-a.x,dy=b.y-a.y,len=Math.hypot(dx,dy);if(len<1)continue;
    const active=!selected || e.source===selected || e.target===selected;
    ctx.globalAlpha=active?.7:.12;ctx.strokeStyle=e.properties.view_layer?'#7893a4':'#6b7f98';ctx.lineWidth=e===selectedEdge?2.5:1.1;ctx.setLineDash(e.properties.view_layer==='research_context'?[5,4]:[]);
    const r=12, end={x:b.x-dx/len*r,y:b.y-dy/len*r};ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(end.x,end.y);ctx.stroke();ctx.setLineDash([]);
    const angle=Math.atan2(dy,dx);ctx.fillStyle=ctx.strokeStyle;ctx.beginPath();ctx.moveTo(end.x,end.y);ctx.lineTo(end.x-7*Math.cos(angle-.45),end.y-7*Math.sin(angle-.45));ctx.lineTo(end.x-7*Math.cos(angle+.45),end.y-7*Math.sin(angle+.45));ctx.closePath();ctx.fill();
    if(labels.checked && active && view.k>.25){ctx.fillStyle='#52677f';ctx.font='10px system-ui';ctx.textAlign='center';ctx.fillText(e.caption.slice(0,42),(a.x+b.x)/2,(a.y+b.y)/2-4);}
  }
  for(const n of shownNodes){const p=screen(n),match=!query || n.name.toLocaleLowerCase().includes(query),active=(!selected||neighbours.has(n.id))&&match;ctx.globalAlpha=active?1:.2;ctx.fillStyle=colors[n.type]||'#999';ctx.strokeStyle=n.id===selected?'#172c46':'white';ctx.lineWidth=n.id===selected?3:1.5;ctx.beginPath();ctx.arc(p.x,p.y,11,0,Math.PI*2);ctx.fill();ctx.stroke();ctx.fillStyle='#263b54';ctx.font=n.id===selected?'bold 12px system-ui':'11px system-ui';ctx.textAlign='center';const text=n.name.length>39?n.name.slice(0,37)+'…':n.name;ctx.fillText(text,p.x,p.y+26);}
  ctx.globalAlpha=1;
}
function step() {
  for(let i=0;i<shownNodes.length;i++)for(let j=i+1;j<shownNodes.length;j++){const a=shownNodes[i],b=shownNodes[j],dx=a.x-b.x,dy=a.y-b.y,d2=Math.max(100,dx*dx+dy*dy),f=Math.min(3,3500/d2);a.vx+=dx/Math.sqrt(d2)*f;a.vy+=dy/Math.sqrt(d2)*f;b.vx-=dx/Math.sqrt(d2)*f;b.vy-=dy/Math.sqrt(d2)*f;}
  for(const e of shownEdges){const dx=e.b.x-e.a.x,dy=e.b.y-e.a.y,len=Math.max(1,Math.hypot(dx,dy)),f=(len-165)*.0015;e.a.vx+=dx/len*f;e.a.vy+=dy/len*f;e.b.vx-=dx/len*f;e.b.vy-=dy/len*f;}
  for(const n of shownNodes){if(drag===n)continue;n.vx*=.8;n.vy*=.8;n.x+=Math.max(-5,Math.min(5,n.vx));n.y+=Math.max(-5,Math.min(5,n.vy));}
  draw();frame++;if(frame<180){requestAnimationFrame(step);}else{animation=false;if(!userMoved)fit();persist();}
}
function start(){if(!animation){animation=true;requestAnimationFrame(step);}}
function hit(x,y){return [...shownNodes].reverse().find(n=>{const p=screen(n);return Math.hypot(p.x-x,p.y-y)<17;});}
function details(title,props){document.getElementById('detail-title').textContent=title;const pre=document.getElementById('detail-properties');pre.hidden=false;pre.textContent=JSON.stringify(props,null,2);const links=document.getElementById('detail-links');links.replaceChildren();const urls=new Set([props.url,props.evidence_url,...(props.evidence_urls||[])].filter(Boolean));for(const url of urls){try{const u=new URL(url);if(!['http:','https:'].includes(u.protocol))continue;const a=document.createElement('a');a.href=u.href;a.target='_blank';a.rel='noopener noreferrer';a.textContent='Открыть первоисточник';links.append(a,document.createElement('br'));}catch(_) {}}}
canvas.addEventListener('pointerdown',e=>{userMoved=true;const rect=canvas.getBoundingClientRect(),x=e.clientX-rect.left,y=e.clientY-rect.top;canvas.setPointerCapture(e.pointerId);const n=hit(x,y);if(n){selected=n.id;selectedEdge=null;drag=n;details(n.name,{type:n.type,id:n.id,...n.properties});}else{selected=null;pan={x:e.clientX,y:e.clientY,vx:view.x,vy:view.y};let closest=null,best=8;for(const edge of shownEdges){const a=screen(edge.a),b=screen(edge.b),dx=b.x-a.x,dy=b.y-a.y,t=Math.max(0,Math.min(1,((x-a.x)*dx+(y-a.y)*dy)/(dx*dx+dy*dy||1))),d=Math.hypot(x-a.x-t*dx,y-a.y-t*dy);if(d<best){best=d;closest=edge;}}if(closest){selectedEdge=closest;details(closest.caption,{relation:closest.type,...closest.properties});}}draw();});
canvas.addEventListener('pointermove',e=>{const rect=canvas.getBoundingClientRect();if(drag){drag.x=(e.clientX-rect.left-view.x)/view.k;drag.y=(e.clientY-rect.top-view.y)/view.k;drag.vx=drag.vy=0;draw();}else if(pan){view.x=pan.vx+e.clientX-pan.x;view.y=pan.vy+e.clientY-pan.y;draw();}});
function release(){drag=null;pan=null;persist();}canvas.addEventListener('pointerup',release);canvas.addEventListener('pointercancel',release);
canvas.addEventListener('wheel',e=>{userMoved=true;e.preventDefault();const rect=canvas.getBoundingClientRect(),x=e.clientX-rect.left,y=e.clientY-rect.top,k=Math.max(.08,Math.min(5,view.k*Math.exp(-e.deltaY*.001)));view.x=x-(x-view.x)*k/view.k;view.y=y-(y-view.y)*k/view.k;view.k=k;draw();persist();},{passive:false});
function resize(){const box=canvas.getBoundingClientRect(),dpr=window.devicePixelRatio||1;width=box.width;height=box.height;canvas.width=width*dpr;canvas.height=height*dpr;ctx.setTransform(dpr,0,0,dpr,0,0);draw();}window.addEventListener('resize',resize);
mode.addEventListener('change',()=>{userMoved=false;selected=null;filter();fit();persist();});search.addEventListener('input',()=>{draw();persist();});labels.addEventListener('change',()=>{draw();persist();});refresh.addEventListener('change',persist);document.getElementById('fit').addEventListener('click',fit);window.addEventListener('beforeunload',persist);
for(const [type,color] of Object.entries(colors)){const label=document.createElement('span'),dot=document.createElement('i');dot.className='dot';dot.style.background=color;label.append(dot,document.createTextNode(names[type]||type));document.getElementById('legend').append(label);}
const state=data.status||{};let syncText=Object.keys(state).length===0?'Офлайн-обзор SQLite; состояние службы доступно в панели CTI':state.last_graph_success?'Neo4j: последнее подтверждение '+state.last_graph_success:'Подтверждение синхронизации Neo4j не получено';if(state.graph_pending||state.last_graph_error)syncText+=' · ожидает обновления';document.getElementById('status').textContent='Данные на '+data.as_of+' · '+syncText;
filter();resize();if(!saved.view)fit();if(selected&&byId.has(selected)){const n=byId.get(selected);details(n.name,{type:n.type,id:n.id,...n.properties});}
setInterval(()=>{if(refresh.checked&&!drag){persist();location.reload();}},60000);
