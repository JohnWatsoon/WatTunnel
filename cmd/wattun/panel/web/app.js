// The panel front end. Plain JS, no build step, embedded in the binary. No product name in this file: it is
// served before sign-in (the command name arrives with /api/me).
(function(){
"use strict";
/* ---------- geography (coarse, for dot rendering) ---------- */
function inPoly(x,y,p){let c=false;for(let i=0,j=p.length-1;i<p.length;j=i++){const xi=p[i][0],yi=p[i][1],xj=p[j][0],yj=p[j][1];if((yi>y)!==(yj>y)&&x<(xj-xi)*(y-yi)/(yj-yi)+xi)c=!c}return c}
const WATER=[
 [[-12,12],[-12,66],[12,66],[10,63.5],[5,62],[5,58.5],[7,58],[8,57],[8.5,55.5],[8.5,54],[5,53.3],[4,52],[2,51],[1.5,50.2],[-1.5,49.7],[-4.8,48.4],[-2.3,47],[-1.3,46],[-1.6,43.4],[-8,43.7],[-9.3,43],[-8.9,38.7],[-9,37],[-6.3,36.5],[-5.6,36],[-6,35.7],[-9.5,32.5],[-9.8,30],[-12,27.5]],
 [[-5.6,36],[-4.5,36.7],[-2,36.8],[0,38.5],[0.2,39.5],[-0.3,39.5],[0.8,41],[3.2,41.9],[3,43.3],[5,43.4],[7.5,43.8],[9,44.4],[10.3,43.5],[12,42],[14,41],[15.7,40],[16,38],[15.6,38],[17,39],[18.5,40.2],[17,41],[16,41.9],[14,42.5],[13.6,43.6],[12.3,44.5],[12.5,45.5],[13.7,45.7],[15,44.8],[16.5,43.5],[18.5,42.4],[19.5,41.8],[19.4,40.4],[21,38.5],[21.5,37],[22.5,36.4],[23,37.5],[23,38.2],[24,38.2],[22.8,40.5],[24,40.8],[26,40.8],[26.2,40.1],[27,38.5],[27.3,37],[28,36.7],[30.5,36.6],[32,36.3],[34,36.8],[36,36.8],[35.9,35.5],[35.6,34.5],[35,33],[34.5,31.5],[32.3,31.3],[30,31.5],[25,31.9],[23,32.6],[20,32],[19.5,30.3],[15.5,31.5],[13,32.8],[11,33.3],[10.2,34.3],[11,35.2],[10.4,36.9],[9.7,37.3],[8,36.9],[3,36.8],[-1,35.6],[-2.2,35.1],[-5.3,35.9]],
 [[27.5,42],[28,43.5],[29.6,45.2],[30.7,46.5],[32,46.2],[33.5,46],[33,45.3],[32.5,45.4],[33.5,44.4],[35.5,45],[36.5,45.3],[38,47],[39.3,47.1],[38,46],[37.5,44.7],[39.8,43.4],[41.6,41.6],[40,41],[36,41.7],[33,42],[29,41.2],[28,41.6]],
 [[47,44.5],[47.5,45.6],[49,46.6],[51.4,47],[53,46.6],[53.1,45.2],[51.3,44.6],[51,43.2],[52.7,42],[53,40.5],[53.8,40],[53.9,38],[53.9,37],[51.5,36.7],[50.2,37.4],[49,38],[48.9,38.9],[49.5,40.3],[48.5,41.9],[47.5,43]],
 [[32.5,29.9],[34.5,29.5],[35,28],[36.5,26],[39,21.5],[41,18],[42.5,15.5],[43.3,12.7],[45,12.8],[48.5,14],[52,15.6],[55,17.2],[57,18.8],[58.5,20.5],[59.8,22.5],[58.8,23.6],[57,24],[56.4,24.8],[56.3,26.2],[55.5,25.5],[54.5,24.2],[52,24],[51.6,24.6],[51.5,25.9],[50.8,24.8],[50.2,25.8],[50,26.5],[49.4,27],[48.5,28.4],[48,29.5],[48.5,30],[49.6,30],[50.5,29],[51.5,27.9],[53.5,26.8],[54.8,26.5],[56.2,27.1],[57,25.7],[61.5,25.1],[64,25.3],[66.5,25.4],[67.3,24.7],[68.5,23.5],[70.3,22.5],[72.7,21],[73,19],[73.5,15.5],[74.5,13],[75,12],[43,12],[43,12.6],[41.5,14.5],[39.5,15.8],[38.5,18],[37.3,21],[36.8,22],[35.6,23.9],[34.6,26.2],[33.5,27.6],[32.6,29.9]],
 [[10.5,54.3],[13,54.2],[14.2,53.9],[18.5,54.7],[21.2,55.2],[21,56.8],[22,57.5],[24.3,57.2],[23.5,58.5],[23.5,59.3],[28,59.6],[30,60],[28.5,60.6],[22.5,60.1],[21.5,61],[21.5,63],[25,65],[22,65.8],[21,64.5],[17.5,62.5],[17.5,61],[18.8,59.8],[18.5,59],[16.5,57.5],[16,56.2],[14.2,55.4],[12.8,55.9],[12.5,56.5],[11.8,57.6],[11,58.8],[10.5,59.4],[9.5,58.9],[8,58],[8.1,57],[8.6,57.1],[10.3,57.6],[10.5,56.5],[10,55.5],[10.5,54.6]]
];
const LANDX=[
 [[-5.7,50],[-3,50.6],[1.4,51.2],[1.7,52.7],[0,53.5],[-1.5,55],[-2,56],[-1.8,57.6],[-3.5,58.6],[-5,58.6],[-6.2,57.5],[-5.6,55.5],[-4.8,54.8],[-3.2,54.6],[-3,53.4],[-4.6,53.3],[-4.2,52.3],[-5.2,51.8],[-3.2,51.4],[-4.5,51.1]],
 [[-6,52],[-6.2,53.4],[-5.6,54.5],[-7,55.3],[-8.3,55.1],[-10,54.2],[-9.8,53],[-10.3,51.8],[-8.3,51.6]],
 [[12.4,38],[15.6,38.3],[15.1,36.7],[12.4,37.6]],[[8.4,41],[9.6,41],[9.6,39.1],[8.4,39]],[[8.5,43],[9.5,43],[9.5,41.4],[8.6,41.4]],
 [[23.5,35.6],[26.3,35.3],[26,35],[23.6,35.2]],[[32.3,35],[34.6,35.6],[33.9,34.6],[32.4,34.7]]
];
const IRAN=[[44,39.5],[48,38.5],[49,38],[51.5,36.8],[54,37.3],[57,38],[60.5,36.6],[61.2,35.6],[60.5,33.5],[61.5,31.3],[63,29.5],[61.5,25.2],[57.3,25.7],[54.5,26.6],[51.5,27.9],[48.6,30],[48,31],[46,33],[45.5,34.5],[44.5,37.2]];
function isLand(lon,lat){
  if(lon>=-12&&lon<=75&&lat>=12&&lat<=66) return !WATER.some(p=>inPoly(lon,lat,p))||LANDX.some(p=>inPoly(lon,lat,p));
  if(lat>66) return (lon>15&&lon<180&&lat<76)||(lon>5&&lon<=15&&lat<70)||(lon>-55&&lon<-20&&lat<82);
  if(lon>75) return lat>22||(lon<80&&lat>8)||(lon>92&&lon<110&&lat>1);
  if(lon<-12) return lon>-55&&lon<-20&&lat>60;
  if(lat<=12&&lat>0) return (lon>-12&&lon<43)||(lon>=43&&lon<51&&lat>2);
  if(lat<=0) return lon>10&&lon<40&&lat>-35;
  return false;
}
function hash(a,b){const s=Math.sin(a*127.1+b*311.7)*43758.5453;return s-Math.floor(s)}

/* ---------- places ---------- */
// The server knows its Kharej hosts by IP only (no GeoIP database ships), so each Kharej is drawn at a fixed
// European anchor in pairing order and labelled with its address. shortcut: decorative position; a per-host
// place setting can come with phase 4.
const IRAN_LL=[51.4,35.7];
const ANCHORS=[[8.7,50.1],[24.9,60.2],[4.9,52.4],[2.35,48.9],[13.4,52.5],[-0.1,51.5],[16.4,48.2],[18.1,59.3]];
const C_OK='62,224,138',C_BAD='255,93,98',C_IR='154,140,255';
function regionOf(lon,lat){return inPoly(lon,lat,IRAN)?1:0}

/* ---------- small helpers ---------- */
const $=(s)=>document.querySelector(s);
const RM=matchMedia('(prefers-reduced-motion: reduce)').matches;
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
function mb(bps){return bps/1048576}
function fmtRate(bps){const v=mb(bps);return v>=100?v.toFixed(0):v>=10?v.toFixed(1):v.toFixed(2)}
function fmtDur(s){if(!s)return '–';if(s<60)return s+' s';if(s<3600)return Math.round(s/60)+' m';if(s<86400)return (s/3600).toFixed(1)+' h';return (s/86400).toFixed(1)+' d'}
function fmtBytes(b){const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++}return (b>=100?b.toFixed(0):b.toFixed(1))+' '+u[i]}
function fitCanvas(c){const r=Math.min(2,window.devicePixelRatio||1);const w=c.clientWidth,h=c.clientHeight;c.width=Math.max(1,Math.round(w*r));c.height=Math.max(1,Math.round(h*r));const x=c.getContext('2d');x.setTransform(r,0,0,r,0,0);return {x,w,h}}
function markDots(){document.querySelectorAll('.mk').forEach(m=>{if(m.childElementCount)return;[1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1].forEach(v=>m.appendChild(el('i',v?'on':'')))})}

async function api(path,opts={}){
  const o={method:opts.method||'GET',headers:{'X-Requested-With':'panel'},credentials:'same-origin',cache:'no-store'};
  if(opts.body!==undefined){o.headers['Content-Type']='application/json';o.body=JSON.stringify(opts.body)}
  const r=await fetch('api/'+path,o);
  let j={};try{j=await r.json()}catch(e){}
  if(r.status===401&&!opts.auth){showLogin();throw new Error('signed out')}
  return {ok:r.ok,status:r.status,j};
}

/* ---------- globe (login) ---------- */
const globe={pts:null,raf:0,stop:null};
function buildGlobe(){
  const N=14000,pts=[],ga=Math.PI*(3-Math.sqrt(5));
  for(let i=0;i<N;i++){const y=1-(i/(N-1))*2,rr=Math.sqrt(1-y*y),th=ga*i;const lat=Math.asin(y)*180/Math.PI;const lon=Math.atan2(Math.sin(th)*rr,Math.cos(th)*rr)*180/Math.PI;const land=isLand(lon,lat);pts.push({lon:lon*Math.PI/180,lat:lat*Math.PI/180,land,reg:land?regionOf(lon,lat):0,n:hash(lon,lat)})}
  globe.pts=pts;
}
function orth(lon,lat,l0,p0,alt){const cl=Math.cos(lat);const x=cl*Math.sin(lon-l0);const y=Math.cos(p0)*Math.sin(lat)-Math.sin(p0)*cl*Math.cos(lon-l0);const z=Math.sin(p0)*Math.sin(lat)+Math.cos(p0)*cl*Math.cos(lon-l0);return [x*alt,y*alt,z]}
function slerp(a,b,s){const toV=p=>{const lo=p[0]*Math.PI/180,la=p[1]*Math.PI/180;return [Math.cos(la)*Math.cos(lo),Math.cos(la)*Math.sin(lo),Math.sin(la)]};const A=toV(a),B=toV(b);const d=Math.acos(Math.min(1,A[0]*B[0]+A[1]*B[1]+A[2]*B[2]));const k1=Math.sin((1-s)*d)/Math.sin(d),k2=Math.sin(s*d)/Math.sin(d);const v=[A[0]*k1+B[0]*k2,A[1]*k1+B[1]*k2,A[2]*k1+B[2]*k2];return [Math.atan2(v[1],v[0]),Math.asin(v[2])]}
function startGlobe(){
  const c=$('#globe');if(!globe.pts)buildGlobe();
  let g=fitCanvas(c);const t0=performance.now();
  const ro=new ResizeObserver(()=>{g=fitCanvas(c)});ro.observe(c);
  const draw=(now)=>{
    const {x,w,h}=g;const t=(now-t0)/1000;x.clearRect(0,0,w,h);
    const R=Math.min(w*0.62,h*0.78),cx=w*0.5,cy=h*0.68;
    const l0=(28+(RM?0:Math.sin(t*0.07)*14))*Math.PI/180,p0=33*Math.PI/180;
    const intro=RM?1:Math.min(1,t/1.8);
    for(const p of globe.pts){
      const q=orth(p.lon,p.lat,l0,p0,1);if(q[2]<0)continue;
      const sx=cx+q[0]*R,sy=cy-q[1]*R;if(sy>h+4||sy<-4||sx<-4||sx>w+4)continue;
      const appear=Math.max(0,Math.min(1,(intro*1.3-(1-q[2]))*2.2));if(appear<=0)continue;
      const shade=0.25+0.75*q[2];
      if(p.reg){x.fillStyle=`rgba(${C_IR},${(0.95*shade*appear).toFixed(3)})`;x.beginPath();x.arc(sx,sy,1.35,0,6.283);x.fill()}
      else if(p.land){x.fillStyle=`rgba(236,236,240,${((0.42+0.3*p.n)*shade*appear).toFixed(3)})`;x.beginPath();x.arc(sx,sy,1.2,0,6.283);x.fill()}
      else{x.fillStyle=`rgba(236,236,240,${(0.06*shade*appear).toFixed(3)})`;x.fillRect(sx-.5,sy-.5,1,1)}
    }
    x.strokeStyle='rgba(255,255,255,0.06)';x.lineWidth=1;x.beginPath();x.arc(cx,cy,R,0,6.283);x.stroke();
    const ar=RM?1:Math.max(0,Math.min(1,(t-1.4)/1.2));
    [[ANCHORS[0],0.11],[ANCHORS[1],0.07]].forEach(([dst,sp],k)=>{
      const pts=[];const n=90;
      for(let i=0;i<=n;i++){const s=i/n;const ll=slerp(IRAN_LL,dst,s);const q=orth(ll[0],ll[1],l0,p0,1+0.16*Math.sin(Math.PI*s));pts.push([cx+q[0]*R,cy-q[1]*R])}
      for(let i=0;i<=n*ar;i+=2){const q=pts[i];x.fillStyle='rgba(255,255,255,0.32)';x.beginPath();x.arc(q[0],q[1],0.9,0,6.283);x.fill()}
      if(ar>=1){const head=1-((t*sp+k*0.5)%1);for(let j=0;j<22;j++){const s=head+j*0.008;if(s>1)break;const q=pts[Math.round(s*n)];const a=1-j/22;x.fillStyle=`rgba(${C_OK},${(a*0.95).toFixed(3)})`;x.beginPath();x.arc(q[0],q[1],j===0?2.4:1.5*a+0.4,0,6.283);x.fill()}}
      const e=pts[n];x.fillStyle='#f3f3f4';x.beginPath();x.arc(e[0],e[1],2.6,0,6.283);x.fill();
    });
    const o=orth(IRAN_LL[0]*Math.PI/180,IRAN_LL[1]*Math.PI/180,l0,p0,1);const ox=cx+o[0]*R,oy=cy-o[1]*R;
    const ph=(t*0.5)%1;x.strokeStyle=`rgba(${C_IR},${((1-ph)*0.7).toFixed(3)})`;x.beginPath();x.arc(ox,oy,3+ph*26,0,6.283);x.stroke();
    x.fillStyle='#f3f3f4';x.beginPath();x.arc(ox,oy,3,0,6.283);x.fill();
    globe.raf=requestAnimationFrame(draw);
  };
  globe.raf=requestAnimationFrame(draw);
  globe.stop=()=>{cancelAnimationFrame(globe.raf);ro.disconnect();globe.stop=null};
}

/* ---------- login ---------- */
let ticket='',clockIv=0;
const f1=$('#f1'),f2=$('#f2');const otp=[];
for(let i=0;i<6;i++){const inp=el('input');inp.inputMode='numeric';inp.maxLength=1;inp.setAttribute('aria-label','Digit '+(i+1));if(i===0)inp.autocomplete='one-time-code';$('.otp').appendChild(inp);otp.push(inp)}
function showLogin(){
  stopApp();$('#app').hidden=true;$('#login').hidden=false;
  f2.hidden=true;f1.hidden=false;$('#p2').classList.remove('on');$('#e1').textContent='';$('#pass').value='';
  if(!globe.stop)startGlobe();
  const tick=()=>{$('#clock').textContent=new Date().toISOString().slice(11,19)+' UTC'};tick();clearInterval(clockIv);clockIv=setInterval(tick,1000);
  $('#user').focus();
}
f1.addEventListener('submit',async e=>{
  e.preventDefault();const u=$('#user').value.trim(),p=$('#pass').value;
  if(!u||!p){$('#e1').textContent='Enter your username and password.';return}
  const b=f1.querySelector('.go');b.disabled=true;
  try{
    const r=await api('login',{method:'POST',body:{user:u,pass:p},auth:true});
    if(r.status===404){$('#e1').textContent='Too many tries. Wait 15 minutes.';return}
    if(!r.ok){$('#e1').textContent=r.j.error||'Sign-in failed.';return}
    if(r.j.need2fa){ticket=r.j.ticket;$('#recWrap').hidden=true;$('.otp').hidden=false;$('#useRec').textContent='Use a recovery code instead';f1.hidden=true;f2.hidden=false;$('#p2').classList.add('on');$('#e2').textContent='';otp.forEach(o=>o.value='');$('#rec').value='';otp[0].focus();return}
    enterApp();
  }catch(err){$('#e1').textContent='No answer from the server.'}finally{b.disabled=false}
});
$('#back').addEventListener('click',()=>{f2.hidden=true;f1.hidden=false;$('#p2').classList.remove('on')});
$('#useRec').addEventListener('click',()=>{const on=$('#recWrap').hidden;$('#recWrap').hidden=!on;$('.otp').hidden=on;$('#useRec').textContent=on?'Use the 6-digit code':'Use a recovery code instead';(on?$('#rec'):otp[0]).focus()});
otp.forEach((o,i)=>{
  o.addEventListener('input',()=>{o.value=o.value.replace(/\D/g,'').slice(-1);if(o.value&&otp[i+1])otp[i+1].focus();if(otp.every(x=>x.value))f2.requestSubmit()});
  o.addEventListener('keydown',e=>{if(e.key==='Backspace'&&!o.value&&otp[i-1])otp[i-1].focus()});
  o.addEventListener('paste',e=>{const d=(e.clipboardData.getData('text')||'').replace(/\D/g,'').slice(0,6);if(!d)return;e.preventDefault();d.split('').forEach((c,k)=>{if(otp[k])otp[k].value=c});(otp[d.length]||otp[5]).focus();if(d.length===6)f2.requestSubmit()});
});
f2.addEventListener('submit',async e=>{
  e.preventDefault();
  const code=$('#recWrap').hidden?otp.map(o=>o.value).join(''):$('#rec').value.trim();
  if(!code)return;
  const r=await api('2fa',{method:'POST',body:{ticket,code},auth:true});
  if(r.ok){enterApp();return}
  if(r.status===404){f2.hidden=true;f1.hidden=false;$('#e1').textContent='Too many tries. Wait 15 minutes.';return}
  f2.hidden=true;f1.hidden=false;$('#p2').classList.remove('on');$('#pass').value='';
  $('#e1').textContent=(r.j.error||'Wrong code.')+(r.j.server_time?' The server’s clock reads '+r.j.server_time+'.':'')+' Sign in again.';
  $('#pass').focus();
});

/* ---------- app shell ---------- */
const S={cli:'',ov:null,live:{},series:[],peak:0,moved:0,es:null,ovIv:0,view:'overview',mapStarted:false,started:false,drawer:null};
function enterApp(){
  if(globe.stop)globe.stop();clearInterval(clockIv);
  $('#login').hidden=true;$('#app').hidden=false;
  if(!S.started){S.started=true;gaugeBase()}
  setView(location.hash.slice(1)||'overview');
  loadOverview();clearInterval(S.ovIv);S.ovIv=setInterval(loadOverview,10000);
  openLive();
}
function stopApp(){clearInterval(S.ovIv);if(S.es){S.es.close();S.es=null}}
document.querySelectorAll('.nav button').forEach(b=>b.addEventListener('click',()=>{location.hash=b.dataset.v}));
addEventListener('hashchange',()=>{if(!$('#app').hidden)setView(location.hash.slice(1))});
const VIEWS={overview:['#vOverview','Overview'],tunnels:['#vTunnels','Tunnels'],kharej:['#vKharej','Kharej servers'],settings:['#vSettings','Settings']};
function setView(v){
  if(!VIEWS[v])v='overview';S.view=v;
  Object.entries(VIEWS).forEach(([k,[sel]])=>{$(sel).hidden=k!==v});
  document.querySelectorAll('.nav button').forEach(b=>{if(b.dataset.v===v)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current')});
  $('#vTitle').textContent=VIEWS[v][1];
  if(v==='overview'&&S.ov&&!S.mapStarted)startMap();
  if(v==='settings')loadSettings();
  if(window.PANEL&&PANEL.onView)PANEL.onView(v);
  render();
}
$('#out').addEventListener('click',async()=>{try{await api('logout',{method:'POST'})}catch(e){}showLogin()});

async function loadOverview(){
  if(!S.cli)try{const m=await api('me');if(m.ok)S.cli=m.j.cli}catch(e){}
  try{const r=await api('overview');if(r.ok){S.ov=r.j;if(S.view==='overview'&&!S.mapStarted)startMap();render()}}catch(e){}
}
function openLive(){
  if(S.es)S.es.close();
  const es=new EventSource('api/live');S.es=es;
  es.onopen=()=>{$('#pulse').classList.add('on');$('#liveTxt').textContent='live'};
  es.onerror=()=>{$('#pulse').classList.remove('on');$('#liveTxt').textContent='reconnecting';
    api('me').catch(()=>{})}; // a 401 here sends the page to sign-in
  es.onmessage=(m)=>{
    let d;try{d=JSON.parse(m.data)}catch(e){return}
    S.live={};let down=0,up=0;
    d.tunnels.forEach(t=>{S.live[t.name]=t;down+=t.down;up+=t.up});
    S.series.push({t:d.t,down,up});if(S.series.length>600)S.series.shift();
    S.peak=Math.max(S.peak,down);S.moved+=down;
    renderLive(down,up);
  };
}

/* ---------- rendering ---------- */
function statusOf(t){
  const l=S.live[t.name];
  if(!t.active)return t.enabled?['p-down','Down']:['p-off','Stopped'];
  if(l&&l.metrics&&!l.alive)return ['p-down','No link'];
  if(l&&l.loss>=5)return ['p-slow','Lossy'];
  return ['p-up','Up'];
}
function render(){
  const ov=S.ov;if(!ov)return;
  $('#hName').textContent=ov.host.name||'server';
  $('#hMeta').textContent=(ov.tunnels.some(t=>t.role==='Iran')?'Iran':'Kharej')+' · '+ov.host.version;
  // headline: what is wrong, in words
  const f=$('#find');f.textContent='';
  const down=ov.tunnels.filter(t=>statusOf(t)[0]==='p-down');
  const lossy=ov.tunnels.filter(t=>statusOf(t)[0]==='p-slow');
  const offK=ov.kharej.filter(k=>!k.online);
  const parts=[];
  down.forEach(t=>{const b=el('b',null,t.name);parts.push([b,' is down'])});
  lossy.forEach(t=>{const m=el('em',null,t.name);parts.push([m,' is losing '+S.live[t.name].loss.toFixed(1)+'%'])});
  offK.forEach(k=>{const b=el('b',null,k.host);parts.push([b,' cannot be reached'])});
  (ov.alerts||[]).filter(a=>a.kind!=='down'&&a.kind!=='kharej').forEach(a=>parts.push([el('em',null,a.text),'']));
  if(!ov.twofa)parts.push([el('em',null,'Two-factor sign-in is off'),' · Settings']);
  if(!parts.length)f.appendChild(el('span','ok',ov.tunnels.length?'Everything is up.':'No tunnels yet. Use New tunnel on the Tunnels page, or the manager: '+S.cli+' new'));
  const more=parts.length>4?parts.splice(4).length:0;
  parts.forEach((p,i)=>{if(i)f.append(' · ');f.append(...p)});
  if(more){f.append(' · ');const a=el('a','dim','+'+more+' more');a.href='#system';f.appendChild(a)}
  renderTables();renderWatchdog();renderServer();renderKharej();renderRoutes();
  if(window.PANEL&&PANEL.onRender)PANEL.onRender();
}
function sparkCells(name){if(!S.ov)return el('div','spk');
  const w=(S.ov.watchdog||[]).find(x=>x.name===name);
  const sp=el('div','spk');(w?w.hours:new Array(24).fill(0)).forEach(v=>sp.appendChild(el('i','s'+v)));return sp;
}
function renderTables(){
  const ov=S.ov;
  [['#rows','#tunN']].forEach(([tb,cnt])=>{
    $(cnt).textContent=ov.tunnels.length;const body=$(tb);body.textContent='';
    if(!ov.tunnels.length){const tr=el('tr');const td=el('td','empty','No tunnels on this server yet.');td.colSpan=10;tr.appendChild(td);body.appendChild(tr);return}
    ov.tunnels.forEach(t=>{
      const l=S.live[t.name]||{};const [cls,word]=statusOf(t);const tr=el('tr');tr.dataset.name=t.name;tr.tabIndex=0;
      const td=(c,txt)=>{const d=el('td',c,txt);tr.appendChild(d);return d};
      td('id',t.name);
      td(null,t.role==='Iran'?(t.paired?'Iran ⇄ Kharej':'Iran'):'Kharej');
      const car=td(null,t.carrier||'–');if(t.reverse)car.appendChild(el('span','sub','reverse'));
      const st=td();const p=el('span','pill '+cls);p.append(el('i'),word);st.appendChild(p);
      td('r n',l.metrics?fmtRate(l.down)+' MB/s':'–').dataset.k='down';
      td('r n',l.metrics?fmtRate(l.up)+' MB/s':'–').dataset.k='up';
      td('r n',l.metrics&&l.rtt?l.rtt.toFixed(0)+' ms':'–');
      const lo=td('r n',l.metrics?l.loss.toFixed(1)+'%':'–');if(cls==='p-slow')lo.classList.add('warnc');
      td().appendChild(sparkCells(t.name));
      td('r ports',(t.ports||[]).join(', ')||'–');
      tr.addEventListener('click',()=>openDrawer(t.name));tr.addEventListener('keydown',e=>{if(e.key==='Enter')openDrawer(t.name)});
      body.appendChild(tr);
    });
  });
}
function renderWatchdog(){
  const wd=S.ov.watchdog||[];const hm=$('#hm');hm.textContent='';
  if(!wd.length){hm.appendChild(el('div','empty','Nothing to watch yet.'));}
  let up=0,n=0,outs=0,longest=0,ongoing=0,longestName='';
  wd.forEach((w,r)=>{
    hm.appendChild(el('span','nm',w.name));const row=el('div','hr');
    w.hours.forEach((v,h)=>{const c=el('i','h'+v);c.style.animationDelay=(0.3+(r*24+h)*0.004).toFixed(3)+'s';c.title=w.name+' · '+(24-h)+' h ago';row.appendChild(c)});
    hm.appendChild(row);up+=w.uptime_pct;n++;outs+=w.outages;if(w.longest_s>longest){longest=w.longest_s;longestName=w.name}if(w.ongoing_since)ongoing++;
  });
  $('#hmPad').textContent=wd.reduce((a,w)=>w.name.length>a.length?w.name:a,'');
  const pct=n?up/n:100;const u=$('#wdUp');u.textContent='';u.append(String(Math.floor(pct)));const dec=el('span','dim','.'+(pct%1).toFixed(1).slice(2)+'%');u.appendChild(dec);u.appendChild(el('span','unit','uptime'));
  $('#wdN').textContent=outs;$('#wdL').textContent=fmtDur(longest);$('#wdO').textContent=ongoing;$('#wdO').classList.toggle('bad',ongoing>0);
}
function setBar(id,lab,text,pct){$(lab).textContent=text;const b=$(id);b.style.width=Math.max(0,Math.min(100,pct)).toFixed(0)+'%';b.classList.toggle('hi',pct>=85)}
function renderServer(){
  const h=S.ov.host;
  setBar('#bCpu','#rCpu','load '+h.load1.toFixed(2),h.cpus?h.load1/h.cpus*100:0);
  setBar('#bMem','#rMem','ram '+h.mem_pct.toFixed(0)+'%',h.mem_pct);
  setBar('#bDisk','#rDisk','disk '+h.disk_pct.toFixed(0)+'%',h.disk_pct);
  $('#srvUp').textContent=h.uptime_s?'up '+fmtDur(h.uptime_s):'';
  $('#srvClock').textContent=h.clock_synced?'synced':'not synced';$('#srvClock').className=h.clock_synced?'':'warnc';
  $('#srv2fa').textContent=S.ov.twofa?'on':'off';$('#srv2fa').className=S.ov.twofa?'':'warnc';
}
function khCard(k){
  const c=el('div','kh');
  const top=el('div','khtop');const p=el('span','pill '+(k.online?'p-up':'p-down'));p.append(el('i'),k.online?'online':'unreachable');top.appendChild(p);
  top.appendChild(el('span','lab',k.online?(k.version?'v'+k.version:'')+(k.caps?' · '+k.caps:''):(k.error||'')));c.appendChild(top);
  const fl=el('div','flaps'+(k.host.length>11?' long':''));fl.setAttribute('aria-label',k.host);k.host.toUpperCase().split('').slice(0,20).forEach((ch,i)=>{const s=el('span','flap',ch);s.setAttribute('aria-hidden','true');s.style.animationDelay=(0.2+i*0.05).toFixed(2)+'s';fl.appendChild(s)});c.appendChild(fl);
  c.appendChild(el('div','lab','through '+k.via.join(', ')));
  const ul=el('ul','rtl');(k.tunnels||[]).forEach(t=>{const li=el('li');li.appendChild(el('span',null,t.name));const p=el('span','pill '+(t.health==='ok'?'p-up':t.state==='active'?'p-down':'p-off'));p.append(el('i'),t.health==='ok'?'up':t.state==='active'?'no link':'stopped');li.appendChild(p);ul.appendChild(li)});
  if(k.online&&!(k.tunnels||[]).length)ul.appendChild(el('li','empty','No tunnels listed.'));
  c.appendChild(ul);return c;
}
function renderKharej(){
  const kh=S.ov.kharej;$('#khSub').textContent=kh.length?kh.length+' paired':'';
  const l=$('#khList');l.textContent='';
  if(!kh.length){l.appendChild(el('div','empty','No Kharej server is paired with this one. Pair from the manager: '+S.cli+' scepter'));return}
  kh.forEach(k=>l.appendChild(khCard(k)));
}

/* routes: per Kharej host, the summed live rate of the local tunnels paired with it */
function hostRate(k){let d=0;k.via.forEach(n=>{const l=S.live[n];if(l)d+=l.down});return d}
function renderRoutes(){
  const ov=S.ov;const kh=ov.kharej;
  $('#mapSub').textContent=ov.tunnels.length+' tunnels · '+kh.length+' Kharej';
  const chips=$('#mapChips');chips.textContent='';
  const ch=(cls,t)=>{const c=el('span','chip');const i=el('i');i.style.background=cls;c.append(i,t);chips.appendChild(c)};
  ch('var(--violet)','this server');if(kh.length)ch('var(--green)','Kharej, up');if(kh.some(k=>!k.online))ch('var(--red)','unreachable');
  const r=$('#routes');r.textContent='';
  kh.slice(0,2).forEach(k=>{const b=el('div','rt');b.appendChild(el('div','lab','to '+k.host+' · '+k.via.length+' tunnel'+(k.via.length>1?'s':'')));const v=el('div','mid n');v.dataset.host=k.host;v.append(fmtRate(hostRate(k)));v.appendChild(el('span','unit','MB/s'));b.appendChild(v);r.appendChild(b)});
  const mv=el('div','rt');mv.appendChild(el('div','lab','moved this visit'));const v=el('div','mid n');v.id='movedNum';v.textContent=fmtBytes(S.moved);mv.appendChild(v);r.appendChild(mv);
  placeTips();
}

/* live numbers */
function odo(e,val){
  const str=val.toFixed(1);
  if(e.dataset.len!==String(str.length)){
    e.textContent='';e.dataset.len=str.length;
    const o=el('span','odo');o.setAttribute('aria-hidden','true');const dot=str.indexOf('.');
    str.split('').forEach((ch,i)=>{if(/\d/.test(ch)){const c=el('span','c'+(i>dot?' dec':''));for(let d=0;d<10;d++)c.appendChild(el('span',null,String(d)));o.appendChild(c)}else o.appendChild(el('span','dec',ch))});
    e.appendChild(o);e.appendChild(el('span','unit','MB/s'));
  }
  e.setAttribute('aria-label',str+' megabytes per second');
  const cs=e.querySelectorAll('.c');let k=0;str.split('').forEach(ch=>{if(/\d/.test(ch)){cs[k].style.transform='translateY(-'+ch+'em)';k++}});
}
function renderLive(down,up){
  if(!S.ov)return;
  odo($('#odo'),mb(down));$('#upNow').textContent=mb(up).toFixed(1);$('#peak').textContent=mb(S.peak).toFixed(1);
  // health counts the tunnels meant to run; one stopped by hand is not a problem
  const want=S.ov.tunnels.filter(t=>t.enabled||t.active);const ups=want.filter(t=>statusOf(t)[0]==='p-up').length;
  $('#upChip').lastChild.textContent=ups+' of '+want.length+' up';
  stripes();gauge(want.length?ups/want.length:1,ups,want.length);
  const ls=Object.values(S.live).filter(l=>l.metrics&&l.alive);
  $('#kvRtt').textContent=ls.length?(ls.reduce((a,l)=>a+l.rtt,0)/ls.length).toFixed(0)+' ms':'–';
  $('#kvLoss').textContent=ls.length?Math.max(...ls.map(l=>l.loss)).toFixed(1)+'%':'–';
  $('#kvConns').textContent=Object.values(S.live).reduce((a,l)=>a+(l.conns||0),0).toLocaleString('en-US');
  document.querySelectorAll('#rows tr').forEach(tr=>{const l=S.live[tr.dataset.name];if(!l||!l.metrics)return;tr.querySelector('[data-k=down]').textContent=fmtRate(l.down)+' MB/s';tr.querySelector('[data-k=up]').textContent=fmtRate(l.up)+' MB/s'});
  document.querySelectorAll('#routes [data-host]').forEach(v=>{const k=S.ov.kharej.find(x=>x.host===v.dataset.host);if(k)v.firstChild.textContent=fmtRate(hostRate(k))});
  const mv=$('#movedNum');if(mv)mv.textContent=fmtBytes(S.moved);
  chart();
  if(S.drawer)drawerLive();
  if(window.PANEL&&PANEL.onLive)PANEL.onLive(down,up);
}
function stripes(){
  const svg=$('#sbars');const last=S.series.slice(-30);const n=30,bw=300/n;const top=Math.max(1,...last.map(s=>s.down));
  let s='<defs><pattern id="hz" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="1.6" height="4" fill="#3a3a41"/></pattern></defs>';
  last.forEach((p,i)=>{const x=(n-last.length+i)*bw;const hh=Math.max(3,p.down/top*82);s+=`<rect x="${(x+1).toFixed(2)}" y="${(84-hh).toFixed(2)}" width="${(bw-2).toFixed(2)}" height="${hh.toFixed(2)}" rx="1.5" fill="${i===last.length-1?'#3ee08a':'url(#hz)'}"/>`});
  svg.innerHTML=s;
}
function gaugeBase(){
  const svg=$('#gauge');let s='';const N=46;
  for(let i=0;i<N;i++){const a=Math.PI*(1-i/(N-1));const cx=125,cy=126,r1=108,r2=92;s+=`<line data-i="${i}" x1="${(cx+r1*Math.cos(a)).toFixed(1)}" y1="${(cy-r1*Math.sin(a)).toFixed(1)}" x2="${(cx+r2*Math.cos(a)).toFixed(1)}" y2="${(cy-r2*Math.sin(a)).toFixed(1)}" stroke="#26262a" stroke-width="3.2" stroke-linecap="round"/>`}
  svg.innerHTML=s;
}
function gauge(frac,ups,total){
  const N=46;$('#gauge').querySelectorAll('line').forEach((ln,i)=>{const f=i/(N-1);const on=total&&f<=frac+1e-9;const col=f<.35?'#ff5d62':f<.6?'#ff7a33':f<.8?'#d4f36a':'#3ee08a';ln.setAttribute('stroke',on?col:getComputedStyle(document.body).getPropertyValue('--line').trim()||'#26262a')});
  $('#gNum').textContent=total?ups+'/'+total:'–';$('#gLab').textContent=!total?'no tunnels':ups===total?'all up':(total-ups)+' need attention';
}
function chart(){
  const W=640,H=200,L=40,T=14,B=26;const d=S.series.slice(-300);const n=d.length;const svg=$('#tsvg');
  if(n<2){svg.innerHTML='';return}
  const vals=d.map(p=>mb(p.down));const top=Math.max(1,Math.ceil(Math.max(...vals)/5)*5);
  const X=i=>L+i*(W-L-4)/(n-1),Y=v=>T+(1-v/top)*(H-T-B);
  let s='<defs><pattern id="dp" width="5" height="5" patternUnits="userSpaceOnUse"><circle cx="2.5" cy="2.5" r="0.9" fill="#3ee08a" opacity="0.45"/></pattern><linearGradient id="fm" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity="1"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient><mask id="mk"><rect x="0" y="0" width="640" height="200" fill="url(#fm)"/></mask></defs>';
  for(let k=0;k<=4;k++){const v=top*k/4;s+=`<line x1="${L}" x2="${W}" y1="${Y(v).toFixed(1)}" y2="${Y(v).toFixed(1)}" class="gl"/><text x="0" y="${(Y(v)+3.5).toFixed(1)}">${v.toFixed(v<10?1:0)}</text>`}
  let p='';vals.forEach((v,i)=>{p+=(i?'L':'M')+X(i).toFixed(1)+' '+Y(v).toFixed(1)});
  s+=`<path d="${p}L${X(n-1)} ${Y(0)}L${L} ${Y(0)}Z" fill="url(#dp)" mask="url(#mk)"/><path d="${p}" fill="none" stroke="#3ee08a" stroke-width="2" stroke-linejoin="round"/>`;
  s+=`<circle r="4" class="fgdot" cx="${X(n-1)}" cy="${Y(vals[n-1])}"/>`;
  const span=d[n-1].t-d[0].t;s+=`<text x="${L}" y="${H-6}">${fmtDur(span)} ago</text><text x="${W}" y="${H-6}" text-anchor="end">now · MB/s</text>`;
  svg.innerHTML=s;
  const avg=vals.reduce((a,b)=>a+b,0)/n;$('#fAvg').textContent=avg.toFixed(1)+' MB/s';$('#fPeak').textContent=Math.max(...vals).toFixed(1)+' MB/s';$('#fLow').textContent=Math.min(...vals).toFixed(1)+' MB/s';$('#fMoved').textContent=fmtBytes(S.moved);
  svg.onpointermove=(e)=>{const b=svg.getBoundingClientRect();const px=(e.clientX-b.left)/b.width*W;const i=Math.max(0,Math.min(n-1,Math.round((px-L)/((W-L-4)/(n-1)))));const tt=$('#tt');tt.hidden=false;tt.style.left=(X(i)/W*100)+'%';tt.textContent=vals[i].toFixed(1)+' MB/s · '+new Date(d[i].t*1000).toLocaleTimeString()};
  svg.onpointerleave=()=>{$('#tt').hidden=true};
}

/* ---------- map ---------- */
const MAPB={L0:-11,L1:66,A0:25.5,A1:66};const map={};
function projM(ll,w,h){return [(ll[0]-MAPB.L0)/(MAPB.L1-MAPB.L0)*w,(MAPB.A1-ll[1])/(MAPB.A1-MAPB.A0)*h]}
function buildMap(w,h){
  const pitch=w<520?4.6:5.4,cols=Math.floor(w/pitch),rows=Math.floor(h/pitch),ox=(w-cols*pitch)/2+pitch/2,oy=(h-rows*pitch)/2+pitch/2;
  const pts=[];const ir=projM(IRAN_LL,w,h);let md=1;
  for(let j=0;j<rows;j++)for(let i=0;i<cols;i++){const sx=ox+i*pitch,sy=oy+j*pitch;const lon=MAPB.L0+sx/w*(MAPB.L1-MAPB.L0),lat=MAPB.A1-sy/h*(MAPB.A1-MAPB.A0);const land=isLand(lon,lat);const d=Math.hypot(sx-ir[0],sy-ir[1]);if(d>md)md=d;pts.push([sx,sy,land?1:0,land?regionOf(lon,lat):0,hash(i,j),d,lon,lat])}
  map.pts=pts;map.md=md;map.pitch=pitch;
}
function placeTips(){
  const w=$('#map').clientWidth,h=$('#map').clientHeight;const wrap=$('#mapw');wrap.querySelectorAll('.tip').forEach(t=>t.remove());if(!S.ov)return;
  const tip=(ll,cls,dot,name,sub)=>{const t=el('div','tip '+cls+(S.mapShown?' on':''));const i=el('i');i.style.background=dot;t.append(i,el('b',null,name),el('span','lab',sub));const p=projM(ll,w,h);t.style.left=(p[0]+6)+'px';t.style.top=p[1]+'px';wrap.appendChild(t)};
  tip(IRAN_LL,'lf','var(--violet)',S.ov.host.name||'this server','this server');
  S.ov.kharej.slice(0,ANCHORS.length).forEach((k,i)=>tip(ANCHORS[i],i%2?'dn':'up',k.online?'var(--green)':'var(--red)',k.host,k.online?(k.tunnels.length+' tunnels'):'unreachable'));
}
function startMap(){
  S.mapStarted=true;const c=$('#map');let g=fitCanvas(c);buildMap(g.w,g.h);placeTips();
  new ResizeObserver(()=>{g=fitCanvas(c);buildMap(g.w,g.h);placeTips()}).observe(c);
  const t0=performance.now();setTimeout(()=>{S.mapShown=true;document.querySelectorAll('.tip').forEach(t=>t.classList.add('on'))},RM?0:2100);
  const draw=(now)=>{
    requestAnimationFrame(draw);
    if(document.hidden||$('#vOverview').hidden)return;
    const {x,w,h}=g;const t=(now-t0)/1000;x.clearRect(0,0,w,h);
    const kh=(S.ov?S.ov.kharej:[]).slice(0,ANCHORS.length);
    const intro=RM?1:Math.min(1,t/1.5);const r=map.pitch*0.24;
    for(const p of map.pts){
      const f=Math.max(0,Math.min(1,(intro*1.25*map.md-p[5])/(map.md*0.18)));if(f<=0)continue;
      let kc=null;if(p[2])for(let i=0;i<kh.length;i++){if(Math.hypot(p[6]-ANCHORS[i][0],(p[7]-ANCHORS[i][1])*1.4)<2.2){kc=kh[i].online?C_OK:C_BAD;break}}
      if(p[3]||kc){x.fillStyle=`rgba(${kc||C_IR},${(0.92*f).toFixed(3)})`;x.beginPath();x.arc(p[0],p[1],r*1.08,0,6.283);x.fill()}
      else if(p[2]){x.fillStyle=`rgba(236,236,240,${((0.36+0.2*p[4])*f).toFixed(3)})`;x.beginPath();x.arc(p[0],p[1],r,0,6.283);x.fill()}
      else{x.fillStyle=`rgba(236,236,240,${(0.06*f).toFixed(3)})`;x.beginPath();x.arc(p[0],p[1],r*0.75,0,6.283);x.fill()}
    }
    const a=projM(IRAN_LL,w,h);const ar=RM?1:Math.max(0,Math.min(1,(t-1.1)/1.0));
    kh.forEach((k,i)=>{
      const b=projM(ANCHORS[i],w,h);const col=k.online?C_OK:C_BAD;
      const mx=(a[0]+b[0])/2,my=(a[1]+b[1])/2,lx=b[0]-a[0],ly=b[1]-a[1],len=Math.hypot(lx,ly)||1;
      let nx=-ly/len,ny=lx/len;if(ny>0){nx=-nx;ny=-ny}const qx=mx+nx*len*.14,qy=my+ny*len*.14;
      const B=(s)=>{const v=1-s;return [v*v*b[0]+2*v*s*qx+s*s*a[0],v*v*b[1]+2*v*s*qy+s*s*a[1]]};
      const n=Math.floor(len/4);
      for(let j=0;j<=n*ar;j++){const q=B(j/n);x.fillStyle='rgba(255,255,255,0.28)';x.beginPath();x.arc(q[0],q[1],0.8,0,6.283);x.fill()}
      // packets: speed follows the live rate to this host; none when unreachable
      const rate=mb(hostRate(k));
      if(ar>=1&&k.online&&rate>0.01){const sp=0.05+Math.min(0.3,rate/120);
        for(let m=0;m<2;m++){const head=((t*sp+m*0.5+i*0.27)%1);for(let j=0;j<26;j++){const s=head-j*0.007;if(s<0)break;const q=B(s);const al=1-j/26;x.fillStyle=`rgba(${col},${(al*0.95).toFixed(3)})`;x.beginPath();x.arc(q[0],q[1],j===0?2.2:0.6+1.2*al,0,6.283);x.fill()}}}
      const ph=(t*0.5+i*0.3)%1;x.strokeStyle=`rgba(${col},${((1-ph)*0.55).toFixed(3)})`;x.lineWidth=1;x.beginPath();x.arc(b[0],b[1],3+ph*18,0,6.283);x.stroke();
      x.fillStyle='#f3f3f4';x.beginPath();x.arc(b[0],b[1],2.6,0,6.283);x.fill();
    });
    const ph=(t*0.5+.5)%1;x.strokeStyle=`rgba(${C_IR},${((1-ph)*0.6).toFixed(3)})`;x.beginPath();x.arc(a[0],a[1],3+ph*22,0,6.283);x.stroke();
    x.fillStyle='#f3f3f4';x.beginPath();x.arc(a[0],a[1],3,0,6.283);x.fill();
  };
  requestAnimationFrame(draw);
}

/* ---------- tunnel drawer ---------- */
async function openDrawer(name){
  S.drawer=name;$('#drawer').hidden=false;const t=S.ov.tunnels.find(x=>x.name===name)||{};
  $('#dName').textContent=name;$('#dSub').textContent=[t.role,t.carrier,t.reverse?'reverse':'',t.uptime?'up '+t.uptime:''].filter(Boolean).join(' · ');
  const info=$('#dInfo');info.textContent='';
  const kv=(k,v)=>{const d=el('div','kv');d.append(el('span',null,k),el('span','n',v));info.appendChild(d)};
  if(t.peer)kv('Kharej',t.peer);kv('Ports',(t.ports||[]).join(', ')||'–');kv('Paired',t.paired?'yes':'no');kv('Starts at boot',t.enabled?'yes':'no');
  const [pc,pw]=statusOf(t);const pl=$('#dPill');pl.textContent='';const pp=el('span','pill '+pc);pp.append(el('i'),pw);pl.appendChild(pp);
  drawerLive();$('#dX').focus();if(window.PANEL&&PANEL.onDrawer)PANEL.onDrawer(name,t);
  const [h,l]=await Promise.all([api('tunnels/'+encodeURIComponent(name)+'/history').catch(()=>null),api('tunnels/'+encodeURIComponent(name)+'/logs?n=200').catch(()=>null)]);
  if(S.drawer!==name)return;
  drawHist(h&&h.ok&&Array.isArray(h.j)?h.j:[]);
  showLog(l);
}
function showLog(l){const pre=$('#dLog');pre.textContent=l&&l.ok?(l.j.lines.join('\n')||'(empty)'):'Could not read the log.';pre.scrollTop=pre.scrollHeight}
$('#dLogR').addEventListener('click',async()=>{if(!S.drawer)return;showLog(await api('tunnels/'+encodeURIComponent(S.drawer)+'/logs?n=200').catch(()=>null))});
function drawerLive(){const l=S.live[S.drawer]||{};const set=(id,v,u)=>{const e=$(id);e.textContent=v;if(u)e.appendChild(el('span','unit',u))};
  set('#dDown',l.metrics?fmtRate(l.down):'–',l.metrics?'MB/s':'');set('#dUp',l.metrics?fmtRate(l.up):'–',l.metrics?'MB/s':'');set('#dRtt',l.metrics&&l.rtt?l.rtt.toFixed(0):'–',l.metrics&&l.rtt?'ms':'');set('#dLoss',l.metrics?l.loss.toFixed(1):'–',l.metrics?'%':'')}
function drawHist(d){
  const svg=$('#dChart');const W=640,H=180,L=40,T=12,B=24;
  if(d.length<2){svg.innerHTML='<text x="320" y="90" text-anchor="middle">No history yet: the tunnel keeps 5 minutes once it runs.</text>';return}
  const v=d.map(s=>mb(s.rate_bps||0)),r=d.map(s=>s.srtt_ms||0);const top=Math.max(1,Math.ceil(Math.max(...v)/5)*5),rt=Math.max(10,Math.max(...r)*1.2);const n=d.length;
  const X=i=>L+i*(W-L-4)/(n-1),Y=x=>T+(1-x/top)*(H-T-B),YR=x=>T+(1-x/rt)*(H-T-B);
  let s='';for(let k=0;k<=4;k++){const y=top*k/4;s+=`<line x1="${L}" x2="${W}" y1="${Y(y).toFixed(1)}" y2="${Y(y).toFixed(1)}" class="gl"/><text x="0" y="${(Y(y)+3.5).toFixed(1)}">${y.toFixed(y<10?1:0)}</text>`}
  let p='',q='';v.forEach((x,i)=>{p+=(i?'L':'M')+X(i).toFixed(1)+' '+Y(x).toFixed(1)});r.forEach((x,i)=>{q+=(i?'L':'M')+X(i).toFixed(1)+' '+YR(x).toFixed(1)});
  s+=`<path d="${q}" fill="none" stroke="#9a8cff" stroke-width="1.4" stroke-dasharray="3 3"/><path d="${p}" fill="none" stroke="#3ee08a" stroke-width="2"/>`;
  s+=`<text x="${L}" y="${H-4}">${fmtDur(d[n-1].t-d[0].t)} ago</text><text x="${W}" y="${H-4}" text-anchor="end">— sending rate MB/s · - - latency (max ${Math.max(...r).toFixed(0)} ms)</text>`;
  svg.innerHTML=s;
}
const closeDrawer=()=>{S.drawer=null;$('#drawer').hidden=true};
$('#dX').addEventListener('click',closeDrawer);$('#drawer').addEventListener('click',e=>{if(e.target===$('#drawer'))closeDrawer()});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&S.drawer)closeDrawer()});

/* ---------- settings ---------- */
async function loadSettings(){
  const r=await api('me');if(!r.ok)return;const on=r.j.twofa;
  document.querySelectorAll('[data-cli]').forEach(e=>{e.textContent=r.j.cli+' '+e.dataset.cli});
  $('#tfChip').textContent=on?'on':'off';$('#tfOff').hidden=on;$('#tfOnBox').hidden=!on;
  $('#tfLeft').textContent=on?r.j.recovery_left+' recovery codes left.':'';
}
$('#tfStart').addEventListener('click',async()=>{
  const r=await api('settings/2fa/setup',{method:'POST'});if(!r.ok)return;
  $('#tfQR').innerHTML=r.j.svg;$('#tfKey').textContent=r.j.secret;$('#tfSetup').hidden=false;$('#tfStart').hidden=true;$('#tfCode').focus();
});
$('#tfOn').addEventListener('click',async()=>{
  const r=await api('settings/2fa/enable',{method:'POST',body:{code:$('#tfCode').value.trim()}});
  if(!r.ok){$('#tfErr').textContent=r.j.error||'Failed.';return}
  $('#tfErr').textContent='';$('#tfSetup').hidden=true;$('#tfStart').hidden=false;$('#tfCode').value='';
  await loadSettings();$('#tfRec').hidden=false;$('#tfRecList').textContent=r.j.recovery.join('\n');loadOverview();
});
$('#tfOffBtn').addEventListener('click',async()=>{
  const r=await api('settings/2fa/disable',{method:'POST',body:{pass:$('#tfOffPass').value,code:$('#tfOffCode').value.trim()}});
  if(!r.ok){$('#tfOffErr').textContent=r.j.error||'Failed.';return}
  $('#tfOffErr').textContent='';$('#tfOffPass').value='';$('#tfOffCode').value='';$('#tfRec').hidden=true;loadSettings();loadOverview();
});
$('#pwBtn').addEventListener('click',async()=>{
  const r=await api('settings/password',{method:'POST',body:{old:$('#pwOld').value,new:$('#pwNew').value}});
  $('#pwErr').textContent=r.ok?'':(r.j.error||'Failed.');if(r.ok){$('#pwOld').value='';$('#pwNew').value='';$('#pwErr').textContent='';$('#pwBtn').textContent='Changed';setTimeout(()=>{$('#pwBtn').textContent='Change'},2000)}
});
$('#outAll').addEventListener('click',async()=>{try{await api('logout-all',{method:'POST'})}catch(e){}showLogin()});

window.PANEL={api,el,$,S,render,loadOverview,fmtBytes,fmtDur,fmtRate,mb,openDrawer,closeDrawer,VIEWS,setView,statusOf,sparkCells,gaugeArc:null};

/* ---------- boot ---------- */
markDots();
document.querySelectorAll('[data-title]').forEach(e=>{e.textContent=document.title});
api('me',{auth:true}).then(r=>{if(r.ok)enterApp();else showLogin()}).catch(()=>showLogin());
})();
