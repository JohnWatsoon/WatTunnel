// Panel actions, jobs, traffic, system and settings pages (phases 2-4). Plain JS over app.js's helpers
// (window.PANEL). No product name in this file: it is served before sign-in.
(function(){
"use strict";
const P=window.PANEL;const {api,el,$,S}=P;
const store={get(k){try{return localStorage.getItem(k)}catch(e){return null}},set(k,v){try{localStorage.setItem(k,v)}catch(e){}}};
P.VIEWS.traffic=['#vTraffic','Traffic'];P.VIEWS.system=['#vSystem','System'];
function when(t){const d=new Date(t*1000);return d.toLocaleDateString(undefined,{month:'short',day:'numeric'})+' '+d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'})}

/* ---------- theme ---------- */
function applyTheme(){const t=store.get('theme')||'system';const r=document.documentElement;if(t==='system')r.removeAttribute('data-theme');else r.dataset.theme=t;
  document.querySelectorAll('[data-theme-set]').forEach(b=>b.classList.toggle('on',b.dataset.themeSet===t))}
document.querySelectorAll('[data-theme-set]').forEach(b=>b.addEventListener('click',()=>{store.set('theme',b.dataset.themeSet);applyTheme()}));
applyTheme();

/* ---------- toasts ---------- */
function toast(msg,bad){const t=el('div','toast'+(bad?' bad':''),msg);$('#toasts').appendChild(t);setTimeout(()=>t.remove(),bad?9000:4500)}

/* ---------- dialog: fields + buttons, resolves with the values or null ---------- */
function ask(title,{text,fields=[],ok='Go ahead',danger=false,full=false,err=''}={}){
  return new Promise(res=>{
    const d=$('#dlg');$('#dlgT').textContent=title;const b=$('#dlgB');b.textContent='';$('#dlgE').textContent=err;
    if(text)b.appendChild(el('p','note',text));
    const all=fields.slice();
    if(full){b.appendChild(el('p','note','This needs your password and a fresh code from your authenticator app.'));all.push({k:'password',label:'Password',type:'password'},{k:'code',label:'Code',mode:'numeric'})}
    const inputs={};
    all.forEach(f=>{const w=el('div','fld');const id='dlg_'+f.k;const l=el('label',null,f.label);l.htmlFor=id;let i;
      if(f.options){i=el('select');f.options.forEach(([v,t])=>{const o=el('option',null,t);o.value=v;i.appendChild(o)})}
      else if(f.area){i=el('textarea');i.rows=f.rows||3;i.spellcheck=false}
      else{i=el('input');i.type=f.type||'text';if(f.mode)i.inputMode=f.mode;i.autocomplete=f.type==='password'?'current-password':'off';i.spellcheck=false}
      i.id=id;if(f.value!=null)i.value=f.value;if(f.ph)i.placeholder=f.ph;w.append(l,i);if(f.hint)w.appendChild(el('div','lab mt4',f.hint));b.appendChild(w);inputs[f.k]=i;
      if(f.onchange)i.addEventListener('change',()=>f.onchange(i.value,inputs))});
    Object.values(inputs).forEach(i=>i.dispatchEvent(new Event('change')));
    const a=$('#dlgA');a.textContent='';
    const cancel=el('button','btn sec','Cancel');cancel.type='button';const go=el('button','btn pri'+(danger?' danger':''),ok);go.type='submit';a.append(cancel,go);
    let settled=false;const done=v=>{if(settled)return;settled=true;d.oncancel=null;d.close();res(v)};
    cancel.onclick=()=>done(null);d.onclose=null;d.oncancel=e=>{e.preventDefault();done(null)};
    $('#dlgF').onsubmit=e=>{e.preventDefault();const v={};Object.entries(inputs).forEach(([k,i])=>{v[k]=i.value.trim()});done(v)};
    d.showModal();const first=Object.values(inputs)[0];(first||go).focus();
  });
}

/* ---------- act: one call with every answer the server can give ---------- */
// opts: {full, title, confirm (text), danger, fields, body}
async function act(path,opts={}){
  let body=Object.assign({},opts.body||{});let err='';
  if(opts.confirm||opts.full||opts.fields){
    const v=await ask(opts.title||'Are you sure?',{text:opts.confirm,fields:opts.fields,full:opts.full,danger:opts.danger,ok:opts.ok});
    if(!v)return null;Object.assign(body,v);
  }
  for(let i=0;i<4;i++){
    let r;try{r=await api(path,{method:opts.method||'POST',body})}catch(e){toast('No answer from the server.',true);return null}
    if(r.ok){if(r.j.job){openJob(r.j.job)}return r.j}
    if(r.status===409&&r.j.lastlink){const v=await ask('Last link to '+r.j.host,{text:r.j.error,fields:[{k:'confirm',label:'Tunnel name'}],danger:true,ok:'Go ahead'});if(!v)return null;body.confirm=v.confirm;continue}
    if(r.status===403&&r.j.reauth){err=r.j.error;const v=await ask(opts.title||'Confirm',{full:true,err});if(!v)return null;Object.assign(body,v);continue}
    toast(r.j.error||('Failed ('+r.status+').'),true);return null;
  }
  return null;
}
P.act=act;

/* ---------- jobs: a progress panel that survives closing and a restart of the panel ---------- */
let jobT=0;
async function openJob(id){
  clearTimeout(jobT);
  const d=$('#dlg');$('#dlgE').textContent='';const b=$('#dlgB');b.textContent='';
  const st=el('span','pill p-slow');st.append(el('i'),'running');const pre=el('pre','log');const res=el('div','mt8');b.append(st,pre,res);
  const a=$('#dlgA');a.textContent='';const close=el('button','btn sec','Close (it keeps running)');close.type='button';close.onclick=()=>{clearTimeout(jobT);d.close()};a.appendChild(close);
  $('#dlgF').onsubmit=e=>e.preventDefault();d.onclose=null;d.oncancel=()=>clearTimeout(jobT);
  if(!d.open)d.showModal();
  let misses=0;
  const tick=async()=>{
    let r=null;try{r=await api('jobs/'+id,{auth:true})}catch(e){}
    if(!r||!r.ok){misses++;st.lastChild.textContent=misses>3?'waiting for the panel to come back':'running';jobT=setTimeout(tick,2000);return}
    misses=0;const j=r.j;$('#dlgT').textContent=j.title;
    const atEnd=pre.scrollTop+pre.clientHeight>=pre.scrollHeight-8;
    pre.textContent=(j.log||[]).filter(l=>!/^TOKEN=/.test(l)).join('\n')||'…';if(atEnd)pre.scrollTop=pre.scrollHeight;
    const cls={running:'p-slow',done:'p-up',failed:'p-down',lost:'p-down'}[j.state];st.className='pill '+cls;st.lastChild.textContent={running:'running',done:'done',failed:'failed (code '+j.rc+')',lost:'no end state (the job stopped without a code)'}[j.state];
    if(j.state==='running'){jobT=setTimeout(tick,1000);return}
    close.textContent='Close';res.textContent='';
    if(j.result&&j.result.TOKEN)res.appendChild(tokenBtn(j.result.TOKEN));
    if(j.result&&j.result.LINK)res.appendChild(el('div','lab','link: '+j.result.LINK));
    toast(j.title+(j.state==='done'?': done':': failed'),j.state!=='done');P.loadOverview();
  };
  tick();
}
P.openJob=openJob;
function tokenBtn(tok){const w=el('div');const b=el('button','btn sec sm','Show the token');b.type='button';b.onclick=()=>{w.textContent='';const t=el('pre','rec',tok);const c=el('button','btn sec sm','Copy');c.type='button';c.onclick=()=>{navigator.clipboard&&navigator.clipboard.writeText(tok);toast('Copied')};w.append(t,c)};w.appendChild(b);return w}

/* ---------- tunnel drawer actions ---------- */
P.onDrawer=(name,t)=>{
  const a=$('#dActs');a.textContent='';const enc=encodeURIComponent(name);
  const btn=(txt,cls,fn)=>{const b=el('button','btn sm '+(cls||'sec'),txt);b.type='button';b.onclick=fn;a.appendChild(b)};
  if(t.active){btn('Restart',null,()=>act('tunnels/'+enc+'/restart').then(r=>r&&toast(name+' restarted')));btn('Stop','sec danger',()=>act('tunnels/'+enc+'/stop',{confirm:'Stop '+name+'? Its users lose the connection.',title:'Stop '+name,danger:true}).then(r=>r&&toast(name+' stopped')))}
  else btn('Start','pri',()=>act('tunnels/'+enc+'/start').then(r=>r&&toast(name+' started')));
  if(t.role==='Iran'){btn('Speed test',null,()=>act('tunnels/'+enc+'/speedtest',{title:'Speed test of '+name,fields:[{k:'mb',label:'Megabytes each way',value:'10',mode:'numeric'}],ok:'Run'}).then(()=>{}));
    btn('Re-test carriers',null,()=>act('tunnels/'+enc+'/retest',{confirm:'Tests every carrier again (auto tunnels) and switches to the best. The tunnel restarts if it switches.',title:'Re-test carriers'}))}
  btn('Ports',null,async()=>{const v=await ask('Ports of '+name,{fields:[{k:'ports',label:'One mapping per line: 443, 8443:443, 53/udp',area:true,rows:5,value:(t.ports||[]).join('\n')}],ok:'Save'});
    if(!v)return;const r=await act('tunnels/'+enc+'/ports',{method:'PUT',body:{ports:v.ports.split(/[\n,]+/)}});if(r){toast(r.note||'Saved');P.loadOverview()}});
  btn('Limit a port',null,async()=>{const v=await ask('Limit a port of '+name,{fields:[{k:'port',label:'Port',mode:'numeric'},{k:'rate',label:'Rate (e.g. 10mbit, empty = none)'},{k:'quota',label:'Quota (e.g. 50G, empty = none)'},{k:'period',label:'Quota resets every',options:[['month','month'],['week','week'],['day','day']]}],ok:'Save'});
    if(!v)return;if(await act('tunnels/'+enc+'/limit',{method:'PUT',body:v}))toast('Saved. Limits apply within seconds.')});
  btn('Show token',null,async()=>{const r=await act('tunnels/'+enc+'/token',{full:true,title:'Show the token of '+name});if(!r)return;
    const b=$('#dlgB');await new Promise(res=>{const d=$('#dlg');$('#dlgT').textContent='Token of '+name;$('#dlgE').textContent='';b.textContent='';if(r.svg){const q=el('div','qr');q.innerHTML=r.svg;b.appendChild(q)}b.appendChild(tokenBtn(r.token));const a2=$('#dlgA');a2.textContent='';const c=el('button','btn sec','Close');c.type='button';c.onclick=()=>{d.close();res()};a2.appendChild(c);$('#dlgF').onsubmit=e=>e.preventDefault();d.onclose=res;d.showModal()})});
  btn('Delete','sec danger',async()=>{const r=await act('tunnels/'+enc+'/delete',{full:true,danger:true,title:'Delete '+name,confirm:'Stops '+name+' and deletes its config, key and token on this server. Its Kharej side stays (delete it from the Kharej page).',ok:'Delete'});if(r)P.closeDrawer()});
};

/* ---------- bulk and new tunnel ---------- */
document.querySelectorAll('[data-bulk]').forEach(b=>b.addEventListener('click',async()=>{
  const a=b.dataset.bulk;const r=await act('bulk',{body:{action:a},title:a[0].toUpperCase()+a.slice(1)+' every tunnel',confirm:a==='stop'?'Every tunnel on this server stops; users lose their connections.':'Every tunnel on this server '+a+'s.',danger:a==='stop'});
  if(r){const bad=Object.entries(r.results).filter(([,v])=>v!=='ok');toast(bad.length?bad.map(([k,v])=>k+': '+v).join('; '):'Done',bad.length>0);P.loadOverview()}}));
$('#newBtn').addEventListener('click',async()=>{
  const ov=S.ov||{tunnels:[]};const vias=ov.tunnels.filter(t=>t.paired&&t.active);
  const fields=[{k:'where',label:'Where',options:vias.length?[['both','On Kharej and here'],['here','Here only, from a token']]:[['here','Here only, from a token']],
      onchange:(v,inp)=>{const both=v==='both';['via','carrier'].forEach(k=>inp[k]&&(inp[k].parentNode.hidden=!both));inp.token&&(inp.token.parentNode.hidden=both)}},
    {k:'token',label:'Token from Kharej (wat1:...)',area:true,rows:3},
    {k:'via',label:'Kharej server, reached through',options:vias.map(t=>[t.name,(t.peer||t.name)+' (via '+t.name+')'])},
    {k:'carrier',label:'Carrier',options:[['auto','auto: test them all here and pick the best'],['wss','wss: TLS websocket, the safe default'],['tls','tls'],['tcp','tcp'],['udp','udp'],['icmp','icmp (ping)'],['grpc','grpc'],['h2','h2'],['ws','ws'],['h2c','h2c']]},
    {k:'map',label:'Ports',ph:'39901:18999, 8443:443',hint:'public port here : port on Kharej, comma-separated'},
    {k:'name',label:'Name (empty = automatic)'},
    {k:'test',label:'Carrier test (auto tokens)',options:[['normal','normal'],['fast','fast'],['anti','anti-censor grid'],['reverse','reverse only'],['extended','extended (with the shaped carriers)']]}];
  await act('new',{title:'New tunnel',fields,ok:'Create'});
});

/* ---------- Kharej cards: actions ---------- */
P.onRender=()=>{
  document.querySelectorAll('#khFull .card').forEach((card,i)=>{
    const k=S.ov.kharej[i];if(!k||card.dataset.acts)return;card.dataset.acts='1';const host=encodeURIComponent(k.host);
    card.querySelectorAll('ul.rtl li').forEach((li,j)=>{const rt=k.tunnels[j];if(!rt)return;const w=el('span','rowacts');
      [['restart','Restart'],['stop','Stop'],['start','Start']].forEach(([a,t])=>{const b=el('button','btn sm sec'+(a==='stop'?' danger':''),t);b.type='button';b.onclick=()=>act('kharej/'+host+'/tunnel',{body:{name:rt.name,action:a},confirm:a==='stop'?'Stop '+rt.name+' on '+k.host+'?':null,title:t+' '+rt.name,danger:a==='stop'}).then(r=>r&&toast(rt.name+': '+a+' done'));w.appendChild(b)});
      const kb=el('button','btn sm sec','New key');kb.type='button';kb.onclick=async()=>{const r=await act('kharej/'+host+'/keyrotate',{full:true,body:{name:rt.name},title:'New key for '+rt.name,confirm:'Kharej makes a new key and restarts '+rt.name+'. Its twin here switches by itself; other Iran servers need the new token.',danger:true});if(r){toast(r.local?r.local+' here uses the new key':'Kharej has the new key; no twin here, use the token',!r.ok);if(r.warning)toast(r.warning,true)}};w.appendChild(kb);
      li.appendChild(w)});
    if(!k.online)return;
    const tools=el('div','tools mt14');const add=(t,cls,fn)=>{const b=el('button','btn sm '+cls,t);b.type='button';b.onclick=fn;tools.appendChild(b)};
    add('Update Kharej','sec',async()=>{const r=await act('kharej/'+host+'/update',{full:true,title:'Update '+k.host,confirm:'Kharej downloads the latest release, checks its signature and restarts its tunnels. It rolls back by itself if the new version fails.'});if(r)toast(r.note||'Update started')});
    add('Backup','sec',async()=>{const body=await ask('Download a backup of '+k.host,{full:true,text:'It holds every tunnel key of that server: keep it private.',ok:'Download'});if(body)download('kharej/'+host+'/backup',body)});
    add('Status','sec',async()=>{const r=await api('kharej/'+host+'/status');showJSON('Update status of '+k.host,r)});
    add('Audit','sec',async()=>{const r=await api('kharej/'+host+'/audit');showJSON('Audit of '+k.host,r,true)});
    card.appendChild(tools);
  });
  if(S.view==='system')renderUpdates();
  notifyAlerts();
};
function showJSON(title,r,logs){const d=$('#dlg');$('#dlgT').textContent=title;$('#dlgE').textContent=r.ok?'':(r.j.error||'Failed');const b=$('#dlgB');b.textContent='';
  const pre=el('pre','log');pre.textContent=r.ok?(logs&&r.j.logs?r.j.logs.join('\n'):JSON.stringify(r.j,null,2)):'';b.appendChild(pre);
  const a=$('#dlgA');a.textContent='';const c=el('button','btn sec','Close');c.type='button';c.onclick=()=>d.close();a.appendChild(c);$('#dlgF').onsubmit=e=>e.preventDefault();d.showModal()}

// download: a POST (password + code in the body) that answers a file
async function download(path,body){
  let r;try{r=await fetch('api/'+path,{method:'POST',headers:{'X-Requested-With':'panel','Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)})}catch(e){toast('No answer from the server.',true);return}
  if(!r.ok){let j={};try{j=await r.json()}catch(e){}toast(j.error||'Failed ('+r.status+')',true);return}
  const cd=r.headers.get('Content-Disposition')||'';const m=/filename="([^"]+)"/.exec(cd);const blob=await r.blob();
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=m?m[1]:'download';document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},1000);
}

/* ---------- browser notifications ---------- */
const seenAlerts=new Set();let alertsPrimed=false;
function notifyAlerts(){
  const al=(S.ov&&S.ov.alerts)||[];
  if(alertsPrimed&&store.get('notify')==='1'&&window.Notification&&Notification.permission==='granted')al.forEach(a=>{if(!seenAlerts.has(a.key))try{new Notification(document.title,{body:a.text,tag:a.key})}catch(e){}});
  al.forEach(a=>seenAlerts.add(a.key));alertsPrimed=true;
}
$('#stNotify').checked=store.get('notify')==='1';
$('#stNotify').addEventListener('change',async e=>{
  if(e.target.checked){if(!window.Notification){toast('This browser has no notifications.',true);e.target.checked=false;return}
    const p=await Notification.requestPermission();if(p!=='granted'){toast('The browser did not allow notifications (an untrusted certificate blocks them).',true);e.target.checked=false;return}}
  store.set('notify',e.target.checked?'1':'0');
});

/* ---------- views ---------- */
P.onView=v=>{if(v==='traffic')loadTraffic();if(v==='system')loadSystem();if(v==='settings')loadSettings2()};

async function loadTraffic(){
  const [r,sp]=await Promise.all([api('traffic?days=30'),api('speedtests')]);
  if(r.ok){
    const days=r.j.days;const svg=$('#trDays');const W=640,H=200,L=44,B=24,T=10;
    const tot=days.map(d=>Object.values(d.tunnels).reduce((a,v)=>a+v[0],0));const top=Math.max(1,...tot);const n=Math.max(1,days.length);const bw=(W-L)/n;
    let s='';for(let k=0;k<=3;k++){const y=T+(H-T-B)*k/3;s+=`<line class="gl" x1="${L}" x2="${W}" y1="${y.toFixed(1)}" y2="${y.toFixed(1)}"/><text x="0" y="${(y+4).toFixed(1)}">${P.fmtBytes(top*(1-k/3))}</text>`}
    days.forEach((d,i)=>{const h=Math.max(1,tot[i]/top*(H-T-B));s+=`<rect class="bar" x="${(L+i*bw+1).toFixed(1)}" y="${(H-B-h).toFixed(1)}" width="${Math.max(1,bw-2).toFixed(1)}" height="${h.toFixed(1)}" rx="1.5"><title>${d.day}: ${P.fmtBytes(tot[i])}</title></rect>`});
    if(days.length)s+=`<text x="${L}" y="${H-6}">${days[0].day}</text><text x="${W}" y="${H-6}" text-anchor="end">${days[days.length-1].day}</text>`;else s+=`<text x="320" y="100" text-anchor="middle">No traffic recorded yet: the panel counts from when it started.</text>`;
    svg.innerHTML=s;
    const tb=$('#trRows');tb.textContent='';const t=r.j.totals;
    Object.keys(t).sort().forEach(n=>{const tr=el('tr');const f=k=>{const v=t[n][k]||[0,0];return P.fmtBytes(v[0])+' ↓ · '+P.fmtBytes(v[1])+' ↑'};tr.append(el('td','id',n),el('td','r n',f('today')),el('td','r n',f('week')),el('td','r n',f('month')));tb.appendChild(tr)});
    if(!Object.keys(t).length){const tr=el('tr');const td=el('td','empty','Nothing yet.');td.colSpan=4;tr.appendChild(td);tb.appendChild(tr)}
  }
  const sel=$('#spTun');const cur=sel.value;sel.textContent='';(S.ov?S.ov.tunnels:[]).filter(t=>t.role==='Iran').forEach(t=>{const o=el('option',null,t.name);o.value=t.name;sel.appendChild(o)});if(cur)sel.value=cur;
  const tb=$('#spRows');tb.textContent='';
  if(sp.ok)sp.j.rows.forEach(x=>{const tr=el('tr');tr.append(el('td','n',when(x.t)),el('td','id',x.name),el('td',null,x.carrier||'–'),el('td','r n',x.down?x.down.toFixed(2)+' MB/s':'–'),el('td','r n',x.up?x.up.toFixed(2)+' MB/s':'–'),el('td','lab',(x.auto?'scheduled ':'')+(x.error||'')));tb.appendChild(tr)});
  if(sp.ok&&!sp.j.rows.length){const tr=el('tr');const td=el('td','empty','No speed tests yet.');td.colSpan=6;tr.appendChild(td);tb.appendChild(tr)}
}
$('#spRun').addEventListener('click',async()=>{const n=$('#spTun').value;if(!n)return;await act('tunnels/'+encodeURIComponent(n)+'/speedtest',{body:{mb:10}});});

function renderUpdates(){
  const u=$('#upList');u.textContent='';if(!S.ov)return;
  const kv=(k,v)=>{const d=el('div','kv');d.append(el('span',null,k),el('span','n',v));u.appendChild(d)};
  kv('This server',S.ov.host.version);S.ov.kharej.forEach(k=>kv(k.host,k.online?(k.version||'?'):'unreachable'));
}
async function loadSystem(){
  renderUpdates();
  const [b,al,jb,au]=await Promise.all([api('backups'),api('alerts'),api('jobs'),api('audit')]);
  const bl=$('#bkList');bl.textContent='';
  if(b.ok){if(!b.j.backups.length)bl.appendChild(el('p','note','No backups yet.'));
    b.j.backups.forEach(x=>{const r=el('div','kv');const l=el('span',null,when(x.t)+(x.auto?' · scheduled':''));const w=el('span','rowacts');w.appendChild(el('span','lab',P.fmtBytes(x.size)));
      const dl=el('button','btn sm sec','Download');dl.type='button';dl.onclick=async()=>{const body=await ask('Download this backup',{full:true,text:'It holds every tunnel key of this server: keep it private.',ok:'Download'});if(body)download('backups/'+encodeURIComponent(x.name)+'/download',body)};
      const del=el('button','btn sm sec danger','Delete');del.type='button';del.onclick=async()=>{if(await act('backups/'+encodeURIComponent(x.name)+'/delete',{confirm:'Delete this backup file?',danger:true,title:'Delete backup'}))loadSystem()};
      w.append(dl,del);r.append(l,w);bl.appendChild(r)})}
  const ll=$('#alList');ll.textContent='';
  if(al.ok){al.j.active.forEach(a=>{const r=el('div','kv');const p=el('span','pill p-down');p.append(el('i'),'now');r.append(el('span',null,a.text),p);ll.appendChild(r)});
    al.j.history.slice(0,15).forEach(a=>{const r=el('div','kv');r.append(el('span','dim',a.text),el('span','lab',when(a.since)+' – '+when(a.cleared)));ll.appendChild(r)});
    if(!al.j.active.length&&!al.j.history.length)ll.appendChild(el('p','note','No alerts.'))}
  const jl=$('#jbList');jl.textContent='';
  if(jb.ok){jb.j.jobs.forEach(j=>{const r=el('div','kv');const b2=el('button','txt',j.title);b2.type='button';b2.onclick=()=>openJob(j.id);const p=el('span','pill '+({running:'p-slow',done:'p-up'}[j.state]||'p-down'));p.append(el('i'),j.state);r.append(b2,p);jl.appendChild(r)});
    if(!jb.j.jobs.length)jl.appendChild(el('p','note','No jobs yet.'))}
  const at=$('#auRows');at.textContent='';
  if(au.ok)au.j.rows.slice(0,100).forEach(x=>{const tr=el('tr');tr.append(el('td','n',when(x.t)),el('td',null,x.user||''),el('td','n',x.ip),el('td',null,x.action),el('td','id',x.target||''),el('td','lab',x.result||''));at.appendChild(tr)});
}
$('#upHere').addEventListener('click',()=>act('update',{full:true,title:'Update this server',confirm:'Downloads the latest release, checks its signature, swaps the binary and restarts the tunnels and this panel. Open connections drop for a few seconds.'}));
$('#upBack').addEventListener('click',()=>act('rollback',{full:true,title:'Roll back',confirm:'Goes back to the previous version and restarts the tunnels and this panel.',danger:true}));
$('#bkNow').addEventListener('click',async()=>{if(await act('backups'))setTimeout(loadSystem,1500)});
$('#bkRestore').addEventListener('click',async()=>{
  const f=$('#bkFile').files[0];if(!f){toast('Pick a backup file first.',true);return}
  if(f.size>6*1024*1024){toast('That file is too big for a settings backup.',true);return}
  const buf=new Uint8Array(await f.arrayBuffer());let bin='';for(let i=0;i<buf.length;i+=32768)bin+=String.fromCharCode.apply(null,buf.subarray(i,i+32768));
  await act('restore',{full:true,danger:true,title:'Restore '+f.name,confirm:'Writes the tunnel settings and keys from the backup over the ones on this server. Running tunnels keep running until you restart them.',body:{data:btoa(bin)},ok:'Restore'});
});

/* ---------- settings (phase 4) ---------- */
async function loadSettings2(){
  const [r,ss]=await Promise.all([api('settings'),api('settings/sessions')]);
  if(r.ok){const j=r.j;$('#stTitle').value=j.title;$('#stPath').value=j.path;$('#stAllow').value=j.allow.join('\n');$('#stAllow').placeholder='your address now: '+j.your_ip;
    const a=j.alerts;$('#alLoss').value=a.loss;$('#alDisk').value=a.disk;$('#alRam').value=a.ram;$('#alSpeed').value=a.speed_every;$('#alBackup').value=a.backup_every;$('#alKeep').value=a.keep;
    certShow(j.cert)}
  const sl=$('#sessList');sl.textContent='';
  if(ss.ok)ss.j.sessions.forEach(x=>{const row=el('div','kv');const l=el('span',null,(x.current?'this browser · ':'')+x.ip+' · '+(x.agent||'').replace(/\(.*?\)/g,'').slice(0,40));const w=el('span','rowacts');w.appendChild(el('span','lab',when(Date.parse(x.seen)/1000)));
    if(!x.current){const b=el('button','btn sm sec','Sign out');b.type='button';b.onclick=async()=>{if(await act('settings/sessions/'+x.id+'/drop'))loadSettings2()};w.appendChild(b)}
    row.append(l,w);sl.appendChild(row)});
}
function certShow(c){
  $('#ceKind').textContent={self:'self-signed',owner:'your own',ca:'private CA',acme:'ACME'}[c.kind]||c.kind;
  const i=$('#ceInfo');i.textContent='';const kv=(k,v)=>{const d=el('div','kv');d.append(el('span',null,k),el('span','n',v));i.appendChild(d)};
  kv('For',(c.names||[]).join(', ')||c.subject||'–');kv('Issued by',c.issuer||'–');kv('Expires',c.not_after?c.not_after.slice(0,10):'–');
  const fp=el('div','lab mt8','SHA-256 '+c.fingerprint);i.appendChild(fp);$('#ceCAdl').hidden=!c.has_ca;
}
$('#stSave').addEventListener('click',async()=>{
  const body={title:$('#stTitle').value,path:$('#stPath').value.trim(),allow:$('#stAllow').value.split(/[\n,]+/).map(x=>x.trim()).filter(Boolean)};
  const r=await act('settings/panel',{method:'PUT',full:true,title:'Save panel settings',body});if(!r)return;
  if(r.moved){toast('The panel moved. Opening the new address: sign in there.');setTimeout(()=>{location.href=location.pathname.replace(/\/[^/]+\/?$/,'/')+r.path+'/'},1500)}else toast('Saved');
});
$('#alSave').addEventListener('click',async()=>{
  const n=id=>Number($(id).value);
  const r=await act('settings/alerts',{method:'PUT',body:{loss:n('#alLoss'),disk:n('#alDisk'),ram:n('#alRam'),speedevery:n('#alSpeed'),backupevery:n('#alBackup'),keep:n('#alKeep')}});
  if(r)toast('Saved');
});
const certDo=async(path,body,title)=>{const r=await act(path,{full:true,title,body});if(r&&r.cert){certShow(r.cert);toast('The panel uses the new certificate now. Reload the page if the browser asks.')}};
$('#ceOwn').addEventListener('click',()=>certDo('settings/cert',{cert:$('#ceCrt').value,key:$('#ceKey').value},'Use your own certificate'));
$('#ceSelf').addEventListener('click',()=>certDo('settings/cert/self',{},'Back to the self-signed certificate'));
$('#ceCA').addEventListener('click',()=>certDo('settings/cert/ca',{},'Make the private CA'));
$('#ceAcme').addEventListener('click',()=>act('settings/cert/acme',{full:true,title:'Certificate for '+$('#ceDom').value,body:{domain:$('#ceDom').value.trim()}}));
})();
