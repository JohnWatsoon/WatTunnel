// Every page except the overview, the tunnel drawer's actions, dialogs, jobs and settings. Plain JS over app.js's
// helpers (window.PANEL). No product name in this file: it is served before sign-in.
(function(){
"use strict";
const P=window.PANEL;const {api,el,$,S}=P;
const store={get(k){try{return localStorage.getItem(k)}catch(e){return null}},set(k,v){try{localStorage.setItem(k,v)}catch(e){}}};
P.VIEWS.traffic=['#vTraffic','Traffic'];P.VIEWS.system=['#vSystem','System'];
const enc=encodeURIComponent;
const COLS=['#3ee08a','#5b93ff','#9a8cff','#ff7a33','#d4f36a','#ff5d62','#7fe0ff','#f0a6ff'];
const colOf=n=>{const i=(S.ov?S.ov.tunnels:[]).findIndex(t=>t.name===n);return COLS[(i<0?0:i)%COLS.length]};
function svgEl(tag,attrs){const e=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const k in attrs)e.setAttribute(k,attrs[k]);return e}
function btn(txt,cls,fn){const b=el('button','btn sm '+(cls||'sec'),txt);b.type='button';b.onclick=fn;return b}
function card(cls,title,sub,right){const c=el('section','card '+(cls||''));const h=el('div','ch');const t=el('div','ct',title);if(sub)t.appendChild(el('span','lab',sub));h.appendChild(t);if(right)h.appendChild(right);c.appendChild(h);return c}
function pill(cls,txt){const p=el('span','pill '+cls);p.append(el('i'),txt);return p}
function split(v,unit){const w=el('span','sv');const s=String(v);const i=s.indexOf('.');w.append(i<0?s:s.slice(0,i));if(i>=0)w.appendChild(el('span','dim',s.slice(i)));if(unit)w.appendChild(el('span','unit',unit));return w}
function bytesSplit(b){const t=P.fmtBytes(b).split(' ');return split(t[0],t[1])}

/* ---------- dates: Gregorian or Persian (Settings -> Display) ---------- */
const cal=()=>store.get('cal')==='persian'?'persian':'gregory';
function when(t){const d=new Date(t*1000);const o={calendar:cal(),numberingSystem:'latn'};
  return d.toLocaleDateString('en-US-u-ca-'+cal(),Object.assign({month:'short',day:'numeric'},o))+' '+d.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'})}
function dayLabel(iso){const d=new Date(iso+'T12:00:00');return d.toLocaleDateString('en-US-u-ca-'+cal(),{month:'short',day:'numeric',calendar:cal(),numberingSystem:'latn'})}
P.when=when;

/* ---------- toasts ---------- */
function toast(msg,bad){const t=el('div','toast'+(bad?' bad':''),msg);$('#toasts').appendChild(t);setTimeout(()=>t.remove(),bad?9000:4500)}

/* ---------- dialog: fields + buttons, resolves with the values or null ---------- */
function ask(title,{text,fields=[],ok='Go ahead',danger=false,full=false,err='',body}={}){
  return new Promise(res=>{
    const d=$('#dlg');$('#dlgT').textContent=title;const b=$('#dlgB');b.textContent='';$('#dlgE').textContent=err;
    if(text)b.appendChild(el('p','note',text));
    if(body)b.appendChild(body);
    const all=fields.slice();
    if(full)all.push({k:'password',label:'Password',type:'password'},{k:'code',label:'Code from your authenticator app',mode:'numeric'});
    const inputs={};
    all.forEach(f=>{const w=el('div','fld');const id='dlg_'+f.k;let i;
      if(f.check){w.className='chk';i=el('input');i.type='checkbox';i.id=id;i.checked=!!f.value;const l=el('label',null,f.label);l.htmlFor=id;w.append(i,l);b.appendChild(w);inputs[f.k]=i;return}
      const l=el('label',null,f.label);l.htmlFor=id;
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
    $('#dlgF').onsubmit=e=>{e.preventDefault();const v={};Object.entries(inputs).forEach(([k,i])=>{v[k]=i.type==='checkbox'?i.checked:i.value.trim()});done(v)};
    if(!d.open)d.showModal();const first=Object.values(inputs).find(i=>i.type!=='checkbox');(first||go).focus();
  });
}
function info(title,body){const d=$('#dlg');$('#dlgT').textContent=title;$('#dlgE').textContent='';const b=$('#dlgB');b.textContent='';b.appendChild(body);
  const a=$('#dlgA');a.textContent='';const c=el('button','btn sec','Close');c.type='button';c.onclick=()=>d.close();a.appendChild(c);$('#dlgF').onsubmit=e=>e.preventDefault();d.onclose=null;d.oncancel=null;if(!d.open)d.showModal()}

/* ---------- act: one call with every answer the server can give ---------- */
// opts: {full, title, confirm (text), danger, fields, body, method, ok}
async function act(path,opts={}){
  let body=Object.assign({},opts.body||{});
  if(opts.confirm||opts.full||opts.fields){
    const v=await ask(opts.title||'Are you sure?',{text:opts.confirm,fields:opts.fields,full:opts.full,danger:opts.danger,ok:opts.ok});
    if(!v)return null;Object.assign(body,v);
  }
  for(let i=0;i<4;i++){
    let r;try{r=await api(path,{method:opts.method||'POST',body})}catch(e){toast('No answer from the server.',true);return null}
    if(r.ok){if(r.j.job)openJob(r.j.job);return r.j}
    if(r.status===409&&r.j.lastlink){const v=await ask('Last link to '+r.j.host,{text:r.j.error,fields:[{k:'confirm',label:'Type the tunnel name'}],danger:true});if(!v)return null;body.confirm=v.confirm;continue}
    if(r.status===403&&r.j.reauth){const v=await ask(opts.title||'Confirm',{full:true,err:r.j.error});if(!v)return null;Object.assign(body,v);continue}
    if(r.status===403&&r.j.need2fa){toast('Turn on two-factor sign-in first (Settings). Actions that show a key or cannot be undone need it.',true);return null}
    toast(r.j.error||('Failed ('+r.status+').'),true);return null;
  }
  return null;
}
P.act=act;

/* ---------- dot matrix: the speed test's look (Overview card and the speed test job) ---------- */
// cols: one fill height per column (0..rows), null = empty; .run makes it a wave. Built with createElement:
// the CSP blocks style="" inside markup.
function matrix(box,cols,rows,run){
  rows=rows||7;const n=cols?cols.length:7;box.textContent='';box.style.setProperty('--n',n);box.classList.toggle('run',!!run);
  for(let j=0;j<rows;j++)for(let i=0;i<n;i++){const d=el('i');d.style.setProperty('--d',((Math.abs(i-(n-1)/2)+Math.abs(j-(rows-1)/2))*0.09).toFixed(2)+'s');
    if(cols&&cols[i]!=null&&(rows-1-j)<cols[i])d.className='f';box.appendChild(d)}
}
function fillCols(vals,n,rows){const v=vals.slice(-n);const top=Math.max(...v,0.001),lo=Math.min(...v)*0.5;const out=v.map(x=>Math.max(1,Math.round(1+(x-lo)/Math.max(top-lo,0.001)*(rows-1))));while(out.length<n)out.unshift(null);return out}

/* ---------- jobs: one card per kind ---------- */
let jobT=0;
const strip=l=>l.replace(/\x1b\[[0-9;]*m/g,'');
function jobShell(){
  const d=$('#dlg');d.classList.add('wide');$('#dlgE').textContent='';const b=$('#dlgB');b.textContent='';
  const head=el('div','jh');const st=pill('p-slow','running');const sub=el('span','lab');head.append(st,sub);
  const body=el('div','jbody');const det=el('details','jlog');det.appendChild(el('summary','lab','Show the full log'));const pre=el('pre','log');det.appendChild(pre);const res=el('div','mt8');
  b.append(head,body,res,det);
  const a=$('#dlgA');a.textContent='';const close=el('button','btn sec','Close (it keeps running)');close.type='button';close.onclick=()=>{clearTimeout(jobT);d.close()};a.appendChild(close);
  $('#dlgF').onsubmit=e=>e.preventDefault();d.onclose=()=>{if(!d.open)d.classList.remove('wide')};d.oncancel=()=>clearTimeout(jobT);
  if(!d.open)d.showModal();
  return {st,sub,body,pre,res,close};
}
// speed test: the matrix waves while it measures, then fills; download and upload as big split numbers
function speedView(body){
  const w=el('div','jspeed');const mx=el('div','mx big');const r=el('div','js-r');
  const tile=(lab)=>{const d=el('div','js-t');const l=el('div','lab',lab);const v=el('div','big2 n','··');d.append(l,v);return {d,l,v}};
  const dn=tile('download'),up=tile('upload');r.append(dn.d,up.d);w.append(mx,r);body.appendChild(w);matrix(mx,null,9,true);
  return (lines,state)=>{
    let D=null,U=null,now='';lines.forEach(l=>{let m=/^(down|up): ([\d.]+) MB\/s in ([\d.]+) s/.exec(l);if(m){if(m[1]==='down')D=[+m[2],+m[3]];else U=[+m[2],+m[3]]}
      m=/: \d+ MB (download|upload) \.\.\./.exec(l);if(m)now=m[1]});
    const set=(t,x,word)=>{t.v.textContent='';if(x){t.v.appendChild(split(x[0].toFixed(1),'MB/s'));t.l.textContent=word+' · '+x[1].toFixed(1)+' s'}else t.v.textContent=state==='running'&&now===word?'measuring':'··';t.d.classList.toggle('now',state==='running'&&now===word&&!x)};
    set(dn,D,'download');set(up,U,'upload');
    if(state!=='running'){const top=Math.max(D?D[0]:0,U?U[0]:0,1);const h=x=>x?Math.max(1,Math.round(x[0]/top*9)):null;const a=h(D),b=h(U);matrix(mx,[a,a,a,a,null,b,b,b,b],9,false)}
  };
}
// carrier test: a live board, one row per carrier as the manager tests it (ATROW lines), the winner marked
function carrierView(body){
  const w=el('div','jcar');const top=el('div','jc-top');const cnt=el('div','jc-cnt');const prog=el('div','jc-prog');top.append(cnt,prog);
  const list=el('div','jc-list');w.append(top,list);body.appendChild(w);
  const seen=new Set();let tun='';
  const pend=el('div','jc-row pend');const pl=el('span','jc-lab lab');const pmx=el('div','mx line');matrix(pmx,new Array(12).fill(0),1,true);pend.append(el('span','jc-rank'),pl,pmx);
  return (lines,state)=>{
    let plan=0;const picks=new Set();const rows=new Map();
    lines.forEach(l=>{let m=/^ATPLAN=(\d+)/.exec(l);if(m)plan=+m[1];m=/^ATPICK=(.+)$/.exec(l);if(m)picks.add(m[1].trim());m=/^TUNNEL=(.+)$/.exec(l);if(m)tun=m[1].trim();
      m=/^ATROW=(ok|fail)\|([^|]*)\|(.*)$/.exec(l);if(m){const f=m[3].split('|');rows.set(m[2],m[1]==='ok'?{ok:true,down:+f[0],up:+f[1],rtt:+f[2]}:{ok:false,why:f.join('|')})}});
    if(!plan&&!rows.size)return false;
    const done=rows.size,ok=[...rows.values()].filter(r=>r.ok).length;
    cnt.textContent='';cnt.append(el('span','big2 n',String(ok)),el('span','lab',' working of '+done+' tested'+(plan?' · '+plan+' planned':'')));
    prog.textContent='';const N=Math.max(plan,done);for(let i=0;i<N;i++){const d=el('i');const r=[...rows.values()][i];d.className=r?(r.ok?'ok':'bad'):(i===done&&state==='running'?'now':'');prog.appendChild(d)}
    const peak=Math.max(1,...[...rows.values()].map(r=>r.ok?Math.max(r.down,r.up):0));
    const sorted=[...rows.entries()].sort((a,b)=>(b[1].ok-a[1].ok)||((b[1].down||0)-(a[1].down||0)));
    [...list.children].forEach(c=>{if(c!==pend)c.remove()});
    sorted.forEach(([lab,r],k)=>{const row=el('div','jc-row'+(r.ok?'':' fail')+(picks.has(lab)?' win':'')+(seen.has(lab)?'':' new'));seen.add(lab);row.dataset.lab=lab;row.dataset.ok=r.ok?'1':'';
      row.appendChild(el('span','jc-rank n',r.ok?String(k+1):'–'));row.appendChild(el('span','jc-lab',lab));
      if(r.ok){const bar=el('span','jc-bar');const B=16,on=Math.max(1,Math.round(r.down/peak*B));for(let i=0;i<B;i++)bar.appendChild(el('i',i<on?'on':''));row.appendChild(bar);
        const v=el('span','jc-v n');v.append(el('b',null,r.down.toFixed(1)),' ↓ '+r.up.toFixed(1)+' ↑ · '+r.rtt.toFixed(0)+' ms');row.appendChild(v)}
      else row.appendChild(el('span','jc-why',r.why));
      if(picks.has(lab))row.appendChild(el('span','chip jc-pick',picks.size>1?'bonded':'in use'));
      list.insertBefore(row,pend.parentNode===list?pend:null)});
    if(state==='done'&&tun&&!w.querySelector('.jc-use'))chooser(w,list,tun,picks);
    if(state==='running'){pl.textContent=plan&&done>=plan?'re-measuring the best ones':'testing the next carrier';if(pend.parentNode!==list)list.appendChild(pend)}else pend.remove();
    return true;
  };
}
// after a carrier test: tick rows to switch to one, or to bond several (same kind; the manager checks)
function chooser(w,list,tun,picks){
  const bar=el('div','jc-use');const say=el('span','lab','Tick a carrier to switch to it, or several of one kind (direct or reverse) to bond them.');const go=el('button','btn pri','Switch');go.type='button';go.disabled=true;bar.append(say,go);w.appendChild(bar);
  const sel=new Set();
  list.querySelectorAll('.jc-row.fail').forEach(row=>{row.prepend(el('span'));row.classList.add('pickable','nochk')});
  list.querySelectorAll('.jc-row[data-ok="1"]').forEach(row=>{const c=el('input');c.type='checkbox';c.className='jc-chk';c.setAttribute('aria-label','use '+row.dataset.lab);row.prepend(c);row.classList.add('pickable');
    c.onchange=()=>{c.checked?sel.add(row.dataset.lab):sel.delete(row.dataset.lab);row.classList.toggle('sel',c.checked);
      const same=sel.size===picks.size&&[...sel].every(x=>picks.has(x));go.disabled=!sel.size||same;
      go.textContent=sel.size>1?'Bond these '+sel.size:'Switch to this one'};
    row.onclick=e=>{if(e.target!==c){c.checked=!c.checked;c.onchange()}}});
  go.onclick=()=>{const labels=[...sel];act('tunnels/'+enc(tun)+'/use',{body:{labels},title:labels.length>1?'Bond '+labels.join(' + '):'Switch to '+labels[0],confirm:tun+' restarts on the new carrier'+(labels.length>1?'s':'')+'; open connections drop.',ok:'Switch'})};
}
// any other job: its steps, the current one pulsing
function stepView(body){
  const steps=el('div','jsteps jsv');body.appendChild(steps);
  return (lines,state)=>{steps.textContent='';lines.slice(-6).forEach((l,i,arr)=>{const s=el('div','jstep'+(i===arr.length-1&&state==='running'?' now':''));s.append(el('i'),el('span',null,l));steps.appendChild(s)})};
}
async function openJob(id){
  clearTimeout(jobT);
  const v=jobShell();let spd=null,car=null,steps=null;let misses=0;
  const tick=async()=>{
    let r=null;try{r=await api('jobs/'+id,{auth:true})}catch(e){}
    if(!r||!r.ok){misses++;v.st.lastChild.textContent=misses>3?'waiting for the panel to come back':'running';jobT=setTimeout(tick,2000);return}
    misses=0;const j=r.j;$('#dlgT').textContent=j.title;
    const all=(j.log||[]).map(strip);const shown=all.filter(l=>!/^[A-Z_]+=/.test(l));
    if(j.kind==='speedtest'){spd=spd||speedView(v.body);spd(shown,j.state)}
    else{car=car||carrierView(v.body);steps=steps||stepView(v.body);
      // the board takes over as soon as the manager reports carriers; until then the plain steps
      if(car(all,j.state))v.body.classList.add('has-car');else steps(shown,j.state)}
    const atEnd=v.pre.scrollTop+v.pre.clientHeight>=v.pre.scrollHeight-8;v.pre.textContent=shown.join('\n')||'…';if(atEnd)v.pre.scrollTop=v.pre.scrollHeight;
    v.sub.textContent=j.state==='running'?'started '+when(j.started):'';
    const cls={running:'p-slow',done:'p-up',failed:'p-down',lost:'p-down'}[j.state];v.st.className='pill '+cls;v.st.lastChild.textContent={running:'running',done:'done',failed:'failed (code '+j.rc+')',lost:'ended without a result'}[j.state];
    if(j.state==='running'){jobT=setTimeout(tick,1000);return}
    v.close.textContent='Close';v.res.textContent='';
    if(j.state!=='done'){const last=shown.filter(l=>l.trim()).slice(-2).join(' · ');if(last)v.res.appendChild(el('p','note bad',last))}
    if(j.result&&j.result.TOKEN)v.res.appendChild(tokenBox(j.result.TOKEN));
    toast(j.title+(j.state==='done'?': done':': failed'),j.state!=='done');P.loadOverview();if(S.view==='system')loadSystem();loadSpeedCard();
  };
  tick();
}
P.openJob=openJob;
function tokenBox(tok,svg){const w=el('div','tokbox');if(svg){const q=el('div','qr');q.innerHTML=svg;w.appendChild(q)}
  const r=el('div','tokr');const t=el('code','tok',tok);t.hidden=true;const sh=btn('Show the token','sec',()=>{t.hidden=!t.hidden;sh.textContent=t.hidden?'Show the token':'Hide'});
  const cp=btn('Copy','sec',()=>{navigator.clipboard&&navigator.clipboard.writeText(tok).then(()=>toast('Copied'),()=>toast('The browser blocked the clipboard: select and copy it.',true))});
  r.append(sh,cp);w.append(r,t);return w}

// download: a POST (password + code, optional passphrase) that answers a file
async function download(path,body){
  let r;try{r=await fetch('api/'+path,{method:'POST',headers:{'X-Requested-With':'panel','Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)})}catch(e){toast('No answer from the server.',true);return}
  if(!r.ok){let j={};try{j=await r.json()}catch(e){}toast(j.error||'Failed ('+r.status+')',true);return}
  const cd=r.headers.get('Content-Disposition')||'';const m=/filename="([^"]+)"/.exec(cd);const blob=await r.blob();
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=m?m[1]:'download';document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},1000);
}
function askDownload(title,path,what){
  ask(title,{full:true,text:what+' Add a passphrase to encrypt the file (10+ characters); without one it downloads as it is.',
    fields:[{k:'passphrase',label:'Passphrase (optional)',type:'password',hint:'Needed again to restore it. It is not stored anywhere.'}],ok:'Download'}).then(v=>{if(v)download(path,v)});
}

/* ---------- live series per tunnel (for the tiles) ---------- */
const SER={};
P.onLive=()=>{
  Object.entries(S.live).forEach(([n,l])=>{const a=SER[n]=SER[n]||[];a.push(l.metrics&&l.alive?l.down:0);if(a.length>90)a.shift()});
  if(S.view==='tunnels')liveTunnels();
  if(S.view==='kharej')liveKharej();
};
function sparkPath(vals,W,H){const n=vals.length;if(n<2)return '';const top=Math.max(...vals,1);let p='';vals.forEach((v,i)=>{p+=(i?'L':'M')+(i*W/(n-1)).toFixed(1)+' '+(H-2-(v/top)*(H-6)).toFixed(1)});return p}

/* ================= TUNNELS ================= */
const PORTS={};let portsAt=0;
async function loadPorts(){
  if(Date.now()-portsAt<15000||!S.ov)return;portsAt=Date.now();
  await Promise.all(S.ov.tunnels.filter(t=>t.active).map(async t=>{try{const r=await api('tunnels/'+enc(t.name)+'/ports');if(r.ok)PORTS[t.name]=r.j.ports}catch(e){}}));
  if(S.view==='tunnels')renderTunnels(true);
}
function quotaOf(n){return (PORTS[n]||[]).filter(p=>p.quota_limit>0)}
function renderTunnels(still){
  const v=$('#vTunnels');if(!S.ov)return;v.textContent='';v.classList.toggle('still',!!still);
  const ts=S.ov.tunnels;const st=ts.map(t=>P.statusOf(t)[0]);
  const up=st.filter(x=>x==='p-up'||x==='p-slow').length,down=st.filter(x=>x==='p-down').length,off=st.filter(x=>x==='p-off').length;
  // command strip
  const strip=el('section','card tstrip');
  const sum=el('div','ts-sum');
  const cnt=el('div','ts-cnt');cnt.append(el('span','ts-n',String(ts.length)),el('span','ts-w',ts.length===1?'tunnel':'tunnels'));
  const seg=el('div','segbar');st.forEach((c,i)=>{const s=el('i',c);s.title=ts[i].name;s.style.animationDelay=(i*40)+'ms';seg.appendChild(s)});
  const leg=el('div','ts-leg');[[up,'up','p-up'],[down,'down','p-down'],[off,'stopped','p-off']].forEach(([n,w,c])=>{if(n||w==='up'){const x=el('span','tl');x.append(el('i',c),el('b',null,String(n)),' '+w);leg.appendChild(x)}});
  sum.append(cnt,seg,leg);
  const rate=el('div','ts-rate');rate.append(el('div','lab','all tunnels, now'));const rv=el('div','big2 n');rv.id='tsRate';rate.appendChild(rv);
  const tools=el('div','ts-tools');
  [['start','Start all'],['restart','Restart all'],['stop','Stop all']].forEach(([a,t])=>tools.appendChild(btn(t,'sec'+(a==='stop'?' danger':''),()=>bulk(a))));
  tools.appendChild(btn('New tunnel','pri',newTunnel));
  strip.append(sum,rate,tools);v.appendChild(strip);
  // tiles
  const g=el('div','tgrid');
  if(!ts.length){const e=el('section','card empty-hero');e.append(el('div','eh-t','No tunnels on this server yet.'),el('p','note','Paste a token from Kharej, or create the tunnel on Kharej and here in one go.'),btn('New tunnel','pri',newTunnel));g.appendChild(e)}
  ts.forEach((t,i)=>g.appendChild(tile(t,i)));
  v.appendChild(g);liveTunnels();loadPorts();
}
function tile(t,i){
  const [cls,word]=P.statusOf(t);const a=el('article','tile '+cls);a.dataset.name=t.name;a.tabIndex=0;a.style.animationDelay=(0.05+i*0.05)+'s';
  a.setAttribute('aria-label',t.name+', '+word);
  const h=el('div','t-h');const nm=el('span','t-name',t.name);const car=el('span','chip',t.carrier||'–');if(t.reverse)car.textContent+=' · reverse';h.append(nm,car,pill(cls,word));a.appendChild(h);
  const r=el('div','t-route');const me=el('span','t-end',S.ov.host.name||'here');const ln=el('i','t-line'+(cls==='p-up'||cls==='p-slow'?' on':''));ln.appendChild(el('b'));const far=el('span','t-end',t.peer||(t.role==='Kharej'?'Iran clients':'–'));r.append(me,ln,far);a.appendChild(r);
  const rt=el('div','t-rate');const big=el('span','big2 n');big.dataset.k='down';const sub=el('span','lab');sub.dataset.k='up';rt.append(big,sub);a.appendChild(rt);
  const sv=svgEl('svg',{class:'t-spark',viewBox:'0 0 300 54',preserveAspectRatio:'none','aria-hidden':'true'});
  const gid='tg'+i;const defs=svgEl('defs',{});const pat=svgEl('pattern',{id:gid,width:4,height:4,patternUnits:'userSpaceOnUse'});pat.appendChild(svgEl('circle',{cx:2,cy:2,r:.8,fill:colOf(t.name),opacity:.55}));defs.appendChild(pat);sv.appendChild(defs);
  sv.appendChild(svgEl('path',{'data-k':'area',fill:'url(#'+gid+')'}));sv.appendChild(svgEl('path',{'data-k':'line',fill:'none',stroke:colOf(t.name),'stroke-width':1.6,'vector-effect':'non-scaling-stroke'}));a.appendChild(sv);
  const m=el('div','t-meta');[['latency','rtt'],['loss','loss'],['users','conns']].forEach(([l,k])=>{const d=el('div');d.append(el('span','lab',l),el('span','n',''));d.lastChild.dataset.k=k;m.appendChild(d)});a.appendChild(m);
  const w=el('div','t-wd');w.append(el('span','lab','24 h'),P.sparkCells(t.name));a.appendChild(w);
  const pr=el('div','t-ports');(t.ports||[]).slice(0,6).forEach(p=>pr.appendChild(el('span','pchip',p)));if((t.ports||[]).length>6)pr.appendChild(el('span','pchip','+'+(t.ports.length-6)));a.appendChild(pr);
  quotaOf(t.name).slice(0,2).forEach(q=>a.appendChild(quotaBar(q)));
  a.addEventListener('click',()=>P.openDrawer(t.name));a.addEventListener('keydown',e=>{if(e.key==='Enter')P.openDrawer(t.name)});
  return a;
}
function quotaBar(q){const pct=Math.min(100,q.quota_used*100/q.quota_limit);const w=el('div','qbar'+(q.exceeded?' over':pct>=90?' hi':''));
  const top=el('div','q-top');top.append(el('span','lab','port '+q.port+' quota'),el('span','n',P.fmtBytes(q.quota_used)+' / '+P.fmtBytes(q.quota_limit)));
  const tr=el('div','q-tr');const f=el('i');f.style.width=pct.toFixed(1)+'%';tr.appendChild(f);w.append(top,tr);
  if(q.resets_at)w.appendChild(el('div','lab q-r','resets '+when(q.resets_at)));return w}
function liveTunnels(){
  let tot=0;Object.values(S.live).forEach(l=>tot+=l.down||0);const r=$('#tsRate');if(r){r.textContent='';r.appendChild(split(P.fmtRate(tot),'MB/s'))}
  document.querySelectorAll('.tile').forEach(a=>{const n=a.dataset.name;const l=S.live[n]||{};const m=l.metrics&&l.alive;
    const b=a.querySelector('[data-k=down]');b.textContent='';b.appendChild(split(m?P.fmtRate(l.down):'–',m?'MB/s':''));
    a.querySelector('[data-k=up]').textContent=m?'↑ '+P.fmtRate(l.up)+' MB/s':(l.metrics?'no link to Kharej':'not running');
    a.querySelector('[data-k=rtt]').textContent=m&&l.rtt?l.rtt.toFixed(0)+' ms':'–';
    const lo=a.querySelector('[data-k=loss]');lo.textContent=m?l.loss.toFixed(1)+'%':'–';lo.classList.toggle('warnc',m&&l.loss>=5);
    a.querySelector('[data-k=conns]').textContent=m?String(l.conns||0):'–';
    const vals=(SER[n]||[]).slice(-60);const p=sparkPath(vals,300,54);a.querySelector('[data-k=line]').setAttribute('d',p);a.querySelector('[data-k=area]').setAttribute('d',p?p+'L300 54L0 54Z':'')});
}
async function bulk(a){
  const r=await act('bulk',{body:{action:a},title:a[0].toUpperCase()+a.slice(1)+' every tunnel',confirm:a==='stop'?'Every tunnel on this server stops; users lose their connections.':'Every tunnel on this server '+(a==='start'?'starts':'restarts')+'.',danger:a==='stop'});
  if(r){const bad=Object.entries(r.results).filter(([,v])=>v!=='ok');toast(bad.length?bad.map(([k,v])=>k+': '+v).join('; '):'Done',bad.length>0);P.loadOverview()}
}
const TESTF={k:'test',label:'Carrier test',options:[['normal','normal'],['fast','fast'],['anti','anti-censor grid'],['reverse','reverse only'],['extended','extended (shaped carriers too)']]};
const PICK={k:'pick',label:'Then use, for auto',options:[['best','the fastest carrier'],['bond','a bond of every working carrier']],hint:'Either way, the results let you switch to any tested carrier or bond the ones you choose.'};
async function newTunnel(){
  const ov=S.ov||{tunnels:[]};const vias=ov.tunnels.filter(t=>t.paired&&t.active);
  const fields=[{k:'where',label:'Where',options:vias.length?[['both','On Kharej and here, in one go'],['here','Here only, from a token']]:[['here','Here only, from a token']],
      onchange:(v,inp)=>{const both=v==='both';['via','carrier'].forEach(k=>inp[k]&&(inp[k].parentNode.hidden=!both));inp.token&&(inp.token.parentNode.hidden=both)}},
    {k:'token',label:'Token from Kharej (wat1:...)',area:true,rows:3},
    {k:'via',label:'Kharej server',options:[...new Map(vias.map(t=>[t.peer||t.name,t.name])).entries()].map(([h,n])=>[n,h])},
    {k:'carrier',label:'Carrier',options:[['auto','auto: test them all and keep the best'],['wss','wss: TLS websocket, the safe default'],['tls','tls'],['tcp','tcp'],['udp','udp'],['icmp','icmp (ping)'],['grpc','grpc'],['h2','h2'],['ws','ws'],['h2c','h2c']]},
    {k:'map',label:'Ports',ph:'39901:18999, 8443:443',hint:'public port here : port on Kharej, comma-separated'},
    {k:'name',label:'Name (empty = automatic)'},
    {k:'test',label:'Carrier test, for auto',options:[['normal','normal'],['fast','fast'],['anti','anti-censor grid'],['reverse','reverse only'],['extended','extended (shaped carriers too)']]},
    PICK];
  await act('new',{title:'New tunnel',fields,ok:'Create'});
}

/* ---------- drawer: ports and actions ---------- */
P.onDrawer=async(name,t)=>{
  const a=$('#dActs');a.textContent='';
  const route=$('#dRoute');route.textContent='';const ln=el('i','t-line'+(t.active?' on':''));ln.appendChild(el('b'));route.append(el('span','t-end',S.ov.host.name||'here'),ln,el('span','t-end',t.peer||'–'));
  const grp=(title,items)=>{const g=el('div','agrp');g.appendChild(el('div','lab',title));const w=el('div','tools');items.filter(Boolean).forEach(x=>w.appendChild(x));g.appendChild(w);a.appendChild(g)};
  const u=act2=>()=>act('tunnels/'+enc(name)+'/'+act2,act2==='stop'?{confirm:'Stop '+name+'? Its users lose the connection.',title:'Stop '+name,danger:true}:{}).then(r=>{if(r){toast(name+': '+act2+' done');P.loadOverview()}});
  grp('Run',[t.active?btn('Restart','sec',u('restart')):btn('Start','pri',u('start')),t.active&&btn('Stop','sec danger',u('stop'))]);
  grp('Test',[t.role==='Iran'&&btn('Speed test','sec',()=>act('tunnels/'+enc(name)+'/speedtest',{title:'Speed test of '+name,fields:[{k:'mb',label:'Megabytes each way',value:'10',mode:'numeric'}],ok:'Run'})),
    t.role==='Iran'&&btn('Re-test carriers','sec',()=>act('tunnels/'+enc(name)+'/retest',{confirm:'Tests every carrier again (auto tunnels). The tunnel restarts if it switches.',title:'Re-test carriers',fields:[TESTF,PICK],ok:'Start the test'}))]);
  grp('Configure',[btn('Ports','sec',()=>editPorts(name,t)),btn('Limit a port','sec',()=>limitPort(name))]);
  if(/\+/.test(t.carrier||''))bondBlock(a,name);
  grp('Keys and pairing',[btn('Show token','sec',()=>showToken(name)),t.paired&&btn('Forget pairing','sec danger',()=>act('tunnels/'+enc(name)+'/pair-forget',{full:true,danger:true,title:'Forget the pairing of '+name,confirm:'Turns off the management channel of '+name+' (pairing: false) and restarts it. The tunnel keeps working; Kharej is then managed from its own console until you pair again.'}).then(r=>{if(r){toast('Pairing forgotten');P.loadOverview()}}))]);
  grp('Danger',[btn('Delete','sec danger',()=>deleteTunnel(name,t))]);
  renderDrawerPorts(name,[]);
  const r=await api('tunnels/'+enc(name)+'/ports').catch(()=>null);
  if(S.drawer===name&&r&&r.ok){PORTS[name]=r.j.ports;renderDrawerPorts(name,r.j.ports)}
};
// Bonding: the mode and every leg of a '+'-bond, live from /stats; mute takes a leg out without a restart
async function bondBlock(a,name){
  const g=el('div','agrp bondg');g.appendChild(el('div','lab','Bonding'));a.appendChild(g);
  const seg=el('div','seg');const legs=el('div','legs');g.append(seg,legs);
  const r=await api('tunnels/'+enc(name)+'/paths').catch(()=>null);if(!r||!r.ok||S.drawer!==name)return;
  [['balanced','balanced','split by path capacity'],['active-backup','active-backup','one path, the next on failure'],['replicate','replicate','datagrams on every path']].forEach(([m,l,h])=>{
    const b=el('button','seg-b'+(r.j.mode===m?' on':''));b.type='button';b.append(el('b',null,l),el('span','lab',h));
    if(r.j.mode!==m)b.onclick=()=>act('tunnels/'+enc(name)+'/bond-mode',{body:{mode:m},title:'Bond mode: '+l,confirm:name+' restarts with the new mode; open connections drop.'}).then(x=>{if(x)setTimeout(()=>P.openDrawer(name),4000)});
    seg.appendChild(b)});
  if(!r.j.paths.length){legs.appendChild(el('div','empty','No path data: the tunnel is stopped.'));return}
  r.j.paths.forEach(p=>{const row=el('div','leg'+(p.muted?' muted':p.alive?'':' down'));
    row.append(el('i','kdot '+(p.muted?'off':p.alive?'ok':'bad')),el('span','leg-n',p.name),el('span','lab n',p.muted?'muted':p.alive?(p.share?p.share+' % of traffic':'up')+(p.rtt?' · '+p.rtt+' ms':''):'down'));
    row.appendChild(btn(p.muted?'Unmute':'Mute','sec sm',()=>act('tunnels/'+enc(name)+'/mute',{body:{path:p.name,mute:!p.muted}}).then(x=>{if(x)setTimeout(()=>P.openDrawer(name),2500)})));
    legs.appendChild(row)});
}
function renderDrawerPorts(name,ports){
  const w=$('#dPorts');w.textContent='';$('#dPortsSub').textContent=ports.length?ports.length+' public':'';
  if(!ports.length){w.appendChild(el('div','empty','No per-port numbers yet (the tunnel is stopped, or has no metrics address).'));return}
  ports.forEach(p=>{const c=el('div','pcard');
    const h=el('div','pc-h');h.append(el('span','pc-port n',p.port),el('span','lab',p.conns+' users'));c.appendChild(h);
    const s=el('div','pc-s');s.append(el('span',null,'↓ '+P.fmtBytes(p.down)),el('span',null,'↑ '+P.fmtBytes(p.up)),el('span','lab',P.fmtRate(p.rate_down)+' MB/s now'));c.appendChild(s);
    if(p.rate_limit)c.appendChild(el('div','lab','limited to '+(p.rate_limit*8/1e6).toFixed(0)+' Mbit/s'));
    if(p.quota_limit>0){c.appendChild(quotaBar(p));c.appendChild(btn('Reset quota','sec',()=>act('tunnels/'+enc(name)+'/quota-reset',{body:{port:+p.port},confirm:'Usage of port '+p.port+' goes back to zero now.',title:'Reset the quota'}).then(r=>{if(r){toast('Quota reset');portsAt=0;P.openDrawer(name)}})))}
    w.appendChild(c)});
}
async function editPorts(name,t){const v=await ask('Ports of '+name,{fields:[{k:'ports',label:'One mapping per line: 443, 8443:443, 53/udp',area:true,rows:6,value:(t.ports||[]).join('\n')}],ok:'Save'});
  if(!v)return;const r=await act('tunnels/'+enc(name)+'/ports',{method:'PUT',body:{ports:v.ports.split(/[\n,]+/).map(x=>x.trim()).filter(Boolean)}});if(r){toast(r.note||'Saved');P.loadOverview()}}
async function limitPort(name){const v=await ask('Limit a port of '+name,{fields:[{k:'port',label:'Port',mode:'numeric'},{k:'rate',label:'Rate, for example 10mbit (empty = none)'},{k:'quota',label:'Quota, for example 50G (empty = none)'},{k:'period',label:'Quota resets every',options:[['month','month'],['week','week'],['day','day']]}],ok:'Save'});
  if(!v)return;if(await act('tunnels/'+enc(name)+'/limit',{method:'PUT',body:v})){toast('Saved. Limits apply within seconds.');portsAt=0}}
async function showToken(name){const r=await act('tunnels/'+enc(name)+'/token',{full:true,title:'Show the token of '+name});if(!r)return;
  const b=el('div');b.appendChild(el('p','note','Anyone with this token can connect to the Kharej side. Paste it only into your own servers.'));b.appendChild(tokenBox(r.token,r.svg));info('Token of '+name,b)}
async function deleteTunnel(name,t){
  const k=S.ov.kharej.find(x=>x.via.includes(name));const twin=k&&(k.tunnels||[]).find(x=>x.name===name);
  const fields=[];if(twin)fields.push({k:'alsoK',label:'Also delete '+twin.name+' on '+k.host,check:true});
  const v=await ask('Delete '+name,{full:true,danger:true,ok:'Delete',fields,text:'Stops '+name+' and deletes its config, key and token on this server.'+(k&&!twin?' Its Kharej side stays (no tunnel of the same name there).':'')});
  if(!v)return;const body={password:v.password,code:v.code};if(v.alsoK)body.kharej=twin.name;
  const r=await act('tunnels/'+enc(name)+'/delete',{body});if(r)P.closeDrawer();
}

/* ================= KHAREJ ================= */
const TIERS=['tunnel','create','manage','full'];
function renderKharejPage(still){
  const v=$('#vKharej');if(!S.ov)return;v.textContent='';v.classList.toggle('still',!!still);const kh=S.ov.kharej;const latest=S.ov.latest;
  if(!kh.length){const e=el('section','card empty-hero');e.append(el('div','eh-t','No Kharej server is paired with this one.'),el('p','note','Pair from the manager on this server: '+(S.cli||'wattun')+' scepter. A tunnel made from a pairing token pairs by itself.'));v.appendChild(e);return}
  const g=el('div','kgrid');
  kh.forEach((k,i)=>{
    const c=el('section','card ksrv'+(k.online?'':' off'));c.style.animationDelay=(0.1+i*0.08)+'s';c.dataset.host=k.host;
    const top=el('div','k-top');top.appendChild(pill(k.online?'p-up':'p-down',k.online?'online':'unreachable'));
    if(k.version){const vc=el('span','chip n','v'+k.version);top.appendChild(vc);if(latest&&newer(latest,k.version))top.appendChild(el('span','chip upd','v'+latest+' is out'))}
    top.appendChild(el('span','grow'));
    const caps=el('div','caps');caps.title='what this pairing may do on Kharej';const ti=TIERS.indexOf(k.caps);TIERS.forEach((x,j)=>{const s=el('span',j<=ti?'on':'',x);caps.appendChild(s)});top.appendChild(caps);c.appendChild(top);
    const fl=el('div','flaps big'+(k.host.length>11?' long':''));fl.setAttribute('aria-label',k.host);k.host.split('').slice(0,24).forEach((ch,j)=>{const s=el('span','flap',ch);s.setAttribute('aria-hidden','true');s.style.animationDelay=(0.2+j*0.04).toFixed(2)+'s';fl.appendChild(s)});c.appendChild(fl);
    // the link: this server to Kharej, packets at the live rate
    const link=el('div','k-link');const a1=el('div','kl-end');a1.append(el('span','kl-dot me'),el('span',null,S.ov.host.name||'this server'));
    const mid=el('div','kl-mid');const line=el('i','t-line wide'+(k.online?' on':''));line.appendChild(el('b'));const st=el('div','kl-st');st.dataset.k='kst';mid.append(line,st);
    const a2=el('div','kl-end r');a2.append(el('span',null,k.host),el('span','kl-dot '+(k.online?'ok':'bad')));link.append(a1,mid,a2);c.appendChild(link);
    const via=el('div','k-via');via.appendChild(el('span','lab','through'));k.via.forEach(n=>{const b=el('button','pchip lnk',n);b.type='button';b.onclick=()=>P.openDrawer(n);via.appendChild(b)});
    if(!k.online&&k.error)via.appendChild(el('span','lab bad',k.error));if(k.seen)via.appendChild(el('span','lab grow r','seen '+when(k.seen)));c.appendChild(via);
    const list=el('div','k-tuns');
    (k.tunnels||[]).forEach(rt=>{const row=el('div','ktr');const ok=rt.health==='ok',act2=rt.state==='active';
      row.append(el('i','kdot '+(ok?'ok':act2?'bad':'off')),el('span','kt-n',rt.name),el('span','chip',rt.carrier||'–'),el('span','kt-p n',rt.ports||''),el('span','lab kt-s',ok?'up':act2?(rt.health||'no link'):'stopped'));
      const m=el('div','kt-a');
      if(k.online){[[act2?'restart':'start',act2?'Restart':'Start',''],act2&&['stop','Stop','danger']].filter(Boolean).forEach(([a,t,d])=>m.appendChild(btn(t,'sec '+d,()=>act('kharej/'+enc(k.host)+'/tunnel',{body:{name:rt.name,action:a},confirm:a==='stop'?'Stop '+rt.name+' on '+k.host+'?':null,title:t+' '+rt.name,danger:a==='stop'}).then(r=>{if(r){toast(rt.name+': '+a+' done');P.loadOverview()}}))));
        m.appendChild(btn('New key','sec',()=>keyRotate(k,rt)));m.appendChild(btn('Delete','sec danger',()=>kharejDelete(k,rt)))}
      row.appendChild(m);list.appendChild(row)});
    if(k.online&&!(k.tunnels||[]).length)list.appendChild(el('div','empty','No tunnels listed on that server.'));
    c.appendChild(list);
    if(k.online){const t=el('div','k-acts');
      t.append(btn('Update','sec',()=>act('kharej/'+enc(k.host)+'/update',{full:true,title:'Update '+k.host,confirm:'Kharej downloads the latest release, checks its signature and restarts its tunnels. It rolls back by itself if the new version fails.'}).then(r=>r&&toast(r.note||'Update started'))),
        btn('Backup','sec',()=>askDownload('Back up '+k.host,'kharej/'+enc(k.host)+'/backup','It holds every tunnel key of that server.')),
        btn('Update status','sec',async()=>{const r=await api('kharej/'+enc(k.host)+'/status');const pre=el('pre','log',r.ok?JSON.stringify(r.j,null,2):(r.j.error||'Failed'));info('Update status of '+k.host,pre)}),
        btn('Audit','sec',async()=>{const r=await api('kharej/'+enc(k.host)+'/audit');const pre=el('pre','log',r.ok?(r.j.logs||[]).join('\n')||JSON.stringify(r.j,null,2):(r.j.error||'Failed'));info('Audit of '+k.host,pre)}),
        btn('Rotate pairing','sec',()=>act('kharej/'+enc(k.host)+'/pair-rotate',{full:true,title:'New pairing credential for '+k.host,confirm:'Kharej makes a new pairing credential; '+k.via.join(', ')+' switch to it and restart. The old one keeps working for 5 minutes.'}).then(r=>r&&toast('Pairing rotated'))));
      c.appendChild(t)}
    g.appendChild(c);
  });
  v.appendChild(g);liveKharej();
}
function liveKharej(){document.querySelectorAll('.ksrv').forEach(c=>{const k=S.ov.kharej.find(x=>x.host===c.dataset.host);if(!k)return;let d=0,rtt=0,n=0;k.via.forEach(v=>{const l=S.live[v];if(l&&l.metrics&&l.alive){d+=l.down;rtt+=l.rtt;n++}});
  const st=c.querySelector('[data-k=kst]');if(st)st.textContent=k.online?P.fmtRate(d)+' MB/s'+(n?' · '+(rtt/n).toFixed(0)+' ms':''):'no channel'})}
async function keyRotate(k,rt){const r=await act('kharej/'+enc(k.host)+'/keyrotate',{full:true,body:{name:rt.name},title:'New key for '+rt.name,danger:true,confirm:'Kharej makes a new key and restarts '+rt.name+'. Its twin here switches by itself; any other Iran server needs the new token.'});
  if(r){toast(r.local?r.local+' here uses the new key':'Kharej has the new key: paste the token where it is used',!r.ok);if(r.warning)toast(r.warning,true);if(r.token&&!r.local)info('New token for '+rt.name,tokenBox(r.token))}}
async function kharejDelete(k,rt){const r=await act('kharej/'+enc(k.host)+'/delete',{full:true,danger:true,title:'Delete '+rt.name+' on '+k.host,confirm:'Deletes the tunnel, its key and config on Kharej. Iran tunnels that use it stop working.',fields:[{k:'confirm',label:'Type '+rt.name+' to confirm'}],body:{name:rt.name},ok:'Delete'});if(r){toast(rt.name+' deleted on '+k.host);P.loadOverview()}}
function newer(a,b){const x=a.split('.').map(Number),y=b.split('.').map(Number);for(let i=0;i<Math.max(x.length,y.length);i++){if((x[i]||0)!==(y[i]||0))return (x[i]||0)>(y[i]||0)}return false}

/* ================= TRAFFIC ================= */
async function loadTraffic(){
  const v=$('#vTraffic');if(!v.childElementCount)loading(v);
  const [r,sp]=await Promise.all([api('traffic?days=30'),api('speedtests')]);if(S.view!=='traffic')return;
  v.textContent='';const g=el('div','grid trg');
  const days=r.ok?r.j.days:[];const tot=r.ok?r.j.totals:{};const hours=r.ok?r.j.hours:[];
  const sum=k=>Object.values(tot).reduce((a,x)=>a+((x[k]||[0,0])[0]+(x[k]||[0,0])[1]),0);
  // hero: this month, with the 30-day bars stacked per tunnel
  const hero=card('s3 trhero','Traffic','last 30 days, both directions',(()=>{const a=el('a','btn sec sm','CSV');a.href='api/traffic.csv';a.download='traffic.csv';return a})());
  const nums=el('div','tr-nums');const big=el('div','tr-big');big.appendChild(el('div','lab','30 days'));const bv=el('div','huge n');bv.appendChild(bytesSplit(sum('month')));big.appendChild(bv);nums.appendChild(big);
  [['today','today'],['week','7 days']].forEach(([k,l])=>{const d=el('div','tr-small');d.append(el('div','lab',l));const x=el('div','mid n');x.appendChild(bytesSplit(sum(k)));d.appendChild(x);nums.appendChild(d)});
  hero.appendChild(nums);
  const names=[...new Set(days.flatMap(d=>Object.keys(d.tunnels)))];
  const W=1300,H=210,B=22,T=8,L=56;const dsum=days.map(d=>Object.values(d.tunnels).reduce((a,x)=>a+x[0]+x[1],0));const top=Math.max(1,...dsum);const n=Math.max(30,days.length);const bw=(W-L)/n;
  const svg=svgEl('svg',{viewBox:`0 0 ${W} ${H}`,class:'trbars',role:'img','aria-label':'Traffic per day, per tunnel'});
  for(let k=1;k<=3;k++){const y=T+(H-T-B)*(1-k/3);svg.appendChild(svgEl('line',{x1:L,x2:W,y1:y,y2:y,class:'gl'}));const tx=svgEl('text',{x:0,y:y+3});tx.textContent=P.fmtBytes(top*k/3);svg.appendChild(tx)}
  days.forEach((d,i)=>{let y=H-B;const x=L+(n-days.length+i)*bw;names.forEach(nm=>{const v=d.tunnels[nm];if(!v)return;const h=(v[0]+v[1])/top*(H-T-B);y-=h;const rc=svgEl('rect',{x:x+1.5,y:y,width:Math.max(1,bw-3),height:Math.max(0,h-1),rx:2,fill:colOf(nm),opacity:.85});const tt=svgEl('title',{});tt.textContent=dayLabel(d.day)+' · '+nm+': '+P.fmtBytes(v[0]+v[1]);rc.appendChild(tt);svg.appendChild(rc)})});
  if(days.length){const a=svgEl('text',{x:L+(n-days.length)*bw,y:H-4});a.textContent=dayLabel(days[0].day);svg.appendChild(a);const b=svgEl('text',{x:W,y:H-4,'text-anchor':'end'});b.textContent='today';svg.appendChild(b)}
  else{const e=svgEl('text',{x:W/2,y:H/2,'text-anchor':'middle'});e.textContent='No traffic recorded yet: the panel counts from when it started.';svg.appendChild(e)}
  const tc=el('div','tc');tc.appendChild(svg);hero.appendChild(tc);
  const lg=el('div','chips mt14');names.forEach(nm=>{const c=el('span','chip');const i=el('i');i.style.background=colOf(nm);c.append(i,nm);lg.appendChild(c)});hero.appendChild(lg);
  g.appendChild(hero);
  // 48 hours as a dot field
  const hc=card('','Last 48 hours','per hour');const hf=el('div','hfield');const hmax=Math.max(1,...hours.map(h=>h.d+h.u));
  const byT={};hours.forEach(h=>byT[h.t]=h);const now=Math.floor(Date.now()/3600000)*3600;
  for(let i=47;i>=0;i--){const t=now-i*3600;const h=byT[t];const v=h?(h.d+h.u)/hmax:0;const c=el('i');c.style.setProperty('--v',v.toFixed(3));c.title=when(t)+' · '+(h?P.fmtBytes(h.d+h.u):'nothing');hf.appendChild(c)}
  hc.appendChild(hf);const hx=el('div','hx2');['−48 h','−36','−24','−12','now'].forEach(x=>hx.appendChild(el('span',null,x)));hc.appendChild(hx);
  const peakH=hours.reduce((a,h)=>(h.d+h.u)>(a?a.d+a.u:-1)?h:a,null);if(peakH)hc.appendChild(el('div','lab mt14','busiest hour: '+when(peakH.t)+' · '+P.fmtBytes(peakH.d+peakH.u)));
  g.appendChild(hc);
  // share per tunnel
  const sc=card('s2','Who used it','30 days, per tunnel');const all=Math.max(1,sum('month'));
  Object.entries(tot).sort((a,b)=>((b[1].month||[0,0])[0]+(b[1].month||[0,0])[1])-((a[1].month||[0,0])[0]+(a[1].month||[0,0])[1])).forEach(([nm,x])=>{const m=x.month||[0,0];const pct=(m[0]+m[1])*100/all;
    const row=el('div','share');const h=el('div','sh-h');const nmS=el('span','sh-n');const dot=el('i');dot.style.background=colOf(nm);nmS.append(dot,nm);h.append(nmS,el('span','n',P.fmtBytes(m[0]+m[1])),el('span','lab',pct.toFixed(0)+'%'));
    const bar=el('div','sh-bar');const f=el('i');f.style.width=pct.toFixed(1)+'%';f.style.background=colOf(nm);bar.appendChild(f);
    const sub=el('div','lab sh-s','↓ '+P.fmtBytes(m[0])+' · ↑ '+P.fmtBytes(m[1])+' · today '+P.fmtBytes(((x.today||[0,0])[0]+(x.today||[0,0])[1])));row.append(h,bar,sub);sc.appendChild(row)});
  if(!Object.keys(tot).length)sc.appendChild(el('div','empty','Nothing yet.'));
  g.appendChild(sc);
  // speed tests
  const rows=sp.ok?sp.j.rows:[];const iran=S.ov?S.ov.tunnels.filter(t=>t.role==='Iran'):[];
  const sel=el('select');sel.setAttribute('aria-label','Tunnel');iran.forEach(t=>{const o=el('option',null,t.name);o.value=t.name;sel.appendChild(o)});
  const tl=el('div','tools');tl.append(sel,btn('Run a test','pri',()=>sel.value&&act('tunnels/'+enc(sel.value)+'/speedtest',{body:{mb:10}}).then(()=>{})));
  const spc=card('s3','Speed tests','download, MB/s',tl);
  const latest={};rows.forEach(x=>{if(!latest[x.name])latest[x.name]=x});
  const lt=el('div','sp-latest');Object.values(latest).slice(0,4).forEach(x=>{const d=el('div','sp-l');const dot=el('i');dot.style.background=colOf(x.name);const h=el('div','lab');h.append(dot,x.name);const v=el('div','mid n');v.appendChild(split(x.down?x.down.toFixed(1):'–',x.down?'MB/s':''));d.append(h,v,el('div','lab','↑ '+(x.up?x.up.toFixed(1):'–')+' · '+when(x.t)));lt.appendChild(d)});spc.appendChild(lt);
  const SW=640,SH=170;const ssvg=svgEl('svg',{viewBox:`0 0 ${SW} ${SH}`,class:'spsc'});const pts=rows.filter(x=>x.down>0).slice().reverse();
  if(pts.length>1){const t0=pts[0].t,t1=pts[pts.length-1].t||t0+1;const vt=Math.max(...pts.map(x=>x.down))*1.15;
    for(let k=1;k<=3;k++){const y=SH-20-(SH-30)*k/3;ssvg.appendChild(svgEl('line',{x1:30,x2:SW,y1:y,y2:y,class:'gl'}));const tx=svgEl('text',{x:0,y:y+3});tx.textContent=(vt*k/3).toFixed(0);ssvg.appendChild(tx)}
    const by={};pts.forEach(x=>(by[x.name]=by[x.name]||[]).push(x));
    Object.entries(by).forEach(([nm,arr])=>{let p='';arr.forEach((x,i)=>{const X=30+(x.t-t0)/(t1-t0||1)*(SW-40),Y=SH-20-x.down/vt*(SH-30);p+=(i?'L':'M')+X.toFixed(1)+' '+Y.toFixed(1);const c=svgEl('circle',{cx:X,cy:Y,r:x.auto?2.6:4,fill:colOf(nm)});const tt=svgEl('title',{});tt.textContent=nm+' · '+x.down.toFixed(1)+' MB/s · '+when(x.t);c.appendChild(tt);ssvg.appendChild(c)});
      ssvg.insertBefore(svgEl('path',{d:p,fill:'none',stroke:colOf(nm),'stroke-width':1.2,opacity:.45}),ssvg.firstChild)});
    const a=svgEl('text',{x:30,y:SH-4});a.textContent=when(t0);ssvg.appendChild(a);const b=svgEl('text',{x:SW,y:SH-4,'text-anchor':'end'});b.textContent=when(t1);ssvg.appendChild(b)}
  else{const e=svgEl('text',{x:SW/2,y:SH/2,'text-anchor':'middle'});e.textContent='No speed tests yet. Run one, or schedule them in Settings.';ssvg.appendChild(e)}
  const stc=el('div','tc mt14');stc.appendChild(ssvg);spc.appendChild(stc);
  const fails=rows.filter(x=>x.error).slice(0,3);fails.forEach(x=>spc.appendChild(el('div','lab bad mt4',when(x.t)+' · '+x.name+': '+x.error)));
  g.appendChild(spc);
  v.appendChild(g);
}

/* ================= SYSTEM ================= */
function arc(label,pct,text,warn){
  const w=el('div','arc');const N=28;const svg=svgEl('svg',{viewBox:'0 0 120 70','aria-hidden':'true'});
  for(let i=0;i<N;i++){const a=Math.PI*(1-i/(N-1));const on=i/(N-1)<=pct/100+1e-9;const col=!on?'var(--line)':i/(N-1)>=warn/100?'var(--orange)':'var(--fg)';
    svg.appendChild(svgEl('line',{x1:60+52*Math.cos(a),y1:62-52*Math.sin(a),x2:60+43*Math.cos(a),y2:62-43*Math.sin(a),stroke:col,'stroke-width':2.6,'stroke-linecap':'round'}))}
  const t=el('div','arc-t');t.append(el('div','mid n',text),el('div','lab',label));w.append(svg,t);return w}
async function loadSystem(){
  const v=$('#vSystem');if(!v.childElementCount)loading(v);
  const [b,al,jb,au,ov]=await Promise.all([api('backups'),api('alerts'),api('jobs'),api('audit'),api('overview')]);if(S.view!=='system')return;
  if(ov.ok)S.ov=ov.j;const h=S.ov.host;const latest=S.ov.latest;v.textContent='';const g=el('div','grid sysg');
  // vitals
  const vc=card('s2','This server',h.uptime_s?'up '+P.fmtDur(h.uptime_s):'');const arcs=el('div','arcs');
  arcs.append(arc('load · '+h.cpus+' cores',h.cpus?Math.min(100,h.load1/h.cpus*100):0,h.load1.toFixed(2),85),arc('memory',h.mem_pct,h.mem_pct.toFixed(0)+'%',90),arc('disk',h.disk_pct,h.disk_pct.toFixed(0)+'%',90));
  vc.appendChild(arcs);const kv=el('div','kvrow');[['clock',h.clock_synced?'synced':'not synced'],['address',h.ip||'–'],['two-factor',S.ov.twofa?'on':'off']].forEach(([k,x])=>{const d=el('div');d.append(el('span','lab',k),el('span','n'+((x==='not synced'||x==='off')?' warnc':''),x));kv.appendChild(d)});vc.appendChild(kv);g.appendChild(vc);
  // versions
  const vr=card('s2','Versions',latest?'latest release '+latest:'release check pending');const vl=el('div','vlist');
  const vrow=(name,ver,on)=>{const r=el('div','vrow');const behind=latest&&ver&&newer(latest,ver);r.append(el('i','kdot '+(on?(behind?'warn':'ok'):'off')),el('span','vn',name),el('span','n',ver?'v'+ver:'–'),el('span','lab',!on?'unreachable':behind?'update available':'up to date'));vl.appendChild(r)};
  vrow('this server',h.version,true);S.ov.kharej.forEach(k=>vrow(k.host,k.version,k.online));vr.appendChild(vl);
  const vt=el('div','tools mt14');vt.append(btn('Update this server','pri',()=>act('update',{full:true,title:'Update this server',confirm:'Downloads the latest release, checks its signature, swaps the binary and restarts the tunnels and this panel. Open connections drop for a few seconds.'})),
    btn('Roll back','sec danger',()=>act('rollback',{full:true,title:'Roll back',confirm:'Goes back to the previous version and restarts the tunnels and this panel.',danger:true})));
  vr.append(vt,el('p','note mt14','Update Kharej first (Kharej servers page), then this server. The page reconnects by itself.'));g.appendChild(vr);
  // backups
  const bk=card('s2','Backups','settings and keys of this server',btn('Back up now','pri',async()=>{if(await act('backups'))setTimeout(loadSystem,1500)}));
  const tl=el('div','btl');const list=b.ok?b.j.backups:[];
  if(!list.length)tl.appendChild(el('div','empty','No backups yet. Schedule them in Settings, or back up now.'));
  list.forEach(x=>{const r=el('div','bt');r.append(el('i','bt-dot'+(x.auto?' auto':'')));const m=el('div','bt-m');m.append(el('span',null,when(x.t)),el('span','lab',(x.auto?'scheduled · ':x.name.startsWith('restore-')?'uploaded · ':'by hand · ')+P.fmtBytes(x.size)));
    const a=el('div','bt-a');a.append(btn('Download','sec',()=>askDownload('Download this backup','backups/'+enc(x.name)+'/download','It holds every tunnel key of this server.')),btn('Delete','sec danger',async()=>{if(await act('backups/'+enc(x.name)+'/delete',{confirm:'Delete this backup file?',danger:true,title:'Delete backup'}))loadSystem()}));
    r.append(m,a);tl.appendChild(r)});
  bk.appendChild(tl);
  const drop=el('label','drop');const fi=el('input');fi.type='file';fi.accept='.gz,.tgz,.wbk,application/gzip';const dt=el('div',null);dt.append(el('b',null,'Restore from a file'),el('span','lab','drop a .tar.gz or encrypted .wbk here, or click'));drop.append(fi,dt);
  drop.addEventListener('dragover',e=>{e.preventDefault();drop.classList.add('over')});drop.addEventListener('dragleave',()=>drop.classList.remove('over'));
  drop.addEventListener('drop',e=>{e.preventDefault();drop.classList.remove('over');if(e.dataTransfer.files[0])restore(e.dataTransfer.files[0])});fi.addEventListener('change',()=>{if(fi.files[0])restore(fi.files[0]);fi.value=''});
  bk.appendChild(drop);g.appendChild(bk);
  // alerts
  const ac=card('s2','Alerts');const af=el('div','afeed');const A=al.ok?al.j:{active:[],history:[]};
  A.active.forEach(a=>{const r=el('div','al on');r.append(el('i'),el('span',null,a.text),el('span','lab','since '+when(a.since)));af.appendChild(r)});
  A.history.slice(0,12).forEach(a=>{const r=el('div','al');r.append(el('i'),el('span',null,a.text),el('span','lab',when(a.since)+' – '+when(a.cleared)));af.appendChild(r)});
  if(!A.active.length&&!A.history.length)af.appendChild(el('div','empty','No alerts. Thresholds are in Settings.'));ac.appendChild(af);g.appendChild(ac);
  // jobs
  const jc=card('s4','Jobs','long actions, kept across restarts');const jl=el('div','jlist');(jb.ok?jb.j.jobs:[]).slice(0,12).forEach(j=>{const r=el('button','jrow');r.type='button';r.onclick=()=>openJob(j.id);r.append(pill({running:'p-slow',done:'p-up'}[j.state]||'p-down',j.state),el('span',null,j.title),el('span','lab',when(j.started)));jl.appendChild(r)});
  if(!jl.childElementCount)jl.appendChild(el('div','empty','No jobs yet.'));jc.appendChild(jl);g.appendChild(jc);
  // audit
  const auc=card('s4','Audit log','every change made in this panel');const pre=el('div','aud');(au.ok?au.j.rows:[]).slice(0,150).forEach(x=>{const r=el('div','au'+(x.result&&!/^(ok|accepted|job )/.test(x.result)?' err':''));r.append(el('span','lab',when(x.t)),el('span',null,x.user||'–'),el('span','lab',x.ip),el('b',null,x.action),el('span','n',x.target||''),el('span','lab',x.result||''));pre.appendChild(r)});
  if(!pre.childElementCount)pre.appendChild(el('div','empty','Nothing changed through the panel yet.'));auc.appendChild(pre);g.appendChild(auc);
  v.appendChild(g);
}
async function restore(f){
  if(f.size>8*1024*1024){toast('That file is too big for a settings backup.',true);return}
  const buf=new Uint8Array(await f.arrayBuffer());let bin='';for(let i=0;i<buf.length;i+=32768)bin+=String.fromCharCode.apply(null,buf.subarray(i,i+32768));const data=btoa(bin);
  const sealed=bin.startsWith('WATBK1');let pass='';
  if(sealed){const v=await ask('Encrypted backup',{fields:[{k:'p',label:'Passphrase',type:'password'}],ok:'Open'});if(!v)return;pass=v.p}
  const r=await api('restore/preview',{method:'POST',body:{data,passphrase:pass}});
  if(!r.ok){toast(r.j.error||'Not a backup of this server.',true);return}
  const body=el('div','rprev');const fs=r.j.files;const ch=fs.filter(x=>x.status!=='same');
  body.appendChild(el('p','note',ch.length?ch.length+' of '+fs.length+' files would change. Keys and tokens are compared but not shown.':'Nothing would change: the backup matches this server.'));
  fs.forEach(x=>{const d=el('details','rf '+x.status);const s=el('summary');s.append(el('span','rf-s',{new:'new',changed:'changed',same:'same',secret:'key changes'}[x.status]),el('span','n',x.file));d.appendChild(s);
    if(x.diff&&x.diff.length){const pre=el('pre','diff');x.diff.forEach(l=>{if(l.op===' '&&x.diff.length>30)return;const ln=el('span','d'+(l.op==='+'?'a':l.op==='-'?'r':'c'),l.op+' '+l.text+'\n');pre.appendChild(ln)});d.appendChild(pre)}
    if(x.status==='changed'||x.status==='new')d.open=ch.length<=3;body.appendChild(d)});
  if(r.j.kept.length)body.appendChild(el('p','note mt14','Not in the backup, left as they are: '+r.j.kept.join(', ')));
  const v=await ask('Restore '+f.name,{body,full:true,danger:true,ok:'Restore',text:''});
  if(!v)return;await act('restore',{body:{data,passphrase:pass,password:v.password,code:v.code}});
}

/* ================= SETTINGS ================= */
async function loadSettings2(){
  const box=$('#setMore');
  const [r,ss]=await Promise.all([api('settings'),api('settings/sessions')]);if(S.view!=='settings'||!r.ok)return;const j=r.j;box.textContent='';
  const g=el('div','grid g2');
  // access
  const acc=card('','Panel access','who reaches this page, and where');
  const f=(id,label,val,o={})=>{const w=el('div','fld');const l=el('label',null,label);l.htmlFor=id;const i=el(o.area?'textarea':'input');i.id=id;i.value=val;i.spellcheck=false;if(o.area)i.rows=3;if(o.mode)i.inputMode=o.mode;if(o.max)i.maxLength=o.max;w.append(l,i);if(o.after)w.appendChild(o.after);if(o.hint)w.appendChild(el('div','lab mt4',o.hint));return w};
  const dice=btn('Random free port','sec',async()=>{const x=await api('settings/random-port');if(x.ok&&x.j.port)$('#stPort').value=x.j.port});
  acc.append(f('stTitle','Page title, also the name in the 2FA app',j.title,{max:60}),f('stPath','Secret path',j.path),
    f('stPort','Port',String(j.port),{mode:'numeric',after:dice,hint:'10000-65535, never a common port. The panel restarts on the new port and the old one closes.'}),
    f('stAllow','Only these addresses may open it (IP or range per line, empty = anyone)',j.allow.join('\n'),{area:true,hint:'your address now: '+j.your_ip}));
  acc.appendChild(btn('Save','pri',async()=>{
    const body={title:$('#stTitle').value,path:$('#stPath').value.trim(),port:+$('#stPort').value,allow:$('#stAllow').value.split(/[\n,]+/).map(x=>x.trim()).filter(Boolean)};
    const x=await act('settings/panel',{method:'PUT',full:true,title:'Save panel access',body});if(!x)return;
    if(x.moved){const u=location.protocol+'//'+location.hostname+':'+x.port+'/'+x.path+'/';toast('The panel moved. Opening '+u);setTimeout(()=>{location.href=u},x.port_changed?5000:1200)}else toast('Saved')}));
  g.appendChild(acc);
  // certificate as four tiles
  const ce=card('','Certificate','what the browser is shown');const c=j.cert;
  const tiles=el('div','cetiles');[['self','Self-signed','made here, the browser warns once'],['owner','Your own','paste a PEM certificate and key'],['ca','Private CA','install once on your phone, valid only for this server'],['acme','ACME','Let\'s Encrypt, for a domain or this server\'s IP']].forEach(([k,t,d])=>{const b=el('button','cet'+(c.kind===k?' on':''));b.type='button';b.append(el('b',null,t),el('span','lab',d));b.onclick=()=>certPick(k);tiles.appendChild(b)});
  ce.appendChild(tiles);
  const ci=el('div','ceinfo');[['for',(c.names||[]).join(', ')||c.subject||'–'],['issued by',c.issuer||'–'],['expires',c.not_after?c.not_after.slice(0,10):'–']].forEach(([k,x])=>{const d=el('div','kv');d.append(el('span',null,k),el('span','n',x));ci.appendChild(d)});
  ci.appendChild(el('div','fp n','SHA-256 '+c.fingerprint));if(c.has_ca){const a=el('a','btn sec sm mt8','Download the CA');a.href='api/settings/ca.crt';a.download='panel-ca.crt';ci.appendChild(a)}
  ce.appendChild(ci);g.appendChild(ce);
  // alerts & schedules
  const al=card('','Alerts and schedules');const a=j.alerts;
  const num=(id,label,val,unit)=>{const w=el('div','numf');const l=el('label',null,label+(unit?' ('+unit+')':''));l.htmlFor=id;const st=el('div','stepper');const i=el('input');i.id=id;i.value=val;i.inputMode='decimal';
    const mk=(s,d)=>{const b=el('button','sbtn',s);b.type='button';b.setAttribute('aria-label',(d>0?'more ':'less ')+label);b.onclick=()=>{i.value=Math.max(0,(+i.value||0)+d)};return b};st.append(mk('−',-1),i,mk('+',1));w.append(l,st);return w};
  al.append(num('alLoss','Packet loss for 5 minutes above',a.loss,'%'),num('alDisk','Disk use above',a.disk,'%'),num('alRam','RAM use above',a.ram,'%'),
    num('alSpeed','Speed test every',a.speed_every,'hours, 0 = off'),num('alBackup','Backup every',a.backup_every,'hours, 0 = off'),num('alKeep','Scheduled backups kept',a.keep,''));
  al.appendChild(el('p','note','Also raised by themselves: a tunnel down, a Kharej server unreachable, a port at 90% of its quota, a new release, a scheduled speed test under half its usual, an expiring certificate, 10 failed sign-ins.'));
  al.appendChild(btn('Save','pri',async()=>{const n=id=>Number($(id).value);if(await act('settings/alerts',{method:'PUT',body:{loss:n('#alLoss'),disk:n('#alDisk'),ram:n('#alRam'),speedevery:n('#alSpeed'),backupevery:n('#alBackup'),keep:n('#alKeep')}}))toast('Saved')}));
  g.appendChild(al);
  // display and sessions
  const dc=card('','This browser');
  const tg=(id,label,on,fn)=>{const w=el('label','tog');const i=el('input');i.type='checkbox';i.id=id;i.checked=on;i.addEventListener('change',()=>fn(i));w.append(i,el('span','tg-k'),el('span',null,label));return w};
  dc.append(tg('stCal','Persian calendar for dates',cal()==='persian',i=>{store.set('cal',i.checked?'persian':'gregory');toast(i.checked?'Dates in the Persian calendar':'Dates in the Gregorian calendar')}),
    tg('stNotify','Browser notifications for new alerts',store.get('notify')==='1',async i=>{
      if(i.checked){if(!window.Notification){toast('This browser has no notifications.',true);i.checked=false;return}
        const p=await Notification.requestPermission();if(p!=='granted'){toast('The browser did not allow notifications (an untrusted certificate blocks them).',true);i.checked=false;return}}
      store.set('notify',i.checked?'1':'0')}));
  dc.appendChild(el('div','ch mt28')).appendChild(el('div','ct','Signed-in browsers'));
  (ss.ok?ss.j.sessions:[]).forEach(x=>{const row=el('div','sess');const ag=(x.agent||'').replace(/\(.*?\)/g,'').replace(/\s+/g,' ').trim();
    row.append(el('i','kdot '+(x.current?'ok':'off')),el('div','ss-m'));row.lastChild.append(el('span',null,(x.current?'this browser · ':'')+x.ip),el('span','lab',ag.slice(0,48)+' · '+when(Date.parse(x.seen)/1000)));
    if(!x.current)row.appendChild(btn('Sign out','sec',async()=>{if(await act('settings/sessions/'+x.id+'/drop'))loadSettings2()}));dc.appendChild(row)});
  g.appendChild(dc);
  box.appendChild(g);
}
async function certPick(k){
  const done=r=>{if(r&&r.cert){toast('The panel uses the new certificate now. Reload if the browser asks.');loadSettings2()}};
  if(k==='self')return done(await act('settings/cert/self',{full:true,title:'Back to the self-signed certificate'}));
  if(k==='ca')return done(await act('settings/cert/ca',{full:true,title:'Make the private CA',confirm:'Makes a CA that can only vouch for this server\'s own IPs, and a certificate from it. Download the CA afterwards and install it on your phone.'}));
  if(k==='owner'){const v=await ask('Use your own certificate',{full:true,fields:[{k:'cert',label:'Certificate (PEM)',area:true,rows:5},{k:'key',label:'Private key (PEM)',area:true,rows:5}],ok:'Use it'});if(!v)return;
    return done(await act('settings/cert',{body:v}))}
  if(k==='acme'){const v=await ask('Certificate from Let\'s Encrypt',{full:true,text:'Give a domain that points at this server, or this server\'s public IP (IP certificates last 6 days and renew by themselves). Port 80 opens for a few seconds during the check; it is refused if something else uses it. If it fails, the current certificate stays.',fields:[{k:'domain',label:'Domain or IP',value:S.ov&&S.ov.host.ip||''}],ok:'Get it'});if(!v)return;
    await act('settings/cert/acme',{body:v})}
}

/* ---------- Overview: speed test card ---------- */
// The matrix columns are the last 7 real runs of the shown tunnel (download, scaled to their best); Run test
// keeps it waving while the job measures.
let stRun=null;
async function loadSpeedCard(){
  const box=$('#mx');if(!box||!S.ov)return;
  const iran=S.ov.tunnels.filter(t=>t.role==='Iran');const btn=$('#stBtn');
  $('#stCard').hidden=!iran.length;if(!iran.length)return;
  const r=await api('speedtests').catch(()=>null);const rows=r&&r.ok?r.j.rows:[];
  const name=(rows.find(x=>iran.some(t=>t.name===x.name))||{}).name||(iran.find(t=>t.active)||iran[0]).name;
  $('#stName').textContent=name;btn.dataset.name=name;
  if(stRun)return;
  const mine=rows.filter(x=>x.name===name&&x.down>0);const last=mine[0];
  matrix(box,fillCols(mine.slice(0,7).reverse().map(x=>x.down),7,7),7,false);
  const v=$('#stVal');v.textContent='';
  if(last){v.appendChild(split(last.down.toFixed(1),'MB/s'));$('#stLab').textContent='last run · '+P.fmtDur(Math.max(1,Math.round(Date.now()/1000-last.t)))+' ago';$('#stSub').textContent='↑ '+last.up.toFixed(1)+' MB/s · '+last.mb+' MB'+(last.auto?' · scheduled':'')}
  else{v.textContent='–';$('#stLab').textContent='no test yet';$('#stSub').textContent=''}
  btn.disabled=false;btn.textContent=last?'Run again':'Run test';
}
$('#stBtn').addEventListener('click',async()=>{
  const b=$('#stBtn');const name=b.dataset.name;if(!name||stRun)return;
  let r;try{r=await api('tunnels/'+enc(name)+'/speedtest',{method:'POST',body:{mb:10}})}catch(e){return}
  if(!r.ok||!r.j.job){toast(r.j.error||'Could not start the test.',true);return}
  stRun=r.j.job;b.disabled=true;b.textContent='Testing…';matrix($('#mx'),null,7,true);$('#stVal').textContent='··';$('#stSub').textContent='';
  const t0=Date.now();
  const poll=async()=>{let j=null;try{const x=await api('jobs/'+stRun,{auth:true});if(x.ok)j=x.j}catch(e){}
    const lines=j?(j.log||[]):[];const down=lines.map(l=>/^down: ([\d.]+) MB\/s/.exec(l)).filter(Boolean).pop();
    $('#stLab').textContent=down?'download done · now upload':'measuring · '+Math.round((Date.now()-t0)/1000)+' s';
    if(down){const v=$('#stVal');v.textContent='';v.appendChild(split((+down[1]).toFixed(1),'MB/s'))}
    if(j&&j.state==='running'||!j){setTimeout(poll,1000);return}
    stRun=null;if(j.state!=='done')toast('Speed test failed: '+((lines.filter(l=>l.trim()).pop())||''),true);loadSpeedCard()};
  poll();
});

/* ---------- loading state: a waving dot matrix while a page fetches ---------- */
function loading(v){v.textContent='';const c=el('section','card loadc');const mx=el('div','mx line');matrix(mx,new Array(14).fill(0),3,true);c.append(mx,el('div','lab','loading'));v.appendChild(c)}

/* ---------- browser notifications ---------- */
const seenAlerts=new Set();let alertsPrimed=false;
function notifyAlerts(){
  const al=(S.ov&&S.ov.alerts)||[];
  if(alertsPrimed&&store.get('notify')==='1'&&window.Notification&&Notification.permission==='granted')al.forEach(a=>{if(!seenAlerts.has(a.key))try{new Notification(document.title,{body:a.text,tag:a.key})}catch(e){}});
  al.forEach(a=>seenAlerts.add(a.key));alertsPrimed=true;
}

/* ---------- view hooks ---------- */
let spLoaded=false;
P.onRender=()=>{notifyAlerts();if(S.view==='overview'&&!spLoaded){spLoaded=true;loadSpeedCard()}if(S.view==='tunnels'&&!S.drawer)renderTunnels(true);if(S.view==='kharej')renderKharejPage(true)};
P.onView=v=>{if(v==='overview')loadSpeedCard();if(v==='tunnels')renderTunnels();if(v==='kharej')renderKharejPage();if(v==='traffic')loadTraffic();if(v==='system')loadSystem();if(v==='settings')loadSettings2()};
})();
