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
function btn(txt,cls,fn){const b=el('button','btn sm '+(cls||'sec'),txt);b.type='button';if(fn)b.onclick=e=>P.busy(b,fn(e));return b}
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
function toast(msg,bad){const t=el('div','toast'+(bad?' bad':''),msg);$('#toasts').appendChild(t);setTimeout(()=>P.dust(t),bad?9000:4500)}
P.toast=toast;

/* ---------- dialog: fields + buttons, resolves with the values or null ---------- */
function ask(title,{text,fields=[],ok='Go ahead',danger=false,full=false,err='',body}={}){
  return new Promise(res=>{
    const d=$('#dlg');$('#dlgT').textContent=title;const b=$('#dlgB');b.textContent='';$('#dlgE').textContent=err;
    if(text)b.appendChild(el('p','note',text));
    if(body)b.appendChild(body);
    const all=fields.slice();
    if(full){all.push({k:'password',label:'Password',type:'password'});if(S.ov&&S.ov.twofa)all.push({k:'code',label:'Code from your authenticator app',mode:'numeric'})}
    const inputs={};
    all.forEach(f=>{const w=el('div','fld');const id='dlg_'+f.k;let i;
      if(f.check){w.className='chk';i=el('input');i.type='checkbox';i.id=id;i.checked=!!f.value;const l=el('label',null,f.label);l.htmlFor=id;w.append(i,l);b.appendChild(w);inputs[f.k]=i;return}
      const l=el('label',null,f.label);l.htmlFor=id;
      if(f.options){i=el('select');f.options.forEach(([v,t])=>{const o=el('option',null,t);o.value=v;i.appendChild(o)})}
      else if(f.area){i=el('textarea');i.rows=f.rows||3;i.spellcheck=false}
      else{i=el('input');i.type=f.type||'text';if(f.mode)i.inputMode=f.mode;i.autocomplete=f.type==='password'?'current-password':'off';i.spellcheck=false}
      i.id=id;if(f.value!=null)i.value=f.value;if(f.ph)i.placeholder=f.ph;w.append(l,f.options?P.dd(i):i);if(f.hint)w.appendChild(el('div','lab mt4',f.hint));b.appendChild(w);inputs[f.k]=i;
      if(f.onchange)i.addEventListener('change',()=>f.onchange(i.value,inputs))});
    Object.values(inputs).forEach(i=>i.dispatchEvent(new Event('change')));
    const a=$('#dlgA');a.textContent='';
    const cancel=el('button','btn sec','Cancel');cancel.type='button';const go=danger?swipe(ok):el('button','btn pri','');if(!danger){go.textContent=ok;go.type='submit'}a.append(cancel,go);
    let settled=false;const done=v=>{if(settled)return;settled=true;d.oncancel=null;d.close();res(v)};
    cancel.onclick=()=>done(null);d.onclose=null;d.oncancel=e=>{e.preventDefault();done(null)};
    $('#dlgF').onsubmit=e=>{e.preventDefault();const v={};Object.entries(inputs).forEach(([k,i])=>{v[k]=i.type==='checkbox'?i.checked:i.value.trim()});done(v)};
    if(!d.open)d.showModal();const first=Object.values(inputs).find(i=>i.type!=='checkbox');(first||go.querySelector('button')||go).focus();
  });
}
/* a dangerous action is confirmed by sliding, not by a click that lands by habit: drag the knob to the end. The knob
   is a real button, so Enter or Space on it confirms from the keyboard. */
function swipe(label){
  const w=el('div','swipe');const fill=el('i','sw-fill');const t=el('span','sw-t','Slide to '+(label==='Go ahead'?'confirm':label.toLowerCase()));const k=el('button','sw-k');k.type='button';
  k.setAttribute('aria-label',label+' (slide, or press Enter)');k.appendChild(P.ico('arrow'));w.append(fill,t,k);
  let x0=null,x=0;const max=()=>w.clientWidth-k.offsetWidth-8;
  const put=v=>{x=Math.max(0,Math.min(max(),v));k.style.transform='translateX('+x+'px)';fill.style.width=(x+k.offsetWidth+4)+'px';t.style.opacity=String(1-x/max()*.9)};
  const fire=()=>{w.classList.add('done');put(max());setTimeout(()=>$('#dlgF').requestSubmit(),220)};
  k.addEventListener('pointerdown',e=>{if(w.classList.contains('done'))return;x0=e.clientX-x;k.setPointerCapture(e.pointerId);w.classList.add('drag')});
  k.addEventListener('pointermove',e=>{if(x0!==null)put(e.clientX-x0)});
  const up=()=>{if(x0===null)return;x0=null;w.classList.remove('drag');if(x>=max()*.86)fire();else{w.classList.add('back');put(0);setTimeout(()=>w.classList.remove('back'),420)}};
  k.addEventListener('pointerup',up);k.addEventListener('pointercancel',up);
  k.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();fire()}});
  k.addEventListener('click',e=>{e.preventDefault();if(!x&&!w.classList.contains('done')){w.classList.remove('nudge');void w.offsetWidth;w.classList.add('nudge')}});
  return w}
// digits roll into place like a counter (speed results): each digit is a column of 0-9 that spins to its value
function roll(v,unit){const w=el('span','sv roll');const s=String(v);let dec=false;
  [...s].forEach((ch,i)=>{if(ch==='.'){dec=true;w.appendChild(el('span','dim','.'));return}
    if(!/\d/.test(ch)){w.appendChild(document.createTextNode(ch));return}
    const c=el('span','rl'+(dec?' dim':''));const col=el('span','rl-c');for(let d=0;d<=9;d++)col.appendChild(el('span',null,String(d)));
    col.style.setProperty('--d',ch);col.style.setProperty('--i',i);c.appendChild(col);w.appendChild(c)});
  if(unit)w.appendChild(el('span','unit',unit));w.setAttribute('aria-label',s+(unit?' '+unit:''));return w}
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
  const head=el('div','jh');const st=pill('p-slow','running');const sub=el('span','lab n');head.append(st,sub);const bar=el('div','jbar run');bar.appendChild(el('i'));
  const body=el('div','jbody');const det=el('details','jlog');det.appendChild(el('summary','lab','Show the full log'));const pre=el('pre','log');det.appendChild(pre);const res=el('div','mt8');
  b.append(head,bar,body,res,det);
  const a=$('#dlgA');a.textContent='';const close=el('button','btn sec','Close (it keeps running)');close.type='button';close.onclick=()=>{clearTimeout(jobT);d.close()};a.appendChild(close);
  $('#dlgF').onsubmit=e=>e.preventDefault();d.onclose=()=>{if(!d.open)d.classList.remove('wide')};d.oncancel=()=>clearTimeout(jobT);
  if(!d.open)d.showModal();
  return {st,sub,bar,body,pre,res,close};
}
// speed test: the matrix waves while it measures, then fills; download and upload as big split numbers
function speedView(body){
  const w=el('div','jspeed');const mx=el('div','mx big');const r=el('div','js-r');
  const tile=(lab)=>{const d=el('div','js-t');const l=el('div','lab',lab);const v=el('div','big2 n','··');d.append(l,v);return {d,l,v}};
  const dn=tile('download'),up=tile('upload');r.append(dn.d,up.d);w.append(mx,r);body.appendChild(w);matrix(mx,null,9,true);
  return (lines,state)=>{
    // PROG=dir|MB/s|MB: the live rate while a direction runs (panel 3.6.1)
    let D=null,U=null,now='',tot=0;const P_={};lines.forEach(l=>{let m=/^(down|up): ([\d.]+) MB\/s in ([\d.]+) s/.exec(l);if(m){if(m[1]==='down')D=[+m[2],+m[3]];else U=[+m[2],+m[3]]}
      m=/: (\d+) MB (download|upload) \.\.\./.exec(l);if(m){now=m[2];tot=+m[1]}m=/^PROG=(down|up)\|([\d.]+)\|([\d.]+)/.exec(l);if(m)P_[m[1]==='down'?'download':'upload']=[+m[2],+m[3]]});
    const set=(t,x,word)=>{const p=state==='running'&&now===word?P_[word]:null,txt=x?'x'+x[0]+x[1]:p?'p'+p[0]+p[1]:'w'+(state==='running'&&now===word);
      if(t.v.dataset.s===txt)return;t.v.dataset.s=txt;t.v.textContent='';t.v.classList.toggle('wait',!x&&!p);
      if(x){t.v.appendChild(roll(x[0].toFixed(1),'MB/s'));t.l.textContent=word+' · '+x[1].toFixed(1)+' s'}
      else if(p){t.v.appendChild(split(p[0].toFixed(2),'MB/s'));t.l.textContent=word+' · '+Math.min(p[1],tot||p[1]).toFixed(1)+(tot?' of '+tot:'')+' MB'}
      else t.v.textContent=state==='running'&&now===word?'measuring':'··';t.d.classList.toggle('now',state==='running'&&now===word&&!x)};
    set(dn,D,'download');set(up,U,'upload');
    if(state!=='running'){const top=Math.max(D?D[0]:0,U?U[0]:0,1);const h=x=>x?Math.max(1,Math.round(x[0]/top*9)):null;const a=h(D),b=h(U);matrix(mx,[a,a,a,a,null,b,b,b,b],9,false)}
  };
}
// carrier test: a live board, one row per carrier as the manager tests it (ATROW lines), the winner marked
const PRESETS={normal:'standard carriers',fast:'anti-censor fast',anti:'anti-censor grid',reverse:'reverse only',extended:'extended (shaped too)'};
function carrierView(body,id){
  const w=el('div','jcar');const top=el('div','jc-top');const cnt=el('div','jc-cnt');const prog=el('div','jc-prog');
  // the preset this run tests, and the way out: End test keeps what was measured and goes on to the choice
  const meta=el('div','jc-meta');const pre=el('span','chip jc-pre');const end=el('button','btn sec','End test');end.type='button';meta.append(pre);
  top.append(cnt,meta,prog);
  const list=el('div','jc-list');w.append(top,list);body.appendChild(w);
  const seen=new Set();let tun='',now='';
  const ctl=(cmd,b)=>P.busy(b,act('jobs/'+id+'/ctl',{body:{cmd,label:now}}));
  end.onclick=()=>ctl('stop',end);
  const pend=el('div','jc-row pend');const pl=el('span','jc-lab lab');const pmx=el('div','mx line');matrix(pmx,new Array(12).fill(0),1,true);
  const skip=el('button','btn sec','Skip');skip.type='button';skip.hidden=true;end.hidden=true;skip.onclick=()=>ctl('skip',skip); // shown only while a carrier is under test
  pend.append(el('span','jc-rank'),pl,pmx);
  $('#dlgA').prepend(skip,end); // next to Close, one row of buttons
  return (lines,state)=>{
    let plan=0,preset='';const picks=new Set();const rows=new Map();now='';
    lines.forEach(l=>{let m=/^ATPLAN=(\d+)/.exec(l);if(m)plan=+m[1];m=/^ATPICK=(.+)$/.exec(l);if(m)picks.add(m[1].trim());m=/^TUNNEL=(.+)$/.exec(l);if(m)tun=m[1].trim();
      m=/^ATPRESET=(\w+)/.exec(l);if(m)preset=m[1];m=/^ATNOW=(.+)$/.exec(l);if(m)now=m[1].trim();
      m=/^ATROW=(ok|fail)\|([^|]*)\|(.*)$/.exec(l);if(m){const f=m[3].split('|');rows.set(m[2],m[1]==='ok'?{ok:true,down:+f[0],up:+f[1],rtt:+f[2]}:{ok:false,why:f.join('|')});if(m[2]===now)now=''}});
    pre.textContent=preset?PRESETS[preset]||preset:'';pre.hidden=!preset;end.hidden=state!=='running';
    if(!plan&&!rows.size){skip.hidden=true;end.hidden=true;return false}
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
    if(state==='running'){const re=plan&&done>=plan;pl.textContent='';
      if(now)pl.append(re?'re-measuring ':'testing ',el('b',null,now));else pl.textContent=re?'re-measuring the best ones':'starting the next carrier';
      skip.hidden=!now;skip.textContent='Skip '+now;if(pend.parentNode!==list)list.appendChild(pend)}else{pend.remove();skip.hidden=true}
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
// any other job: its steps, the current one a dot-matrix. Rows are updated in place, so a poll only animates the
// line that is new (rebuilding them all replayed every entry animation and made the dialog stutter).
function stepView(body){
  const steps=el('div','jsteps jsv');body.appendChild(steps);
  const row=(k,text,old)=>{const s=old||el('div','jstep');if(s.dataset.k===k&&s.dataset.t===text)return s;s.className='jstep '+k;s.dataset.k=k;s.dataset.t=text;
    const m=el('i');if(k==='now')m.appendChild(P.dm('spiral',3,4));else m.appendChild(P.ico(k==='ok'?'check':'x'));s.replaceChildren(m,el('span',null,text));return s};
  return (lines,state)=>{let ls=lines.filter(l=>l.trim()).slice(-6);let ks;
    if(!ls.length){ls=[state==='running'?'Starting …':'It stopped before printing anything.'];ks=[state==='running'?'now':'bad']}
    else ks=ls.map((l,i)=>{const last=i===ls.length-1;return last&&state==='running'?'now':last&&state!=='done'?'bad':'ok'});
    const old=[...steps.children];
    // the window slides when a 7th line arrives: drop from the top, then match the rest by position
    while(old.length&&old.length>ls.length)old.shift().remove();
    if(old.length&&old[0].dataset.t!==ls[0]&&old.findIndex(o=>o.dataset.t===ls[0])>0){const k=old.findIndex(o=>o.dataset.t===ls[0]);old.splice(0,k).forEach(o=>o.remove())}
    ls.forEach((l,i)=>{const s=row(ks[i],l,old[i]);if(!old[i])steps.appendChild(s)})};
}
async function openJob(id){
  clearTimeout(jobT);
  const v=jobShell();let spd=null,car=null,steps=null;let misses=0;
  const tick=async()=>{
    let r=null;try{r=await api('jobs/'+id,{auth:true})}catch(e){}
    if(!r||!r.ok){misses++;v.st.lastChild.textContent=misses>3?'waiting for the panel to come back':'running';jobT=setTimeout(tick,2000);return}
    misses=0;const j=r.j;$('#dlgT').textContent=j.title;
    const all=(j.log||[]).map(strip).filter(l=>j.kind!=='pair'||!/^TUNNEL=/.test(l)); /* a pairing link is hidden: no carrier switch on it */const shown=all.filter(l=>!/^[A-Z_]+=/.test(l));
    if(j.kind==='speedtest'){spd=spd||speedView(v.body);spd(all,j.state)}
    else{car=car||carrierView(v.body,id);steps=steps||stepView(v.body);
      // the board takes over as soon as the manager reports carriers; until then the plain steps
      if(car(all,j.state))v.body.classList.add('has-car');else steps(shown,j.state)}
    const atEnd=v.pre.scrollTop+v.pre.clientHeight>=v.pre.scrollHeight-8;v.pre.textContent=shown.join('\n')||'…';if(atEnd)v.pre.scrollTop=v.pre.scrollHeight;
    const secs=Math.max(0,Math.round(Date.now()/1000-j.started));const dur=secs<60?secs+' s':Math.floor(secs/60)+' min '+(secs%60)+' s';if(j.state==='running')v.seen=1;v.sub.textContent=j.state==='running'?'running for '+dur:v.seen?'took about '+dur:'';
    v.bar.className='jbar '+({running:'run',done:'ok'}[j.state]||'bad');
    const cls={running:'p-slow',done:'p-up',failed:'p-down',lost:'p-down'}[j.state];v.st.className='pill '+cls;v.st.lastChild.textContent={running:'running',done:'done',failed:'failed (code '+j.rc+')',lost:'ended without a result'}[j.state];
    if(j.state==='running'){jobT=setTimeout(tick,1000);return}
    v.close.textContent='Close';v.res.textContent='';
    if(j.state!=='done'){const last=shown.filter(l=>l.trim()).slice(-2).join(' · ');
      v.res.appendChild(el('p','note bad',last||(j.rc===127?'The command could not start on this server (code 127: not found). Reinstall with the installer, then try again.':'It ended with code '+j.rc+' and printed nothing. The server journal has more: '+(S.cli||'wattun')+' logs.')))}
    if(j.result&&j.result.TOKEN)v.res.appendChild(tokenBox(j.result.TOKEN));
    toast(j.title+(j.state==='done'?': done':': failed'),j.state!=='done');P.loadOverview();if(S.view==='system')loadSystem();loadSpeedCard();
  };
  tick();
}
P.openJob=openJob;P.toast=toast;
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
  tools.appendChild(btn('New tunnel','fx-holo',newTunnel));
  strip.append(sum,rate,tools);v.appendChild(strip);
  // tiles
  const g=el('div','tgrid');
  if(!ts.length){const e=el('section','card empty-hero');e.append(el('div','eh-t','No tunnels on this server yet.'),el('p','note','Paste a token from Kharej, or create the tunnel on Kharej and here in one go.'),btn('New tunnel','fx-holo',newTunnel));g.appendChild(e)}
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
P.newTunnel=()=>newTunnel();
// the carrier test only runs for an auto tunnel: a token from Kharej may be one, a carrier picked here is not
const testVis=inp=>{const notAuto=inp.where&&inp.where.value==='both'&&inp.carrier&&inp.carrier.value!=='auto';inp.test&&(inp.test.closest(".fld").hidden=notAuto);
  inp.domain&&(inp.domain.closest(".fld").hidden=notAuto||!inp.where||inp.where.value!=='both')};
async function newTunnel(){
  const ov=S.ov||{tunnels:[],kharej:[]};const vias=(ov.kharej||[]).filter(k=>k.online);
  const fields=[{k:'where',label:'Where',options:vias.length?[['both','On Kharej and here, in one go'],['here','Here only, from a token']]:[['here','Here only, from a token']],
      onchange:(v,inp)=>{const both=v==='both';['via','carrier'].forEach(k=>inp[k]&&(inp[k].closest(".fld").hidden=!both));inp.token&&(inp.token.closest(".fld").hidden=both);testVis(inp)}},
    {k:'token',label:'Token from Kharej (wat1:...)',area:true,rows:3},
    {k:'via',label:'Kharej server',options:vias.map(k=>[k.host,k.host])},
    {k:'carrier',label:'Carrier',options:[['auto','auto: test them all, keep the best'],['wss','wss: TLS websocket, the safe default'],['tls','tls'],['tcp','tcp'],['udp','udp'],['icmp','icmp: ping packets'],['grpc','grpc'],['h2','h2'],['ws','ws'],['h2c','h2c'],['ptcp','ptcp: fake TCP, raw socket'],['spray','spray: hops ports'],['gre','gre'],['ipip','ipip'],
      ...['tcp','tls','wss','ws','grpc','h2','h2c','udp'].map(c=>['reverse-'+c,c+' reverse: Kharej dials here'])],
      onchange:(v,inp)=>testVis(inp)},
    {k:'map',label:'Ports',ph:'39901:18999, 8443:443',hint:'public port here : port on Kharej, comma-separated'},
    {k:'name',label:'Name (empty = automatic)'},
    {k:'domain',label:'Cloudflare domain (optional)',ph:'cdn.example.com',hint:'proxied to Kharej (orange cloud, SSL Full); the test then tries wss and grpc through Cloudflare'},
    {k:'test',label:'Carrier test',options:[['normal','normal'],['fast','fast'],['anti','anti-censor grid'],['reverse','reverse only'],['extended','extended (shaped carriers too)']]}];
  await act('new',{title:'New tunnel',fields,ok:'Create'});
}

/* ---------- drawer: ports and actions ---------- */
/* tunnel boot: while a start or restart comes up, the drawer shows its stages on a dot matrix that fills stage by
   stage, a live rate trace, and the time; it folds away once traffic can flow, or turns red with the reason */
function boot(name,t,verb){
  $('#drawer .boot')&&$('#drawer .boot').remove();
  const W=26,H=6,b=el('div','boot');const mx=el('div','bt-mx');const dots=[];
  for(let y=0;y<H;y++)for(let x=0;x<W;x++){const i=el('i');i.style.setProperty('--x',x);i.style.setProperty('--y',y);i.style.setProperty('--r',((x*7+y*13)%10)/10);mx.appendChild(i);dots.push(i)}
  const st=el('div','bt-st');const stages=[verb==='restart'?'Restart sent':'Start sent','Unit running',t.role==='Iran'?'Session with Kharej':'Iran connected','Ready for traffic'];
  const rows=stages.map(x=>{const r=el('div','bt-r');r.append(el('i'),el('span',null,x));st.appendChild(r);return r});
  const NS='http://www.w3.org/2000/svg',g=document.createElementNS(NS,'svg');g.setAttribute('viewBox','0 0 260 40');g.setAttribute('preserveAspectRatio','none');g.setAttribute('class','bt-g');g.setAttribute('aria-hidden','true');
  const pl=document.createElementNS(NS,'polyline');g.appendChild(pl);
  const head=el('div','bt-h');const tt=el('span',null,(verb==='restart'?'Restarting ':'Starting ')+name);const tm=el('span','lab n','0.0 s');head.append(tt,tm);
  b.append(head,mx,st,g);$('#dRoute').after(b);
  // only state read after the start/restart answered counts: before that the overview and live feed still describe the old process
  const t0=performance.now();let stage=0,ok=null,since3=0,iv,fresh=false,seen=0,lastT=null,at=0;const pts=[];
  const set=k=>{if(k<=stage||performance.now()-at<450)return;stage=k;at=performance.now();rows.forEach((r,i)=>r.className='bt-r'+(i<k?' ok':i===k?' now':''));
    const fill=Math.round(k/4*W);dots.forEach((d,i)=>d.classList.toggle('on',i%W<fill))};
  set(0);rows[0].className='bt-r now';
  const end=(good,msg)=>{clearInterval(iv);b.classList.add(good?'done':'fail');tm.textContent=((performance.now()-t0)/1000).toFixed(1)+' s';
    if(good){at=0;set(4);tt.textContent=name+' is up';setTimeout(()=>{b.classList.add('fold');setTimeout(()=>b.remove(),600)},2200)}
    else{tt.textContent=msg;rows.forEach((r,i)=>{if(i===stage)r.className='bt-r bad'})}};
  iv=setInterval(()=>{const sec=(performance.now()-t0)/1000;tm.textContent=sec.toFixed(1)+' s';
    if(!b.isConnected){clearInterval(iv);return}
    const tv=(S.ov.tunnels||[]).find(x=>x.name===name)||{},l=S.live[name]||{},lt=(S.series[S.series.length-1]||{}).t;
    if(ok&&lt!==lastT){lastT=lt;seen++}
    if(ok)set(1);if(fresh&&tv.active)set(2);if(stage>=2&&seen>=2&&l.alive)set(3);
    if(stage===3){since3=since3||sec;if(l.down>0||l.conns>0||sec-since3>2.5)end(true)}
    pts.push(l.down||0);if(pts.length>80)pts.shift();const mxv=Math.max(.01,...pts);pl.setAttribute('points',pts.map((v,i)=>(i/Math.max(1,pts.length-1)*260).toFixed(1)+','+(38-v/mxv*34).toFixed(1)).join(' '));
    if(ok&&sec%1<.26)P.loadOverview().then(()=>{fresh=true});
    if(sec>40)end(false,name+' did not come up: the journal below says why')},250);
  return r=>{if(!r){end(false,'The '+verb+' was refused');return}ok=true;lastT=(S.series[S.series.length-1]||{}).t}}
P.onDrawer=async(name,t)=>{
  const a=$('#dActs');a.textContent='';
  const route=$('#dRoute');route.textContent='';const ln=el('i','t-line'+(t.active?' on':''));ln.appendChild(el('b'));route.append(el('span','t-end',S.ov.host.name||'here'),ln,el('span','t-end',t.peer||'–'));
  const grp=(title,items)=>{const g=el('div','agrp');g.appendChild(el('div','lab',title));const w=el('div','tools');items.filter(Boolean).forEach(x=>w.appendChild(x));g.appendChild(w);a.appendChild(g)};
  const u=act2=>()=>{const b=act2!=='stop'?boot(name,t,act2):null;
    return act('tunnels/'+enc(name)+'/'+act2,act2==='stop'?{confirm:'Stop '+name+'? Its users lose the connection.',title:'Stop '+name,danger:true}:{}).then(r=>{if(b)b(r);if(r){if(!b)toast(name+': '+act2+' done');P.loadOverview()}})};
  grp('Run',[t.active?btn('Restart','sec',u('restart')):btn('Start','pri',u('start')),t.active&&btn('Stop','sec danger',u('stop'))]);
  grp('Test',[t.role==='Iran'&&btn('Speed test','sec',()=>act('tunnels/'+enc(name)+'/speedtest',{title:'Speed test of '+name,fields:[{k:'mb',label:'Megabytes each way',value:'10',mode:'numeric'}],ok:'Run'})),
    t.role==='Iran'&&btn('Re-test carriers','sec',()=>act('tunnels/'+enc(name)+'/retest',{confirm:'Tests every carrier again (auto tunnels). The tunnel restarts if it switches; pick bond to join the best ones.',title:'Re-test carriers',fields:[TESTF],ok:'Start the test'})),
    t.role==='Iran'&&btn('Change carrier','sec',()=>changeCarrier(name)),
    btn('Diagnose','sec',()=>act('tunnels/'+enc(name)+'/diagnose'))]);
  const cdnc=/^(ws|wss|h2|h2c|grpc)$/.test(t.carrier||''),pool=/^(tcp|tls|ws|wss|h2|h2c|grpc)(\+(tcp|tls|ws|wss|h2|h2c|grpc))*$/.test(t.carrier||'');
  const tool=(op,label,confirm)=>btn(label,'sec',()=>act('tunnels/'+enc(name)+'/tool',{body:{op},title:label,confirm,ok:'Start'}));
  grp('Tune',[t.role==='Iran'&&!t.reverse&&pool&&tool('acmatrix','Find best anti-censorship','Tests every fake-SNI, desync mode and ECH combination on this route and applies the fastest. Takes a few minutes; the tunnel restarts once at the end.'),
    t.role==='Iran'&&!t.reverse&&cdnc&&tool('cdntune','Tune Cloudflare path','Finds the Cloudflare edges that serve this tunnel\'s domain, with ECH and TLS settings, and applies the best. Needs a domain on the tunnel.'),
    t.role==='Iran'&&/\+/.test(t.carrier||'')&&tool('bondretest','Re-test bond legs','Tests every leg again plus the ones that failed before, and adds one that works again.'),
    tool('resettraffic','Reset traffic','Zeroes the lifetime traffic counters of this tunnel. It restarts.')]);
  grp('Configure',[btn('Ports','sec',()=>editPorts(name,t)),t.role==='Iran'&&btn('Move ports','sec',()=>movePorts(name,t)),btn('Limit a port','sec',()=>limitPort(name))]);
  if(/\+/.test(t.carrier||''))bondBlock(a,name);
  grp('Keys and pairing',[btn('Show token','sec',()=>showToken(name)),t.paired&&btn('Forget pairing','sec danger',()=>act('tunnels/'+enc(name)+'/pair-forget',{full:true,danger:true,title:'Forget the pairing of '+name,confirm:'Turns off the management channel of '+name+' (pairing: false) and restarts it. The tunnel keeps working; Kharej is then managed from its own console until you pair again.'}).then(r=>{if(r){toast('Pairing forgotten');P.loadOverview()}}))]);
  grp('Danger',[btn('Delete','sec danger',()=>deleteTunnel(name,t))]);
  renderDrawerPorts(name,[]);settingsBlock(name,t);
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
// Change carrier: the tunnel's last carrier test, as the job showed it, with the same picker; no new test (4.0.2)
async function changeCarrier(name){
  const r=await api('tunnels/'+enc(name)+'/carriers').catch(()=>null);
  if(!r||!r.ok||!r.j.rows.length){toast('No saved carrier test for '+name+' yet. Run Re-test carriers once; later switches use its results.',true);return}
  const body=el('div');info('Change the carrier of '+name,body);
  body.appendChild(el('p','note','From the test of '+when(r.j.at)+'. Tick one to switch, or several of one kind to bond them; nothing is tested again.'));
  carrierView(body,'')(['TUNNEL='+name,'ATPRESET='+(r.j.preset||'')].concat(r.j.rows.map(x=>'ATROW='+x),(r.j.use||[]).map(x=>'ATPICK='+x)),'done');
}
// Settings: the console's Advanced page as presets. A click only marks a change; the bar at the bottom applies them
// all with one restart (keys both ends must share go to Kharej first, on the server side).
async function settingsBlock(name,t){
  const w=$('#dSet'),bar=$('#dApply');w.textContent='';bar.hidden=true;$('#dSetSub').textContent='';
  const r=await api('tunnels/'+enc(name)+'/settings').catch(()=>null);
  if(S.drawer!==name)return;
  if(!r||!r.ok||!r.j.options){w.appendChild(el('div','empty','Could not read the settings.'));return}
  const st=r.j,pend={},opts=st.options;
  const top=el('div','ogrp');top.appendChild(el('div','og-t','General'));w.appendChild(top);
  // start at boot: a switch, applied at once (no restart)
  const bw=el('div','orow inl'),sw=el('button','tgl'+(st.boot?' on':''));sw.type='button';sw.setAttribute('role','switch');sw.setAttribute('aria-checked',st.boot);sw.setAttribute('aria-label','Start at boot');sw.appendChild(el('i'));
  const bt=el('div','or-l'),bl=el('div','lab');bt.append(el('div','or-n','Start at boot'),bl);
  const bpaint=()=>{sw.classList.toggle('on',st.boot);sw.setAttribute('aria-checked',st.boot);bl.textContent=st.boot?'comes back after a reboot':'stays down after a reboot'};bpaint();
  sw.onclick=()=>P.busy(sw,act('tunnels/'+enc(name)+'/boot',{body:{on:!st.boot}}).then(x=>{if(x){st.boot=!st.boot;bpaint();P.loadOverview()}}));
  bw.append(bt,sw);top.appendChild(bw);
  // anti-censorship: one preset, applied on the end that dials
  if(st.presets&&st.presets.length){
    const aw=el('div','orow'),hd=el('div','or-l');
    hd.append(el('div','or-n','Anti-censorship'),el('div','lab',st.ac_where==='kharej'?'Reverse tunnel: Kharej dials, so the preset is set there':'now: '+(st.ac_now||'none')));
    const ch=el('div','ochips wrap');
    st.presets.forEach(p=>{const b=el('button','och'+(st.ac_where==='here'&&acMatch(st.ac_now,p.value)?' on':''),p.label);b.type='button';if(p.hint)b.title=p.hint;
      b.onclick=()=>act('tunnels/'+enc(name)+'/ac-preset',{body:{preset:p.value},title:'Anti-censorship: '+p.label,confirm:(p.hint?p.hint[0].toUpperCase()+p.hint.slice(1)+'. ':'')+(st.ac_where==='kharej'?'Kharej applies it and restarts its side; it rolls back if the tunnel does not come up.':name+' restarts with it; open connections drop for a few seconds.'),ok:'Apply'}).then(x=>{if(x){toast('Preset '+p.label+(x.job?' is being applied':' applied on Kharej'));setTimeout(()=>{if(S.drawer===name)settingsBlock(name,t)},x.job?6000:1500)}});
      ch.appendChild(b)});
    aw.append(hd,ch);
    if(st.ac_where==='here'){const tb=btn('Test what passes the filter','sec',()=>act('tunnels/'+enc(name)+'/ac-test'));tb.classList.add('ortest');aw.appendChild(tb)}
    top.appendChild(aw)}
  // the option groups
  const rows=[];
  const draw=()=>{
    const n=Object.keys(pend).length;bar.hidden=!n;bar.textContent='';if(!n)return;
    const both=Object.keys(pend).some(k=>opts.find(o=>o.key===k).both_ends);
    const sum=Object.entries(pend).map(([k,v])=>{const o=opts.find(x=>x.key===k);return o.label+' '+labelOf(o,v)}).join(' · ');
    const tx=el('div','ab-t');tx.append(el('b',null,n+(n===1?' change':' changes')),el('span','lab',sum));
    bar.append(tx,btn('Discard','sec',()=>{Object.keys(pend).forEach(k=>delete pend[k]);rows.forEach(f=>f());draw()}),
      btn('Apply and restart','pri',()=>act('tunnels/'+enc(name)+'/settings',{method:'PUT',body:{set:pend},title:'Apply '+n+(n===1?' change':' changes'),
        confirm:(both?'Kharej changes first; if it refuses, nothing changes here. ':'')+name+' restarts once with the new settings; open connections drop for a few seconds.',ok:'Apply and restart'}).then(x=>{if(x){toast('Settings applied. '+name+' restarted.');P.loadOverview();settingsBlock(name,t)}})))};
  [...new Set(opts.map(o=>o.group))].forEach(g=>{
    const box=el('div','ogrp');box.appendChild(el('div','og-t',g));w.appendChild(box);
    opts.filter(o=>o.group===g).forEach(o=>{
      const row=el('div','orow'),lt=el('div','or-l'),nm=el('div','or-n',o.label);
      if(o.both_ends)nm.appendChild(el('span','tag','both ends'));lt.append(nm,el('div','lab',o.help));
      const ch=el('div','ochips');row.append(lt,ch);box.appendChild(row);
      const cur=()=>o.key in pend?pend[o.key]:o.value;
      const set=v=>{if(v===o.value)delete pend[o.key];else pend[o.key]=v;paint();draw()};
      let cb=null,f=null,inp=null;
      const paint=()=>{const v=cur(),known=o.choices.some(c=>c.value===v),p=o.key in pend;
        ch.querySelectorAll('.och[data-v]').forEach(b=>{const on=b.dataset.v===v;b.classList.toggle('on',on&&!p);b.classList.toggle('pend',on&&p)});
        if(cb){cb.hidden=false;f.hidden=true;cb.textContent=known?'Custom':v+(o.custom.unit?' '+o.custom.unit:'');cb.classList.toggle('on',!known&&!p);cb.classList.toggle('pend',!known&&p)}};
      o.choices.forEach(c=>{const b=el('button','och',c.label);b.type='button';b.dataset.v=c.value;if(c.hint)b.title=c.hint;b.onclick=()=>set(c.value);ch.appendChild(b)});
      if(o.custom){cb=el('button','och','Custom');cb.type='button';f=el('span','ocust');f.hidden=true;
        inp=el('input');inp.inputMode=o.custom.ip?'text':'decimal';inp.spellcheck=false;inp.autocomplete='off';inp.placeholder=o.custom.ip?'10.0.0.5':o.custom.min+'–'+o.custom.max;inp.setAttribute('aria-label',o.label);
        const ok=el('button','och on','Set');ok.type='button';
        const take=()=>{const v=inp.value.trim();if(!v){paint();return}const e=checkCustom(o,v);if(e){toast(e,true);inp.focus();return}set(v)};
        ok.onclick=take;inp.onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();take()}if(e.key==='Escape')paint()};
        f.append(inp);if(o.custom.unit)f.appendChild(el('span','lab',o.custom.unit));f.appendChild(ok);
        cb.onclick=()=>{cb.hidden=true;f.hidden=false;const v=cur();inp.value=o.choices.some(c=>c.value===v)?'':v;inp.focus()};ch.append(cb,f)}
      paint();rows.push(paint)})});
  $('#dSetSub').textContent=opts.length+' options';
}
const AC_WORD={cloudflare:'cloudflare','rst-fast':'rst-fast',mci:'mci',irancell:'irancell',conservative:'conservative',blackout:'blackout'};
function acMatch(now,v){now=(now||'').toLowerCase();return v==='off'?/none|disabled/.test(now):now.includes(AC_WORD[v])}
function labelOf(o,v){const c=o.choices.find(x=>x.value===v);return c?c.label:v+(o.custom&&o.custom.unit?' '+o.custom.unit:'')}
function checkCustom(o,v){const c=o.custom;
  if(c.ip)return /^\[?[0-9a-fA-F:.]+\]?$/.test(v)?'':o.label+': enter an IPv4 or IPv6 address';
  const f=Number(v);if(!isFinite(f)||(!c.float&&!Number.isInteger(f))||f<(c.min||0)||f>c.max)return o.label+': enter '+(c.float?'a number':'a whole number')+' from '+c.min+' to '+c.max+(c.unit?' '+c.unit:'');return ''}
function renderDrawerPorts(name,ports){
  const w=$('#dPorts');w.textContent='';$('#dPortsSub').textContent=ports.length?ports.length+' public':'';
  if(!ports.length){w.appendChild(el('div','empty','No per-port numbers yet (the tunnel is stopped, or has no metrics address).'));return}
  // busiest first; only the top 4 until asked, so a 19-port tunnel does not bury the rest of the drawer
  const all=ports.slice().sort((a,b)=>(b.rate_down+b.rate_up)-(a.rate_down+a.rate_up)||(b.down+b.up)-(a.down+a.up)||b.conns-a.conns),open=S.portsAll===name;
  (open?all:all.slice(0,4)).forEach(p=>{const c=el('div','pcard');
    const h=el('div','pc-h');h.append(el('span','pc-port n',p.port),el('span','lab',p.conns+' users'));c.appendChild(h);
    const s=el('div','pc-s');s.append(el('span',null,'↓ '+P.fmtBytes(p.down)),el('span',null,'↑ '+P.fmtBytes(p.up)),el('span','lab',P.fmtRate(p.rate_down)+' MB/s now'));c.appendChild(s);
    if(p.rate_limit)c.appendChild(el('div','lab','limited to '+(p.rate_limit*8/1e6).toFixed(0)+' Mbit/s'));
    if(p.quota_limit>0){c.appendChild(quotaBar(p));c.appendChild(btn('Reset quota','sec',()=>act('tunnels/'+enc(name)+'/quota-reset',{body:{port:+p.port},confirm:'Usage of port '+p.port+' goes back to zero now.',title:'Reset the quota'}).then(r=>{if(r){toast('Quota reset');portsAt=0;P.openDrawer(name)}})))}
    w.appendChild(c)});
  if(all.length>4)w.appendChild(btn(open?'Show the busiest 4':'Show all '+all.length+' ports','sec pmore',()=>{S.portsAll=open?null:name;renderDrawerPorts(name,ports)}));
}
async function editPorts(name,t){const v=await ask('Ports of '+name,{fields:[{k:'ports',label:'One mapping per line: 443, 8443:443, 53/udp',area:true,rows:6,value:(t.ports||[]).join('\n')}],ok:'Save'});
  if(!v)return;const r=await act('tunnels/'+enc(name)+'/ports',{method:'PUT',body:{ports:v.ports.split(/[\n,]+/).map(x=>x.trim()).filter(Boolean)}});if(r){toast(r.note||'Saved');P.loadOverview()}}
// move ports to another Iran tunnel; a paired target gets them added on its Kharej first (4.0.3)
async function movePorts(name,t){
  const ps=t.ports||[],to=((S.ov&&S.ov.tunnels)||[]).filter(x=>x.role==='Iran'&&x.name!==name);
  if(ps.length<2||!to.length){toast(ps.length<2?name+' has one port; a tunnel keeps at least one.':'No other Iran tunnel to move to.',true);return}
  const fields=[{k:'to',label:'Move to',options:to.map(x=>[x.name,x.name+' · '+x.carrier])}].concat(ps.map((p,i)=>({k:'p'+i,label:p,check:true})));
  const v=await ask('Move ports of '+name,{text:'Tick the ports to move. The other tunnel takes them over within seconds, no restart.',fields,ok:'Move'});if(!v)return;
  const ports=ps.filter((p,i)=>v['p'+i]);if(!ports.length){toast('Tick at least one port.',true);return}
  const r=await act('tunnels/'+enc(name)+'/move-ports',{body:{to:v.to,ports}});if(r){toast(r.note);P.loadOverview()}}
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
  if(S.ov.host.role==='kharej'){pairingCard(v);return}
  const bar=el('div','k-bar');bar.append(el('span','lab grow',kh.length?kh.length+' paired':''),btn('Add Kharej','pri',addKharej));v.appendChild(bar);
  if(!kh.length){const e=el('section','card empty-hero');e.append(el('div','eh-t','No Kharej server is paired with this one.'),el('p','note','On the Kharej server run '+(S.cli||'wattun')+' and press t, or open its panel: it shows the pairing token. Then press Add Kharej here and paste it.'));v.appendChild(e);return}
  const g=el('div','kgrid');
  kh.forEach((k,i)=>{
    const c=el('section','card ksrv'+(k.online?'':' off'));c.style.animationDelay=(0.1+i*0.08)+'s';c.dataset.host=k.host;
    const top=el('div','k-top');top.appendChild(pill(k.online?'p-up':'p-down',k.online?'online':'unreachable'));
    if(k.version){const vc=el('span','chip n','v'+k.version);top.appendChild(vc);if(latest&&newer(latest,k.version))top.appendChild(el('span','chip upd','v'+latest+' is out'))}
    top.appendChild(el('span','grow'));if(k.res&&k.res.uptime_s)top.appendChild(el('span','lab','up '+P.fmtDur(k.res.uptime_s)));
    if(k.caps)top.title='This pairing may: '+TIERS.slice(0,TIERS.indexOf(k.caps)+1).join(', ');c.appendChild(top);
    const fl=P.flaps(k,'big',24,0.04);c.appendChild(fl);
    // the link: this server to Kharej, packets at the live rate
    const link=el('div','k-link');const a1=el('div','kl-end');a1.append(el('span','kl-dot me'),el('span',null,S.ov.host.name||'this server'));
    const mid=el('div','kl-mid');const line=el('i','t-line wide'+(k.online?' on':''));line.appendChild(el('b'));const st=el('div','kl-st');st.dataset.k='kst';mid.append(line,st);
    const a2=el('div','kl-end r');a2.append(el('span',null,k.host),el('span','kl-dot '+(k.online?'ok':'bad')));link.append(a1,mid,a2);c.appendChild(link);
    // load, memory and disk of that server (Kharej 3.6.1+ sends them with its hello)
    if(k.online&&k.res){const r=k.res,ar=el('div','arcs sm');ar.append(arc('load · '+r.cpus+(r.cpus===1?' core':' cores'),r.cpus?Math.min(100,r.load1/r.cpus*100):0,r.load1.toFixed(2),85),arc('memory',r.mem_pct,r.mem_pct.toFixed(0)+'%',90),arc('disk',r.disk_pct,r.disk_pct.toFixed(0)+'%',90));c.appendChild(ar)}
    // the tunnels here that lead to it (the pairing link stays out of sight: it is not a tunnel to manage)
    const via=el('div','k-via');const mine=k.via.filter(n=>n!==k.link);if(mine.length)via.appendChild(el('span','lab','tunnels here'));mine.forEach(n=>{const b=el('button','pchip lnk',n);b.type='button';b.onclick=()=>P.openDrawer(n);via.appendChild(b)});
    if(!k.online&&k.error)via.appendChild(el('span','lab bad',k.error));if(k.seen)via.appendChild(el('span','lab grow r','seen '+when(k.seen)));c.appendChild(via);
    const list=el('div','k-tuns');
    (k.tunnels||[]).forEach(rt=>{const row=el('div','ktr');const ok=rt.health==='ok',act2=rt.state==='active';
      row.append(el('i','kdot '+(ok?'ok':act2?'bad':'off')),el('span','kt-n',rt.name),el('span','chip',rt.carrier||'–'),el('span','kt-p n',rt.ports||''),el('span','lab kt-s',ok?'up':act2?(rt.health||'no link'):'stopped'));
      const m=el('div','kt-a');
      if(k.online){[[act2?'restart':'start',act2?'Restart':'Start',''],act2&&['stop','Stop','danger']].filter(Boolean).forEach(([a,t,d])=>m.appendChild(btn(t,'sec ic '+d,()=>act('kharej/'+enc(k.host)+'/tunnel',{body:{name:rt.name,action:a},confirm:a==='stop'?'Stop '+rt.name+' on '+k.host+'?':null,title:t+' '+rt.name,danger:a==='stop'}).then(r=>{if(r){toast(rt.name+': '+a+' done');P.loadOverview()}}))));
        m.appendChild(btn('New key','sec ic',()=>keyRotate(k,rt)));m.appendChild(btn('Delete','sec ic danger',()=>kharejDelete(k,rt)))}
      row.appendChild(m);list.appendChild(row)});
    if(k.online&&!(k.tunnels||[]).length)list.appendChild(el('div','empty','No tunnels listed on that server.'));
    c.appendChild(list);
    if(k.online){const t=el('div','k-acts');
      t.append(btn('Update','sec sm',()=>act('kharej/'+enc(k.host)+'/update',{full:true,title:'Update '+k.host,confirm:'Kharej downloads the latest release, checks its signature and restarts its tunnels. It rolls back by itself if the new version fails.'}).then(r=>r&&toast(r.note||'Update started'))),
        btn('Backup','sec sm',()=>askDownload('Back up '+k.host,'kharej/'+enc(k.host)+'/backup','It holds every tunnel key of that server.')),
        btn('Update status','sec ic push',async()=>{const r=await api('kharej/'+enc(k.host)+'/status');const pre=el('pre','log',r.ok?JSON.stringify(r.j,null,2):(r.j.error||'Failed'));info('Update status of '+k.host,pre)}),
        btn('Audit','sec ic',async()=>{const r=await api('kharej/'+enc(k.host)+'/audit');const pre=el('pre','log',r.ok?(r.j.logs||[]).join('\n')||JSON.stringify(r.j,null,2):(r.j.error||'Failed'));info('Audit of '+k.host,pre)}),
        btn('Rotate pairing','sec ic',()=>act('kharej/'+enc(k.host)+'/pair-rotate',{full:true,title:'New pairing credential for '+k.host,confirm:'Kharej makes a new pairing credential; '+k.via.join(', ')+' switch to it and restart. The old one keeps working for 5 minutes.'}).then(r=>r&&toast('Pairing rotated'))));
      if(k.link)t.appendChild(removeBtn(k));c.appendChild(t)}
    else if(k.link){const t=el('div','k-acts');t.appendChild(removeBtn(k));c.appendChild(t)}
    g.appendChild(c);
  });
  v.appendChild(g);liveKharej();
}
function removeBtn(k){return btn('Remove','sec sm danger',()=>act('kharej/'+enc(k.host)+'/remove',{full:true,danger:true,title:'Remove Kharej '+k.host,confirm:'Deletes the pairing link to '+k.host+'. Your tunnels to it keep running; they are no longer managed from here. Add it again with its pairing token.'}).then(r=>{if(r)setTimeout(()=>P.loadOverview(),1500)}))}
// Iran: pair with one more Kharej from its pairing token (wattun add-kharej as a job; the carrier board shows the test)
P.addKharej=()=>addKharej();
function addKharej(){return act('kharej-add',{full:true,title:'Add Kharej',ok:'Add',fields:[{k:'token',label:'Pairing token from Kharej (wat1:...)',area:true,rows:3,hint:'On the Kharej server: '+(S.cli||'wattun')+', then t. Or its panel: Kharej servers.'},
  {k:'test',label:'Carrier test',options:[['fast','fast (a few minutes)'],['normal','normal'],['anti','anti-censor grid']]}]})}
// Kharej: its pairing token and who is paired; made on first use, rotate makes a new one
async function pairingCard(v){
  const c=el('section','card pairc');v.appendChild(c);
  c.append(el('div','eh-t','This is a Kharej server.'),el('p','note','The Iran server adds it with the pairing token below (Kharej servers, Add Kharej). Tunnels are then made from Iran, on both servers at once.'));
  const st=el('div','k-via');c.appendChild(st);const acts=el('div','k-acts');c.appendChild(acts);
  const r=await api('pairing').catch(()=>null);if(!r||!r.ok){st.appendChild(el('span','lab bad','The pairing state could not be read.'));return}
  st.append(el('span','lab','pairing'),el('span',null,r.j.state));
  if(!r.j.made){acts.appendChild(btn('Make the pairing token','pri',()=>act('pairing',{body:{action:'make'},title:'Make the pairing token',confirm:'Opens the hidden pairing link on this server (a minute at most). The token is shown here afterwards.'})));return}
  acts.append(btn('Show the pairing token','pri',async()=>{const x=await act('pairing',{body:{action:'show'},full:true,title:'Show the pairing token'});if(!x)return;
      const b=el('div');b.appendChild(el('p','note','It holds the link key. Paste it only into your own Iran server.'));b.appendChild(tokenBox(x.token));info('Pairing token',b)}),
    btn('Rotate the token','sec danger',()=>act('pairing',{body:{action:'rotate'},full:true,danger:true,title:'New pairing token',confirm:'The old token stops working. The Iran server paired now loses its link and has to add this Kharej again with the new token.'})));
}
function liveKharej(){document.querySelectorAll('.ksrv').forEach(c=>{const k=S.ov.kharej.find(x=>x.host===c.dataset.host);if(!k)return;let d=0,rtt=0,n=0;k.via.forEach(v=>{const l=S.live[v];if(l&&l.metrics&&l.alive){d+=l.down;rtt+=l.rtt;n++}});
  const st=c.querySelector('[data-k=kst]');if(st)st.textContent=k.online?P.fmtRate(d)+' MB/s'+(n?' · '+(rtt/n).toFixed(0)+' ms':''):'no channel'})}
async function keyRotate(k,rt){const r=await act('kharej/'+enc(k.host)+'/keyrotate',{full:true,body:{name:rt.name},title:'New key for '+rt.name,danger:true,confirm:'Kharej makes a new key and restarts '+rt.name+'. Its twin here switches by itself; any other Iran server needs the new token.'});
  if(r){toast(r.local?r.local+' here uses the new key':'Kharej has the new key: paste the token where it is used',!r.ok);if(r.warning)toast(r.warning,true);if(r.token&&!r.local)info('New token for '+rt.name,tokenBox(r.token))}}
async function kharejDelete(k,rt){const r=await act('kharej/'+enc(k.host)+'/delete',{full:true,danger:true,title:'Delete '+rt.name+' on '+k.host,confirm:'Deletes the tunnel, its key and config on Kharej. Iran tunnels that use it stop working.',fields:[{k:'confirm',label:'Type '+rt.name+' to confirm'}],body:{name:rt.name},ok:'Delete'});if(r){toast(rt.name+' deleted on '+k.host);P.loadOverview()}}
const newer=P.newer;
// every server behind the newest release: Kharej first, then this one (the backend's update-all job)
P.updateAll=()=>act('update-all',{full:true,title:'Update every server',ok:'Update all',confirm:'Each Kharej server that runs an older version updates itself (its tunnels restart, it rolls back by itself if the new version fails), then this server updates and this page reconnects.'});
$('#sbUpdB').onclick=()=>P.updateAll();

/* ================= TRAFFIC ================= */
function dayClock(hours){
  const hc=card('dclock','Time of day','last 24 h over the day before');
  const now=Math.floor(Date.now()/3600000)*3600,byT={};hours.forEach(h=>byT[h.t]=h.d+h.u);
  const cur=[],prev=[];for(let i=0;i<24;i++){const t=now-i*3600;const hr=new Date(t*1000).getHours();cur[hr]=byT[t]||0;prev[hr]=byT[t-86400]||0}
  const max=Math.max(1,...cur,...prev),C=130,R0=48,RL=74,nowH=new Date(now*1000).getHours();
  const svg=svgEl('svg',{viewBox:'0 0 260 260',role:'img','aria-label':'Traffic per hour of the day'});
  svg.appendChild(svgEl('circle',{cx:C,cy:C,r:R0-8,class:'dc-in'}));
  for(let hr=0;hr<24;hr++){const a=hr/24*2*Math.PI-Math.PI/2,cs=Math.cos(a),sn=Math.sin(a);
    const sp=(v,cls,w)=>{if(!v)return document.createComment('');const r=R0+Math.max(3,v/max*RL);const l=svgEl('line',{x1:C+cs*R0,y1:C+sn*R0,x2:C+cs*r,y2:C+sn*r,class:cls,'stroke-width':w});l.style.setProperty('--i',hr);return l};
    const gr=svgEl('g',{class:'dc-h'+(hr===nowH?' now':'')});gr.append(sp(prev[hr],'dc-p',7),sp(cur[hr],'dc-c',3.4));
    const tt=svgEl('title',{});tt.textContent=String(hr).padStart(2,'0')+':00 · last 24 h '+P.fmtBytes(cur[hr])+' · the day before '+P.fmtBytes(prev[hr]);gr.appendChild(tt);svg.appendChild(gr)}
  [0,6,12,18].forEach(hr=>{const a=hr/24*2*Math.PI-Math.PI/2,r=R0+RL+14;const t=svgEl('text',{x:C+Math.cos(a)*r,y:C+Math.sin(a)*r+3.5,'text-anchor':'middle',class:'dc-t'});t.textContent=String(hr).padStart(2,'0');svg.appendChild(t)});
  const tot=cur.reduce((a,x)=>a+x,0),tp=svgEl('text',{x:C,y:C+2,'text-anchor':'middle',class:'dc-v'});tp.textContent=P.fmtBytes(tot);svg.appendChild(tp);
  const tl=svgEl('text',{x:C,y:C+17,'text-anchor':'middle',class:'dc-t'});tl.textContent='last 24 h';svg.appendChild(tl);
  const w=el('div','dc-w');w.appendChild(svg);hc.appendChild(w);
  const busy=cur.indexOf(Math.max(...cur)),quiet=cur.indexOf(Math.min(...cur)),hh=h=>String(h).padStart(2,'0')+':00';
  const f=el('div','dc-f');
  if(tot){[['busiest',hh(busy),P.fmtBytes(cur[busy])],['quietest',hh(quiet),P.fmtBytes(cur[quiet])],['vs the day before',(()=>{const p=prev.reduce((a,x)=>a+x,0);return p?((tot>=p?'+':'−')+Math.abs((tot-p)*100/p).toFixed(0)+'%'):'–'})(),'']].forEach(([l,v,sub])=>{const d=el('div');d.append(el('div','lab',l),el('div','n dc-n',v));if(sub)d.appendChild(el('div','lab',sub));f.appendChild(d)})}
  else f.appendChild(el('div','empty','Nothing moved in the last 24 hours.'));
  hc.appendChild(f);return hc}
async function loadTraffic(){
  const v=$('#vTraffic');if(!v.childElementCount)loading(v,'rail');
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
  // a day as a clock: one spoke per hour of the day, the last 24 hours bright over the 24 before them, so the busy
  // and quiet times of day read at a glance
  g.appendChild(dayClock(hours));
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
  const tl=el('div','tools');tl.append(P.dd(sel),btn('Run a test','pri',()=>sel.value&&act('tunnels/'+enc(sel.value)+'/speedtest',{body:{mb:10}}).then(()=>{})));
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
  const v=$('#vSystem');if(!v.childElementCount)loading(v,'radar');
  const [b,al,jb,au,ov]=await Promise.all([api('backups'),api('alerts'),api('jobs'),api('audit'),api('overview')]);if(S.view!=='system')return;
  if(ov.ok)S.ov=ov.j;const h=S.ov.host;const latest=S.ov.latest;v.textContent='';const g=el('div','grid sysg');
  // vitals
  const vc=card('s2','This server',h.uptime_s?'up '+P.fmtDur(h.uptime_s):'');const arcs=el('div','arcs');
  arcs.append(arc('load · '+h.cpus+' cores',h.cpus?Math.min(100,h.load1/h.cpus*100):0,h.load1.toFixed(2),85),arc('memory',h.mem_pct,h.mem_pct.toFixed(0)+'%',90),arc('disk',h.disk_pct,h.disk_pct.toFixed(0)+'%',90));
  vc.appendChild(arcs);const kv=el('div','kvrow');[['clock',h.clock_synced?'synced':'not synced'],['address',h.ip||'–'],['two-factor',S.ov.twofa?'on':'off']].forEach(([k,x])=>{const d=el('div');d.append(el('span','lab',k),el('span','n'+((x==='not synced'||x==='off')?' warnc':''),x));kv.appendChild(d)});vc.appendChild(kv);g.appendChild(vc);
  // versions
  const vr=card('s2','Versions',latest?'latest release '+latest:'release check pending');const vl=el('div','vlist');
  const vrow=(name,ver,on)=>{const r=el('div','vrow');const behind=latest&&ver&&newer(latest,ver);r.append(el('i','kdot '+(on?(behind?'warn':'ok'):'off')),el('span','vn',name),el('span','n',ver?'v'+ver:'–'),el('span','lab',!on?'unreachable':behind?'update available':'up to date'));vl.appendChild(r)};
  vrow('this server',h.version,true);S.ov.kharej.forEach(k=>vrow(k.host,k.version,k.online));vr.appendChild(vl);vr.classList.add('vcard');
  const behind=latest?[h.version,...S.ov.kharej.filter(k=>k.online).map(k=>k.version)].filter(x=>x&&newer(latest,x)).length:0;
  const vt=el('div','tools vfoot');
  vt.append(btn(behind?'Update all ('+behind+')':'Update all',behind?'fx-aurora':'pri',()=>P.updateAll()),
    btn('Update this server','sec',()=>act('update',{full:true,title:'Update this server',confirm:'Downloads the latest release, checks its signature, swaps the binary and restarts the tunnels and this panel. Open connections drop for a few seconds.'})),
    btn('Roll back','sec ic danger push',()=>act('rollback',{full:true,title:'Roll back',confirm:'Goes back to the previous version and restarts the tunnels and this panel.',danger:true})));
  vr.append(el('p','note',behind?'Update all does the Kharej servers first, then this one; the page reconnects by itself.':'Every server runs the newest release.'),vt);g.appendChild(vr);
  // the manager's server tools (4.0.3)
  const st=card('s2','Speed and access','kernel tuning, auto tunnels, who may connect');const stool=(op,label,cls,confirm)=>btn(label,cls,()=>act('server-tool',{body:{op},title:label,confirm,ok:'Start'}));
  const sw=el('div','tools');sw.append(stool('boost','Kernel speed boost','pri','Turns on BBR, 64 MB socket buffers and FQ on this server. Safe to run again; Undo puts the old values back.'),stool('boost-undo','Undo boost','sec','Puts the kernel settings back as they were before the boost.'),
    stool('optimize','Re-test auto tunnels','sec','Tests every auto tunnel again now, as the night run does, and switches where a carrier is clearly better.'),
    stool('fw-on','Iran-only clients','sec','Only Iranian addresses may connect to the client ports of this server. Others are dropped by the firewall.'),stool('fw-off','Allow every address','sec','Removes the Iran-only rule from the client ports.'));
  st.appendChild(sw);g.appendChild(st);
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
  if(k==='acme'){const ip=S.ov&&S.ov.host.ip||'';const v=await ask('Certificate from Let’s Encrypt',{full:true,text:'For '+(ip||'this server’s IP')+', unless you give a domain that points here. IP certificates last 6 days and renew by themselves. Port 80 opens for a few seconds during the check. If it fails, the current certificate stays.',fields:[{k:'domain',label:'Domain (optional)',ph:ip,hint:'Empty: this server’s IP'}],ok:'Get it'});if(!v)return;
    await act('settings/cert/acme',{body:v})}
}

/* ---------- Overview: speed test card ---------- */
// The matrix fills the card: one column per real run of the shown tunnel (download, scaled to their best), as many
// columns and rows as fit; Run test keeps it waving while the job measures.
let stRun=null,stDown=[];
function mxFit(box){return [Math.max(7,Math.floor((box.clientWidth+5)/14)),Math.max(4,Math.floor((box.clientHeight+5)/14))]}
function mxDraw(){const box=$('#mx');if(!box||stRun)return;const [n,rows]=mxFit(box);matrix(box,fillCols(stDown.slice(0,n).reverse(),n,rows),rows,false)}
let mxT=0;window.addEventListener('resize',()=>{clearTimeout(mxT);mxT=setTimeout(mxDraw,150)});
async function loadSpeedCard(){
  const box=$('#mx');if(!box||!S.ov)return;
  const iran=S.ov.tunnels.filter(t=>t.role==='Iran');const btn=$('#stBtn');
  $('#stCard').hidden=!iran.length;if(!iran.length)return;
  const r=await api('speedtests').catch(()=>null);const rows=r&&r.ok?r.j.rows:[];
  const name=(rows.find(x=>iran.some(t=>t.name===x.name))||{}).name||(iran.find(t=>t.active)||iran[0]).name;
  $('#stName').textContent=name;btn.dataset.name=name;
  if(stRun)return;
  const mine=rows.filter(x=>x.name===name&&x.down>0);const last=mine[0];
  stDown=mine.map(x=>x.down);mxDraw();
  const v=$('#stVal');v.textContent='';
  if(last){v.appendChild(split(last.down.toFixed(1),'MB/s'));$('#stLab').textContent='last run · '+P.fmtDur(Math.max(1,Math.round(Date.now()/1000-last.t)))+' ago';$('#stSub').textContent='↑ '+last.up.toFixed(1)+' MB/s · '+last.mb+' MB'+(last.auto?' · scheduled':'')}
  else{v.textContent='–';$('#stLab').textContent='no test yet';$('#stSub').textContent=''}
  btn.disabled=false;btn.textContent=last?'Run again':'Run test';
}
$('#stBtn').addEventListener('click',async()=>{
  const b=$('#stBtn');const name=b.dataset.name;if(!name||stRun)return;
  let r;try{r=await api('tunnels/'+enc(name)+'/speedtest',{method:'POST',body:{mb:10}})}catch(e){return}
  if(!r.ok||!r.j.job){toast(r.j.error||'Could not start the test.',true);return}
  stRun=r.j.job;b.disabled=true;b.textContent='Testing…';{const [n,rows]=mxFit($('#mx'));matrix($('#mx'),new Array(n).fill(null),rows,true)}$('#stVal').textContent='··';$('#stSub').textContent='';
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
function loading(v,kind){v.textContent='';const c=el('section','card loadc');c.append(P.dm(kind||'rail',5,6),el('div','lab','loading'));v.appendChild(c)}

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
