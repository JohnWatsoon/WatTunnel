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
// Outside the detailed Europe / Middle East box: coarse continent outlines, enough for a world-wide dot map.
const WORLD=[
 [[-168,66],[-162,70],[-156,71.3],[-141,69.6],[-128,70],[-115,68.5],[-95,68],[-85,69.5],[-80,63],[-94,59],[-92,57],[-82,55],[-79,52],[-77,60],[-70,59],[-64,60],[-61,56],[-55,52],[-60,47],[-66,45],[-70,43],[-70,41.5],[-74,40.5],[-76,38],[-75.5,35.5],[-81,31.5],[-80,27],[-80.4,25.2],[-82,26.5],[-83,29.5],[-85,30],[-89,30.2],[-91,29.5],[-94,29.5],[-97.3,27.5],[-97.5,25],[-97.7,22],[-96,19],[-94.5,18.2],[-91,18.8],[-90.5,21],[-87,21.5],[-88,17],[-88.5,15.8],[-84,15.9],[-83.5,11],[-81.5,9],[-79.5,9.5],[-77.5,8.5],[-78,7],[-80,7.5],[-81.5,8],[-83.5,8.4],[-85.7,11],[-87.5,13],[-91,13.9],[-94.5,16],[-96.5,15.7],[-100,17],[-105.5,20.5],[-105.5,23],[-109.5,25.5],[-112.5,29],[-114.5,31],[-113,29],[-110,23],[-112,24.5],[-114,27.5],[-115,30],[-117,32.5],[-120.5,34.5],[-122.5,37.5],[-124.3,40.5],[-124,46],[-124.7,48.4],[-123,49],[-127,50.5],[-130,54.5],[-133,57],[-137,58.5],[-142,60],[-146,61],[-150,59.5],[-154,57.5],[-158,56],[-163,54.7],[-158,58.5],[-162,60],[-165,62.5],[-164,64.5],[-168,65.5]],
 [[-77.5,8.5],[-72,12],[-68,10.6],[-62,10.7],[-60,8.5],[-57,6],[-52,5],[-50,1.5],[-48,-1],[-44,-2.5],[-39,-3.5],[-35,-5.5],[-35,-9],[-39,-13.5],[-39.5,-18],[-41,-22],[-44.5,-23.2],[-48.5,-26],[-48.7,-28.5],[-52,-32],[-54,-34.8],[-57.5,-35],[-57.5,-38],[-62,-39],[-62.5,-41],[-65,-42],[-63.5,-42.8],[-65,-45],[-67.5,-46.5],[-66,-48],[-69,-50.5],[-68.5,-52.5],[-71,-54],[-74.5,-52],[-75.5,-48],[-74,-44],[-73.5,-40],[-73.5,-37],[-71.5,-32],[-71.4,-28],[-70.4,-23],[-70.2,-18.4],[-75,-15.5],[-77,-12],[-79.5,-7.5],[-81.2,-5],[-80,-2],[-80.5,0.5],[-78.8,1.5],[-77.5,4],[-77.4,7]],
 [[-17,21],[-16.5,14.7],[-17.5,14.7],[-15,11],[-13,8],[-10.5,6.3],[-7.5,4.4],[-3,5],[1.5,6.2],[4.5,6.3],[6,4.3],[8.5,4.5],[9.5,3.5],[9.5,-1],[11.8,-4.5],[13.2,-9],[11.8,-16.5],[14.5,-22.5],[15.3,-27],[18.4,-34.2],[20,-34.8],[25.5,-34],[28,-33],[31,-29.5],[32.8,-26],[35.5,-24],[35.4,-21.5],[34.8,-19.8],[39.2,-16],[40.5,-10.5],[39.3,-7],[39.2,-4.7],[41.5,-1.5],[43.5,1.5],[47,4.5],[49.5,8],[51.2,11.8],[48,11.2],[44.5,10.4],[43.3,11.6],[42.7,13],[41,15],[39,15],[32,15],[0,15],[-17,15]],
 [[49.3,-12],[50.4,-15.5],[47.2,-24.9],[45.2,-25.5],[43.7,-21.5],[44.2,-16.3],[46.5,-15.5],[48.7,-13.3]],
 [[75,66],[75,72],[80,73],[88,75.5],[100,77.5],[105,77.5],[113,73.5],[128,72.5],[140,72.5],[150,71.5],[160,70],[170,70],[180,69],[180,65],[178,64.5],[174,61.5],[164,60],[163,57],[156.5,51],[156,57.5],[160,61.5],[154,59.3],[142,59.3],[137,54],[141,52],[140.5,48.5],[135,43.5],[132,43],[129.5,41],[129.5,37],[129,35],[126.5,34.5],[126.5,37.5],[125,39.5],[121.5,40],[122,40.5],[119,39.2],[118,38],[121,37],[119.5,35],[121,32.5],[122,30],[120,26],[116.5,22.8],[113.5,22.2],[110,21],[109.7,18.5],[108,21.5],[106,20],[106.5,17],[109,13],[109,11.5],[105,8.6],[103,10.5],[100.5,13.5],[100,12],[99.5,9],[100.5,7],[102,6.2],[103.5,4],[103.5,1.4],[101,2.5],[98,8],[98.5,10.5],[97.7,16],[95,15.8],[94,18],[92,21.5],[90,22],[88.5,21.7],[86.5,20],[85,19],[82.3,16.6],[80.2,13.5],[80,9.5],[77.5,8],[76.5,9],[75,12]],
 [[12,66],[15,68],[18,69.8],[23,70.8],[28,71],[31,70],[40,68],[44,68.5],[53,68.5],[60,69.8],[68,69],[69,72.5],[73,72.5],[75,72],[75,66]],
 [[79.8,9.8],[81.8,7.5],[81.2,6],[80,6],[79.7,8]],
 [[130,31],[131.5,31.5],[132,33.5],[135,33.5],[137,34.5],[139.8,35],[141,37],[142,39.5],[141.5,41.4],[140,41.5],[140,40],[139.5,38],[137,37],[136,36],[133,35.5],[131,34.3],[129.7,33.2]],
 [[140,41.5],[141.2,41.8],[143.5,42],[145.5,43.3],[144.5,44],[141.8,45.5],[141.5,43.3],[140,42.6]],
 [[120,18.5],[122.3,18.5],[122,16],[124,13],[126,9],[125.5,6],[122,7],[123,10],[120,15]],
 [[109,1.5],[109.7,-1],[110.5,-3],[114.5,-4],[116.5,-3.5],[118,1],[119,5],[117,7],[115.5,5],[113,3.2],[111,1.8]],
 [[95.3,5.6],[97.5,5.2],[100.5,2],[104,-1],[106,-3],[105.7,-5.8],[104.5,-5.8],[102,-4],[100.5,-1],[98.5,2]],
 [[105.2,-6.8],[106,-5.9],[108.5,-6.3],[111,-6.4],[114.5,-7.7],[114.4,-8.7],[110.7,-8.2],[106.5,-7.4]],
 [[131,-1.5],[134,-0.8],[138,-1.5],[141,-2.6],[145.7,-5.3],[147.5,-6.2],[150.5,-10.5],[147,-10],[144,-7.8],[141,-9],[138,-8],[137.7,-5],[135,-4.4],[132,-2.8]],
 [[113.5,-22],[114,-26.5],[115,-30],[115,-33.5],[117.8,-35.1],[123.5,-33.9],[126,-32.3],[131,-31.5],[134.2,-32.6],[135.9,-34.9],[137.7,-32.6],[137.5,-35.2],[140,-37.7],[143.5,-38.8],[146.3,-39.1],[150,-37.5],[151.2,-33.9],[153.2,-30],[153,-25],[150.8,-22.5],[146.3,-18.9],[145.3,-14.9],[143.5,-14],[142.5,-10.7],[141.5,-13.5],[141.6,-17],[140,-17.7],[135.8,-14.8],[136.8,-12.1],[132.6,-11.5],[131,-12.2],[129.5,-15],[126.5,-14],[122.2,-17.4],[121,-19.6],[117,-20.6]],
 [[144.6,-40.7],[148.3,-40.9],[148,-43.2],[146,-43.6]],
 [[172.7,-34.4],[174.4,-36.4],[175.9,-37.4],[178.5,-37.7],[176.9,-39.6],[174.9,-41.4],[173,-40.5],[172.7,-43.4],[171,-44.5],[169,-46.6],[166.5,-46],[168,-44],[170.8,-42.5],[172.2,-40.6],[173.9,-39.2],[174.6,-36.9]],
 [[-73,78.3],[-66,81],[-50,82.5],[-30,83.5],[-20,82],[-18,77],[-20,72],[-22,70],[-30,68.2],[-40,65],[-43,60],[-48,61],[-52,65],[-54,68.5],[-56,72.5],[-62,76],[-70,77]],
 [[-24,65.5],[-22,66.4],[-16,66.5],[-13.5,65.2],[-14.5,64.4],[-18,63.4],[-22.6,63.8]],
 [[-62,66.5],[-65,63],[-72,62.5],[-78,64.5],[-73,68],[-80,70],[-90,73.5],[-80,73.8],[-70,71],[-64,68]],
 [[-125,72],[-115,73.5],[-105,73],[-96,72],[-90,76],[-80,77],[-70,79],[-62,82],[-80,83],[-95,81.5],[-100,78],[-110,77.8],[-120,76],[-125,74.5]],
 [[-85,21.8],[-82,23.2],[-77,22.2],[-74.2,20.2],[-77.5,19.8],[-81,21.5]],
 [[-74.4,18.4],[-72.8,19.9],[-69,19.7],[-68.4,18.6],[-71,18.1]]
];
function isLand(lon,lat){
  if(lon>=-12&&lon<=75&&lat>=12&&lat<=66) return !WATER.some(p=>inPoly(lon,lat,p))||LANDX.some(p=>inPoly(lon,lat,p));
  if(lat<-63) return true;
  return WORLD.some(p=>inPoly(lon,lat,p));
}
function hash(a,b){const s=Math.sin(a*127.1+b*311.7)*43758.5453;return s-Math.floor(s)}

/* ---------- places ---------- */
// Positions come from the server's IP-location cache (overview.geo, keyed by address). An address it could not
// place yet falls back: this server to Tehran (Iran side) or Europe (Kharej side), a Kharej server to a European
// anchor in pairing order.
const IRAN_LL=[51.4,35.7];
const ANCHORS=[[8.7,50.1],[24.9,60.2],[4.9,52.4],[2.35,48.9],[13.4,52.5],[-0.1,51.5],[16.4,48.2],[18.1,59.3]];
const C_OK='62,224,138',C_BAD='255,93,98',C_IR='154,140,255';
function regionOf(lon,lat){return inPoly(lon,lat,IRAN)?1:0}
function places(){
  const ov=S.ov;const geo=ov.geo||{};const g=geo[ov.host.ip];
  // not placed yet: an Iran server falls back to Tehran, a Kharej server to the first European anchor
  const kx=ov.host.role==='kharej';
  const me={ll:g?[g.lon,g.lat]:kx?ANCHORS[0]:IRAN_LL,city:g?(g.city||g.cc):'',cc:g?g.cc:(kx?'':'IR?'),known:!!g};
  const kh=ov.kharej.map((k,i)=>{const q=geo[k.host];return {k,ll:q?[q.lon,q.lat]:ANCHORS[i%ANCHORS.length],city:q?(q.city||q.cc):'',cc:q?q.cc:'',known:!!q}});
  return {me,kh};
}
// split-flap board of a Kharej server: its city when the location cache knows it, else its address
// (the dots of an address are narrow gaps, not tiles)
function flaps(k,cls,max,step){const q=(S.ov.geo||{})[k.host];const city=q&&q.city?q.city.toUpperCase():'';const w=city||k.host;
  const fl=el('div','flaps '+(cls||'')+(w.length>11?' long':''));fl.setAttribute('aria-label',city?city+', '+k.host:k.host);
  w.split('').slice(0,max).forEach((ch,j)=>{const s=el('span','flap'+(ch==='.'?' sep':ch===' '?' sp':''),ch==='.'||ch===' '?'':ch);s.setAttribute('aria-hidden','true');s.style.animationDelay=(0.2+j*step).toFixed(2)+'s';fl.appendChild(s)});
  fl.dataset.city=city;return fl}
/* ---------- small helpers ---------- */
const $=(s)=>document.querySelector(s);
const RM=matchMedia('(prefers-reduced-motion: reduce)').matches;
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
/* ---------- icons: one line set (lucide geometry, 24 grid, 1.5 stroke), picked from the button's label ---------- */
const ICO={play:['M7 4.5v15l12-7.5z'],stop:['M7 7h10v10H7z'],restart:['M20 12a8 8 0 1 1-2.34-5.66','M20 4v5h-5'],
  rotate:['M4 12a8 8 0 1 0 2.34-5.66','M4 4v5h5'],key:['M2.5 15.5a5 5 0 1 0 10 0a5 5 0 1 0-10 0','m11 12 9.5-9.5','m16.5 6.5 3 3','m19 4 2 2'],
  trash:['M4 7h16','M9 7V4.5h6V7','M6.5 7l1 13h9l1-13','M10 11v5.5','M14 11v5.5'],plus:['M12 5v14','M5 12h14'],
  down:['M12 4v11','m7 10.5 5 5 5-5','M5 20h14'],up:['M12 20V9','m7 13.5 5-5 5 5','M5 4h14'],box:['M3.5 4.5h17v4h-17z','M5 8.5v11h14v-11','M10 12.5h4'],
  pulse:['M3 12h4l3-7 4 14 3-7h4'],list:['M9 6h11','M9 12h11','M9 18h11','M4.5 6h.01','M4.5 12h.01','M4.5 18h.01'],
  gauge:['M12 14.5l4.5-4.5','M3.8 18.5a9.5 9.5 0 1 1 16.4 0'],copy:['M9 9h11v11H9z','M5 15H4V4h11v1'],
  eye:['M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z','M9.5 12a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0'],
  x:['M18 6 6 18','M6 6l12 12'],check:['M20 6.5 9 17.5l-5-5'],arrow:['M5 12h14','m13 6 6 6-6 6'],
  unlink:['M9 17H7a5 5 0 0 1 0-10h2','M15 7h2a5 5 0 0 1 3.9 8.1','M8 12h3','M3 3l18 18'],
  power:['M12 3v9','M17.7 6.3a8 8 0 1 1-11.4 0'],pen:['M16.5 4.5a2.1 2.1 0 1 1 3 3L8 19l-4 1 1-4z'],
  share:['M5 12v7.5h14V12','M12 3v12','m8 7 4-4 4 4'],link:['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1','M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'],
  shield:['M12 21s7.5-3.5 7.5-9.5V5.5L12 3 4.5 5.5v6C4.5 17.5 12 21 12 21z'],
  grid:['M5 4h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z','M15 4h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z','M5 14h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1z','M15 14h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1z'],
  route:['M3 19a3 3 0 1 0 6 0a3 3 0 1 0-6 0','M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15','M15 5a3 3 0 1 0 6 0a3 3 0 1 0-6 0'],
  globe:['M2.5 12a9.5 9.5 0 1 0 19 0a9.5 9.5 0 1 0-19 0','M2.5 12h19','M12 2.5a14.5 14.5 0 0 1 0 19a14.5 14.5 0 0 1 0-19z'],
  bars:['M3.5 3.5v15a2 2 0 0 0 2 2h15','M18 16.5V9','M13 16.5V5.5','M8 16.5v-3'],
  server:['M5 3.5h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2z','M5 13.5h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2z','M7 7h.01','M7 17h.01'],
  sliders:['M20 7h-9','M14 17H4','M14 17a3 3 0 1 0 6 0a3 3 0 1 0-6 0','M4 7a3 3 0 1 0 6 0a3 3 0 1 0-6 0'],
  github:['M15 21.5v-3.8a4.4 4.4 0 0 0-1-3.2c3 0 6-2 6-5.5a5.4 5.4 0 0 0-1-3.5 4.6 4.6 0 0 0 0-3.5s-1 0-3 1.5a10.3 10.3 0 0 0-8 0C6 2 5 2 5 2a4.6 4.6 0 0 0 0 3.5A5.4 5.4 0 0 0 4 9c0 3.5 3 5.5 6 5.5a4.4 4.4 0 0 0-1 3.2v3.8','M9 18c-4.5 2-5-2-7-2'],
  chev:['m6 9 6 6 6-6'],
  logout:['M9 20.5H5.5a2 2 0 0 1-2-2v-13a2 2 0 0 1 2-2H9','m16 16.5 4.5-4.5L16 7.5','M20.5 12H9'],refresh:['M20 12a8 8 0 0 1-14.3 4.9','M4 12a8 8 0 0 1 14.3-4.9','M18 3v4.5h-4.5','M6 21v-4.5h4.5']};
function ico(n){const ns='http://www.w3.org/2000/svg',s=document.createElementNS(ns,'svg');s.setAttribute('viewBox','0 0 24 24');s.setAttribute('class','ico i-'+n);s.setAttribute('aria-hidden','true');
  ICO[n].forEach(d=>{const p=document.createElementNS(ns,'path');p.setAttribute('d',d);s.appendChild(p)});return s}
// first match wins: the specific labels before the generic verbs
const ICO_BY=[[/^find best|^iran-only|^allow every/i,'shield'],[/^tune|^kernel|^undo boost/i,'sliders'],[/^reset traffic/i,'refresh'],[/^re-test auto/i,'refresh'],[/^diagnose/i,'pulse'],[/^move ports/i,'route'],[/^re-?test/i,'refresh'],[/^roll ?back/i,'restart'],[/^back ?up/i,'box'],[/^limit/i,'gauge'],[/^ports/i,'pen'],[/^csv$/i,'down'],[/^random/i,'refresh'],[/^reset quota/i,'refresh'],[/^forget/i,'unlink'],[/^run a test/i,'gauge'],[/^(run test|run again|speed|test)/i,'gauge'],[/^(start|resume|turn on)/i,'play'],[/^restart/i,'restart'],[/^(stop|turn off|pause)/i,'stop'],
  [/key/i,'key'],[/^(rotate|new pairing)/i,'rotate'],[/^remove kharej|^remove$|^forget|^unpair/i,'unlink'],[/^(delete|remove|clear)/i,'trash'],
  [/^(new|add|set up)/i,'plus'],[/^update status/i,'pulse'],[/^(update|install|download)/i,'down'],[/^(backup|export)/i,'box'],
  [/^(restore|upload|import)/i,'up'],[/^(audit|log|journal|history)/i,'list'],[/^copy/i,'copy'],[/^(show|hide|reveal)/i,'eye'],
  [/^(close|cancel|dismiss)/i,'x'],[/^(sign out)/i,'power'],[/token|qr/i,'share'],[/^(edit|change|rename|move)/i,'pen'],
  [/^(bond|use|pick)/i,'link'],[/^(refresh|reload|retry|re-?measure)/i,'refresh'],[/cert|2fa|two-factor/i,'shield'],
  [/^(save|apply|done|confirm|verify|ok|yes)/i,'check'],[/^(open|go|continue|next|details|why)/i,'arrow']];
function decorate(b){if(b.querySelector(':scope>svg.ico'))return;const t=b.textContent.trim();if(!t)return;
  const m=ICO_BY.find(([re])=>re.test(t));if(!m)return;b.prepend(ico(m[1]));
  if(b.classList.contains('ic')){b.setAttribute('aria-label',t);b.title=t}}
// every .btn, now and later (labels change after a run, rows re-render): decorate on any change
new MutationObserver(ms=>{for(const m of ms){const t=m.target;if(t.nodeType===1&&t.classList.contains('btn'))decorate(t);
  m.addedNodes.forEach(n=>{if(n.nodeType!==1)return;if(n.classList.contains('btn'))decorate(n);n.querySelectorAll&&n.querySelectorAll('.btn').forEach(decorate)})}})
  .observe(document.documentElement,{childList:true,subtree:true});
// press: the socket pops; a click handler that returns a promise keeps the ring turning until it settles
document.addEventListener('pointerdown',e=>{const b=e.target.closest&&e.target.closest('.btn');if(!b||b.disabled)return;b.classList.remove('hit');void b.offsetWidth;b.classList.add('hit')});
document.addEventListener('animationend',e=>{if(e.animationName==='pop'){const b=e.target.closest('.btn');if(b)b.classList.remove('hit')}});
/* dot-matrix loaders: one N×N grid of dots, each dot carries its column, row, distance from the centre, angle and
   spiral order as CSS variables; the kind picks which one drives the delay (app.css .dm-*). Different waits get
   different shapes: a button strobes, a page scans, a job climbs, a boot spirals. */
const DM_KINDS=['strobe','drift','ladder','spiral','ring','orbit','drop','bars','rail','halo','radar','checker'];
function dm(kind,n=3,size){const w=el('span','dm dm-'+kind);w.setAttribute('aria-hidden','true');w.style.setProperty('--n',n);if(size)w.style.setProperty('--s',size+'px');
  const c=(n-1)/2,maxd=Math.hypot(c,c)||1,ord=spiralOrder(n);
  for(let y=0;y<n;y++)for(let x=0;x<n;x++){const i=el('i');const st=i.style;
    st.setProperty('--x',(x/(n-1||1)).toFixed(3));st.setProperty('--y',(y/(n-1||1)).toFixed(3));
    st.setProperty('--d',(Math.hypot(x-c,y-c)/maxd).toFixed(3));st.setProperty('--a',((Math.atan2(y-c,x-c)/(2*Math.PI)+1)%1).toFixed(3));
    st.setProperty('--o',(ord[y*n+x]/(n*n)).toFixed(3));st.setProperty('--c',(x+y)%2);st.setProperty('--r',((x*7+y*13)%10/10).toFixed(1));w.appendChild(i)}
  return w}
function spiralOrder(n){const o=new Array(n*n);let x=0,y=0,dx=1,dy=0,t=0,l=0,r=n-1,b=n-1;for(let k=0;k<n*n;k++){o[y*n+x]=k;
  if(dx===1&&x===r){dx=0;dy=1;t++}else if(dy===1&&y===b){dx=-1;dy=0;r--}else if(dx===-1&&x===l){dx=0;dy=-1;b--}else if(dy===-1&&y===t){dx=1;dy=0;l++}x+=dx;y+=dy}return o}
/* dropdowns: the native select stays (it holds the value, fires change, and a form or code reads it as before)
   but is hidden; a button shows the choice and opens a popover list (top layer, so it also floats over dialogs).
   Arrows move, Enter picks, Escape or a click outside closes. Returns a wrapper to place instead of the select. */
function dd(sel){
  const w=el('div','dd'),b=el('button','dd-b'),lab=el('span','dd-l'),list=el('div','dd-p');
  b.type='button';b.setAttribute('aria-haspopup','listbox');b.setAttribute('aria-expanded','false');b.append(lab,ico('chev'));
  list.setAttribute('popover','auto');list.setAttribute('role','listbox');sel.classList.add('nsel');sel.tabIndex=-1;sel.setAttribute('aria-hidden','true');
  w.append(sel,b,list);
  const sync=()=>{lab.textContent=sel.selectedOptions[0]?sel.selectedOptions[0].textContent:''};
  const opts=()=>[...list.querySelectorAll('.dd-o')];
  const pick=o=>{sel.value=o.value;sync();sel.dispatchEvent(new Event('change'));list.hidePopover();b.focus()};
  const place=()=>{const r=b.getBoundingClientRect(),up=innerHeight-r.bottom<260&&r.top>innerHeight-r.bottom;list.classList.toggle('up',up);
    list.style.left=r.left+'px';list.style.minWidth=r.width+'px';list.style.top=up?'auto':r.bottom+6+'px';list.style.bottom=up?(innerHeight-r.top+6)+'px':'auto'};
  const open=()=>{list.textContent='';[...sel.options].forEach((o,k)=>{const it=el('button','dd-o'+(o.selected?' on':''));it.type='button';it.setAttribute('role','option');it.setAttribute('aria-selected',String(o.selected));
      it.style.setProperty('--k',k);it.append(el('span',null,o.textContent),ico('check'));it.onclick=()=>pick(o);list.appendChild(it)});
    list.showPopover();place();(list.querySelector('.on')||list.firstChild).focus({preventScroll:true})};
  b.onclick=()=>list.matches(':popover-open')?list.hidePopover():open();
  b.onkeydown=e=>{if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();open()}};
  list.onkeydown=e=>{const a=opts(),k=a.indexOf(document.activeElement);if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();a[(k+(e.key==='ArrowDown'?1:-1)+a.length)%a.length].focus()}else if(e.key==='Tab')list.hidePopover()};
  list.addEventListener('toggle',e=>{const on=e.newState==='open';b.setAttribute('aria-expanded',String(on));w.classList.toggle('open',on)});
  addEventListener('scroll',()=>{if(list.matches(':popover-open'))place()},true);
  sel.addEventListener('change',sync);
  const lb=sel.id&&document.querySelector('label[for="'+sel.id+'"]');if(lb){lb.htmlFor='';lb.onclick=()=>b.focus();b.setAttribute('aria-label',lb.textContent)}else b.setAttribute('aria-label',sel.getAttribute('aria-label')||'');
  sync();return w}
// busy: the button's icon turns into a small strobing matrix while the action runs, and the label stays
/* a running button keeps its dot matrix across re-renders: the views rebuild every poll, so the state is held by
   the button's identity (its section and label), and every new button with that identity comes up busy too */
const BUSY=new Set();
function bkey(b){const h=b.closest('[data-host],[id]');return (h?h.dataset.host||h.id:'')+'|'+b.textContent.trim()}
function busyOn(b){if(b.classList.contains('busy'))return;b.classList.add('busy');b.setAttribute('aria-busy','true');
  const m=dm(b.dataset.dm||'strobe',3);m.classList.add('bdm');b.prepend(m)}
function busyOff(b){b.classList.remove('busy');b.removeAttribute('aria-busy');const m=b.querySelector(':scope>.bdm');if(m)m.remove()}
function busy(b,r){if(!r||typeof r.then!=='function')return r;const k=bkey(b);BUSY.add(k);busyOn(b);
  const done=()=>{BUSY.delete(k);document.querySelectorAll('.btn.busy').forEach(x=>{if(bkey(x)===k)busyOff(x)})};r.then(done,done);return r}
new MutationObserver(ms=>{if(!BUSY.size)return;for(const m of ms)for(const n of m.addedNodes){if(n.nodeType!==1)continue;
  (n.matches('.btn')?[n]:n.querySelectorAll('.btn')).forEach(b=>{if(BUSY.has(bkey(b)))busyOn(b)})}}).observe(document.documentElement,{childList:true,subtree:true});
document.addEventListener('DOMContentLoaded',()=>{document.querySelectorAll('.btn').forEach(decorate);const o=document.getElementById('out');if(o)o.replaceChildren(ico('logout'))});
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
function showLogin(){document.title=preTitle;return showLogin0.apply(this,arguments)}
function showLogin0(){
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
document.querySelectorAll('.nav button').forEach(b=>{if(b.dataset.ic)b.prepend(ico(b.dataset.ic));b.addEventListener('click',()=>{location.hash=b.dataset.v;b.classList.remove('hit');void b.offsetWidth;b.classList.add('hit')})});
$('#gh').appendChild(ico('github'));
// the active row's background slides to the row; re-measured when the rail/full sidebar switch moves the rows
function placeInd(){const b=$('.nav button[aria-current]'),i=$('#navInd');if(!b||!b.offsetParent){i.classList.remove('on');return}i.style.setProperty('--y',b.offsetTop+'px');i.style.setProperty('--x',b.offsetLeft+'px');i.style.setProperty('--w',b.offsetWidth+'px');i.style.height=b.offsetHeight+'px';i.classList.add('on')}
addEventListener('resize',placeInd);
addEventListener('hashchange',()=>{if(!$('#app').hidden)setView(location.hash.slice(1))});
const VIEWS={overview:['#vOverview','Overview'],tunnels:['#vTunnels','Tunnels'],kharej:['#vKharej','Kharej servers'],settings:['#vSettings','Settings']};
function setView(v){
  if(!VIEWS[v])v='overview';S.view=v;
  const order=Object.keys(VIEWS),prev=S.prevView;S.prevView=v;
  Object.entries(VIEWS).forEach(([k,[sel]])=>{$(sel).hidden=k!==v});
  document.querySelectorAll('.nav button').forEach(b=>{if(b.dataset.v===v)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current')});
  placeInd();
  if(prev&&prev!==v){const pn=$(VIEWS[v][0]),t=$('#vTitle');[pn,t].forEach(e=>{e.classList.remove('enter','up');void e.offsetWidth;e.classList.add('enter')});if(order.indexOf(v)<order.indexOf(prev))pn.classList.add('up')}
  $('#vTitle').textContent=VIEWS[v][1];$('#hAct').hidden=v!=='overview';
  if(v==='overview'&&S.ov&&!S.mapStarted)startMap();
  if(v==='settings')loadSettings();
  if(window.PANEL&&PANEL.onView)PANEL.onView(v);
  render();
}
$('#out').addEventListener('click',async()=>{try{await api('logout',{method:'POST'})}catch(e){}showLogin()});

async function loadOverview(){
  // the first load asks both at once (one round trip on a slow link, not two)
  if(!S.me)api('me').then(m=>{if(m.ok){S.me=m.j;S.cli=m.j.cli;brand(m.j)}}).catch(()=>{});else brand(S.me);
  try{const r=await api('overview');if(r.ok){S.ov=r.j;if(S.view==='overview'&&!S.mapStarted)startMap();render()}}catch(e){}
}
// the software's name and project page arrive only after sign-in (the login page does not say what this runs)
// the tab says the product only after sign-in (the name comes from an authenticated answer; the page served before sign-in
// carries the neutral title, which showLogin puts back)
const preTitle=document.title;
function brand(m){if(!m.product)return;$('#brand').textContent=m.product;document.title=m.product;const g=$('#gh');g.href=m.repo;g.setAttribute('aria-label',m.product+' on GitHub');g.title='Project page';g.hidden=false}
function newer(a,b){const x=a.split('.').map(Number),y=b.split('.').map(Number);for(let i=0;i<Math.max(x.length,y.length);i++){if((x[i]||0)!==(y[i]||0))return (x[i]||0)>(y[i]||0)}return false}
function sideBar(ov){
  const down=ov.tunnels.filter(t=>statusOf(t)[0]==='p-down').length,off=ov.kharej.filter(k=>!k.online).length;
  const ct=$('#cTun');ct.textContent=ov.tunnels.length||'';ct.className='cnt n'+(down?' bad':'');ct.title=down?down+' down':'';
  const ck=$('#cKh');ck.textContent=ov.kharej.length||'';ck.className='cnt n'+(off?' bad':'');ck.title=off?off+' unreachable':'';
  const L=ov.latest,behind=L?[ov.host.version,...ov.kharej.filter(k=>k.online).map(k=>k.version)].filter(v=>v&&newer(L,v)).length:0;
  $('#sbUpd').hidden=!behind;
  if(behind){$('#sbUpdV').textContent=L;$('#sbUpdS').textContent=behind===1?'1 server runs an older one':behind+' servers run older ones'}
  if(!S.navPlaced){S.navPlaced=true;placeInd()}
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
// while a dialog is open the page behind it stays still: redrawing it under the dialog's 12 px backdrop blur every
// second made the dialog stutter. The view catches up when the dialog closes.
const modal=()=>{const d=$('#dlg');return d&&d.open};
function render(){
  const ov=S.ov;if(!ov)return;if(modal()){S.stale=true;return}
  syncDrawer();
  $('#hName').textContent=ov.host.name||'server';
  const side={iran:'Iran',kharej:'Kharej',mixed:'Iran and Kharej'}[ov.host.role]||(ov.tunnels.some(t=>t.role==='Iran')?'Iran':ov.tunnels.length?'Kharej':'');
  $('#hMeta').textContent=(side?side+' · ':'')+ov.host.version;
  sideBar(ov);
  // headline: what is wrong, in words
  const f=$('#find');f.textContent='';
  const down=ov.tunnels.filter(t=>statusOf(t)[0]==='p-down');
  const lossy=ov.tunnels.filter(t=>statusOf(t)[0]==='p-slow');
  const offK=ov.kharej.filter(k=>!k.online);
  const parts=[];
  const go=(e,fn)=>{e.classList.add('fgo');e.tabIndex=0;e.setAttribute('role','link');e.onclick=fn;e.onkeydown=k=>{if(k.key==='Enter')fn()};return e};
  down.forEach(t=>{const b=go(el('b',null,t.name),()=>openDrawer(t.name));parts.push([b,statusOf(t)[1]==='No link'?' has no link':' is down'])});
  lossy.forEach(t=>{const m=go(el('em',null,t.name),()=>openDrawer(t.name));parts.push([m,' is losing '+S.live[t.name].loss.toFixed(1)+'%'])});
  offK.forEach(k=>{const b=go(el('b',null,k.host),()=>setView('kharej'));parts.push([b,' cannot be reached'])});
  (ov.alerts||[]).filter(a=>a.kind!=='down'&&a.kind!=='kharej').forEach(a=>parts.push([el('em',null,a.text),'']));
  if(!ov.twofa)parts.push([go(el('em',null,'Two-factor sign-in is off'),()=>setView('settings')),'']);
  if(!parts.length)f.appendChild(el('span','ok',ov.tunnels.length?'Everything is up.':'No tunnels yet. Use New tunnel on the Tunnels page, or the manager: '+S.cli+' new'));
  const more=parts.length>3?parts.splice(3).length:0;
  parts.forEach((p,i)=>{if(i)f.append(' · ');f.append(...p)});
  if(more){f.append(' · ');const a=el('a','dim','+'+more+' more');a.href='#system';f.appendChild(a)}
  heads(down,lossy);
  renderTables();renderWatchdog();renderServer();renderKharej();renderRoutes();
  if(window.PANEL&&PANEL.onRender)PANEL.onRender();
}
// the head's buttons fix the first problem in the headline; with none, the two things people come here to do
function heads(down,lossy){
  const h=$('#hAct');if(!h)return;const P=window.PANEL;const enc=encodeURIComponent;const w=[];
  const d=down.find(t=>t.enabled||t.active),l=lossy[0];
  if(l)w.push(['sec','Why is '+l.name+' slow?',()=>openDrawer(l.name)]);
  if(d)w.push(['pri',(d.active?'Restart ':'Start ')+d.name,()=>P.act('tunnels/'+enc(d.name)+'/'+(d.active?'restart':'start')).then(r=>{if(r){P.toast(d.name+': done');loadOverview()}})]);
  if(!w.length){const st=$('#stBtn');if(st&&st.dataset.name)w.push(['sec','Speed test',()=>st.click()])}
  if(w.length<2&&P.newTunnel)w.push([w.some(x=>x[0]==='pri')?'sec':'pri','New tunnel',()=>P.newTunnel()]);
  const key=w.map(x=>x[0]+x[1]).join('|');if(h.dataset.k===key)return;h.dataset.k=key;h.textContent='';
  w.forEach(([c,t,fn])=>{const b=el('button','btn '+c,t);b.type='button';b.onclick=()=>busy(b,fn());h.appendChild(b)});
}
// the round button: the same few actions as big tiles, the first problem among them
function quick(){
  const P=window.PANEL,ov=S.ov;if(!ov)return [];const enc=encodeURIComponent;const st=$('#stBtn');
  const down=ov.tunnels.find(t=>statusOf(t)[0]==='p-down'&&(t.enabled||t.active));
  return [['plus','New tunnel','on Kharej and here',()=>P.newTunnel()],
    st&&st.dataset.name&&['gauge','Speed test',st.dataset.name,()=>st.click()],
    down?['restart',(down.active?'Restart ':'Start ')+down.name,statusOf(down)[1].toLowerCase(),()=>P.act('tunnels/'+enc(down.name)+'/'+(down.active?'restart':'start')).then(r=>{if(r)loadOverview()})]
      :['link','Add Kharej','with its pairing token',()=>P.addKharej()],
    ['list','Logs and health','System page',()=>setView('system')]].filter(Boolean);
}
function openQuick(){const qa=$('#qa'),box=$('#qaTiles');box.textContent='';
  quick().forEach(([ic,t,sub,fn],i)=>{const b=el('button','qt');b.type='button';b.style.setProperty('--d',(i*0.05+0.03).toFixed(2)+'s');
    const tx=el('span',null,t);tx.appendChild(el('span','lab',sub));b.append(ico(ic),tx);b.onclick=()=>{closeQuick();fn()};box.appendChild(b)});
  qa.hidden=false;$('#fab').setAttribute('aria-expanded','true');const f=box.querySelector('.qt');if(f)f.focus()}
// the dialog follows its content's height smoothly (a job's lines, an error, a second step) instead of jumping
{const dlg=$('#dlg');let lastH=0;
  new ResizeObserver(()=>{if(!dlg.open){lastH=0;return}const h=dlg.offsetHeight;
    if(lastH&&Math.abs(h-lastH)>8&&!RM)dlg.animate([{height:lastH+'px'},{height:h+'px'}],{duration:300,easing:'cubic-bezier(.16,1,.3,1)'});lastH=h}).observe($('#dlgF'));
  dlg.addEventListener('close',()=>{lastH=0;if(S.stale){S.stale=false;render()}})}
function closeQuick(){const qa=$('#qa');if(!qa||qa.hidden||qa.classList.contains('closing'))return;
  const t=[...qa.querySelectorAll('.qt')];t.forEach((x,i)=>x.style.setProperty('--o',((t.length-1-i)*0.035).toFixed(3)+'s'));
  qa.classList.add('closing');$('#fab').setAttribute('aria-expanded','false');$('#fab').focus();
  setTimeout(()=>{qa.hidden=true;qa.classList.remove('closing')},RM?0:460)}
document.addEventListener('DOMContentLoaded',()=>{const f=$('#fab');if(!f)return;f.onclick=openQuick;$('#qaX').onclick=closeQuick;
  $('#qa').addEventListener('click',e=>{if(e.target.id==='qa')closeQuick()});document.addEventListener('keydown',e=>{if(e.key==='Escape')closeQuick()})});
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
      tr.firstChild.appendChild(el('span','sub',t.role==='Iran'?(t.peer?'to '+t.peer:'Iran side'):'Kharej side'));
      const car=td(null,t.carrier||'–');if(t.reverse)car.appendChild(el('span','sub','reverse'));
      const st=td();const p=el('span','pill '+cls);p.append(el('i'),word);st.appendChild(p);
      td('r n',l.metrics?fmtRate(l.down)+' MB/s':'–').dataset.k='down';
      td('r n',l.metrics?fmtRate(l.up)+' MB/s':'–').dataset.k='up';
      td('r n',l.metrics&&l.rtt?l.rtt.toFixed(0)+' ms':'–');
      const lo=td('r n',l.metrics?l.loss.toFixed(1)+'%':'–');if(cls==='p-slow')lo.classList.add('warnc');
      td().appendChild(sparkCells(t.name));
      td('ports n',(t.ports||[]).join(', ')||'–');
      const ta=td('r ta');const P=window.PANEL,enc=encodeURIComponent;
      const ib=(lab,fn)=>{const b=el('button','btn ic',lab);b.type='button';b.onclick=e=>{e.stopPropagation();busy(b,fn())};ta.appendChild(b)};
      ib(t.active?'Restart':'Start',()=>P.act('tunnels/'+enc(t.name)+'/'+(t.active?'restart':'start')).then(r=>{if(r)loadOverview()}));
      if(t.role==='Iran'&&t.active)ib('Speed test',()=>P.act('tunnels/'+enc(t.name)+'/speedtest',{body:{mb:10}}));
      ib('Details',()=>openDrawer(t.name));
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
// a ring per resource: the arc is the share used, orange from 70 %, red from 85 %
function ring(id,txt,pct,title){const r=$(id);if(!r)return;const f=Math.max(0,Math.min(100,pct))/100;const c=2*Math.PI*42;
  const a=r.querySelector('.r1');a.style.setProperty('stroke-dasharray',(c*f).toFixed(1)+' '+c.toFixed(1));
  r.classList.toggle('warn',pct>=70&&pct<85);r.classList.toggle('hi',pct>=85);r.querySelector('.rv .n').textContent=txt;if(title)r.title=title}
function renderServer(){
  const h=S.ov.host;
  // CPU use of the whole machine (load average when the server cannot say), and how much of it is the tunnels: a Kharej
  // often runs other services too, and the owner should see which part is ours
  const cp=h.cpu_pct>0||h.wat_procs?h.cpu_pct:-1;
  if(cp>=0)ring('#gCpu',cp.toFixed(0)+'%',cp,'load '+h.load1.toFixed(2)+' on '+(h.cpus||'?')+' cores');else ring('#gCpu',h.load1.toFixed(2),h.cpus?h.load1/h.cpus*100:0,(h.cpus||'?')+' cores');
  $('#gCpu .rv .lab').textContent=cp>=0?'cpu':'load';
  const ws=$('#srvWat');if(ws){ws.textContent=h.wat_procs?h.wat_cpu_pct.toFixed(1)+'% cpu · '+h.wat_mem_mb.toFixed(0)+' MB':'–';ws.title=h.wat_procs+' processes: tunnels, this panel, heal';
    $('#srvOther').textContent=cp>=0?Math.max(0,cp-h.wat_cpu_pct).toFixed(0)+'% cpu':'–'}
  ring('#gMem',h.mem_pct.toFixed(0)+'%',h.mem_pct);
  ring('#gDisk',h.disk_pct.toFixed(0)+'%',h.disk_pct);
  $('#srvUp').textContent=h.uptime_s?'up '+fmtDur(h.uptime_s):'';
  $('#srvClock').textContent=h.clock_synced?'synced':'not synced';$('#srvClock').className=h.clock_synced?'':'warnc';
  $('#srv2fa').textContent=S.ov.twofa?'on':'off';$('#srv2fa').className=S.ov.twofa?'':'warnc';
}
function khCard(k){
  const c=el('div','kh');
  const top=el('div','khtop');const p=el('span','pill '+(k.online?'p-up':'p-down'));p.append(el('i'),k.online?'online':'unreachable');top.appendChild(p);
  top.appendChild(el('span','lab',k.online?(k.version?'v'+k.version:'')+(k.caps?' · '+k.caps:''):(k.error||'')));c.appendChild(top);
  const fl=flaps(k,'',20,0.05);c.appendChild(fl);
  c.appendChild(el('div','lab',(fl.dataset.city?k.host+' · ':'')+'through '+k.via.map(n=>n===k.link?'pairing link':n).join(', ')));
  const ul=el('ul','rtl');(k.tunnels||[]).forEach(t=>{const li=el('li');li.appendChild(el('span',null,t.name));const p=el('span','pill '+(t.health==='ok'?'p-up':t.state==='active'?'p-down':'p-off'));p.append(el('i'),t.health==='ok'?'up':t.state==='active'?'no link':'stopped');li.appendChild(p);ul.appendChild(li)});
  if(k.online&&!(k.tunnels||[]).length)ul.appendChild(el('li','empty','No tunnels listed.'));
  c.appendChild(ul);return c;
}
function renderKharej(){
  const kh=S.ov.kharej;$('#khSub').textContent=kh.length?kh.length+' paired':'';
  const l=$('#khList');l.textContent='';
  if(!kh.length){l.appendChild(el('div','empty','No Kharej server is paired yet. Kharej servers, then Add Kharej, with the pairing token Kharej shows.'));return}
  kh.forEach(k=>l.appendChild(khCard(k)));
}

/* routes: per Kharej host, the summed live rate of the local tunnels paired with it */
function kTun(k){const n=k.via.filter(v=>v!==k.link).length;return n?n+' tunnel'+(n>1?'s':''):'paired'}
function hostRate(k){let d=0;k.via.forEach(n=>{const l=S.live[n];if(l)d+=l.down});return d}
function renderRoutes(){
  const ov=S.ov;const kh=ov.kharej;
  $('#mapSub').textContent=ov.tunnels.length+' tunnels · '+kh.length+' Kharej';
  const chips=$('#mapChips');chips.textContent='';
  const ch=(cls,t)=>{const c=el('span','chip');const i=el('i');i.style.background=cls;c.append(i,t);chips.appendChild(c)};
  ch('var(--violet)','this server');if(kh.length)ch('var(--green)','Kharej, up');if(kh.some(k=>!k.online))ch('var(--red)','unreachable');
  const r=$('#routes');r.textContent='';
  const geo=ov.geo||{};const busy=kh.slice().sort((a,b)=>hostRate(b)-hostRate(a));
  busy.slice(0,2).forEach(k=>{const g=geo[k.host];const b=el('div','rt');b.appendChild(el('div','lab','to '+(g&&g.city||k.host)+' · '+kTun(k)));const v=el('div','mid n');v.dataset.host=k.host;v.append(fmtRate(hostRate(k)));v.appendChild(el('span','unit','MB/s'));b.appendChild(v);r.appendChild(b)});
  const mv=el('div','rt');mv.appendChild(el('div','lab','moved this visit'));const v=el('div','mid n');v.id='movedNum';v.textContent=fmtBytes(S.moved);mv.appendChild(v);r.appendChild(mv);
  if(S.mapStarted)mapPlaces();
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
  if(!S.ov||modal())return;
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
  // 30 bars of 2 s each = the last 60 s, so the labels under them are true; each bar is that pair's average
  const svg=$('#sbars');const src=S.series.slice(-60),last=[];for(let i=src.length%2;i<src.length;i+=2)last.push({down:(src[i].down+(src[i+1]||src[i]).down)/2});
  const n=30,bw=300/n;const top=Math.max(131072,...last.map(s=>s.down));$('#sbTop').textContent='bar top '+mb(top).toFixed(mb(top)<10?1:0)+' MB/s';
  let s='<defs><pattern id="hz" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="1.6" height="4" fill="#3a3a41"/></pattern></defs>';
  for(let i=0;i<n-last.length;i++)s+=`<rect x="${(i*bw+1).toFixed(2)}" y="81" width="${(bw-2).toFixed(2)}" height="3" rx="1.5" fill="#232327"/>`;
  last.forEach((p,i)=>{const x=(n-last.length+i)*bw;const hh=Math.max(3,p.down/top*82);s+=`<rect x="${(x+1).toFixed(2)}" y="${(84-hh).toFixed(2)}" width="${(bw-2).toFixed(2)}" height="${hh.toFixed(2)}" rx="1.5" fill="${i===last.length-1?'#3ee08a':'url(#hz)'}"/>`});
  svg.innerHTML=s;
}
function gaugeBase(){
  const svg=$('#gauge');let s='';const N=46;
  for(let i=0;i<N;i++){const a=Math.PI*(1-i/(N-1));const cx=125,cy=126,r1=108,r2=92;s+=`<line data-i="${i}" x1="${(cx+r1*Math.cos(a)).toFixed(1)}" y1="${(cy-r1*Math.sin(a)).toFixed(1)}" x2="${(cx+r2*Math.cos(a)).toFixed(1)}" y2="${(cy-r2*Math.sin(a)).toFixed(1)}" stroke="#26262a" stroke-width="3.2" stroke-linecap="round"/>`}
  svg.innerHTML=s;
}
function gauge(frac,ups,total){
  // one colour for the whole arc, from the state: all up is green, half or more up is orange, less is red
  const N=46,col=frac>=1?'#3ee08a':frac>=.5?'#ff7a33':'#ff5d62',off=getComputedStyle(document.body).getPropertyValue('--line').trim()||'#26262a';
  $('#gauge').querySelectorAll('line').forEach((ln,i)=>{const on=total&&i/(N-1)<=frac+1e-9;ln.setAttribute('stroke',on?col:off)});
  $('#gNum').textContent=total?ups+'/'+total:'–';$('#gLab').textContent=!total?'no tunnels':ups===total?'all up':(total-ups)+' need attention';
}
function chart(){
  const svg=$('#tsvg'),box=svg.parentNode;const W=640,L=40,T=14,B=26;const H=Math.max(200,Math.round(W*box.clientHeight/Math.max(1,box.clientWidth)));
  svg.setAttribute('viewBox','0 0 '+W+' '+H);const d=S.series.slice(-300);const n=d.length;
  if(n<2){svg.innerHTML='';return}
  const vals=d.map(p=>mb(p.down));const top=Math.max(1,Math.ceil(Math.max(...vals)/5)*5);
  const X=i=>L+i*(W-L-4)/(n-1),Y=v=>T+(1-v/top)*(H-T-B);
  let s='<defs><pattern id="dp" width="5" height="5" patternUnits="userSpaceOnUse"><circle cx="2.5" cy="2.5" r="0.9" fill="#3ee08a" opacity="0.45"/></pattern><linearGradient id="fm" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity="1"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient><mask id="mk"><rect x="0" y="0" width="640" height="'+H+'" fill="url(#fm)"/></mask></defs>';
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
// Equirectangular, fitted around every server: Iran and Germany fill the card, a US server zooms it out to the
// Atlantic. shortcut: no wrap at the date line, fine until a server sits east of 150 E with one west of 150 W.
let MAPB={L0:-11,L1:66,A0:25.5,A1:66};const map={sig:''};
function fitBounds(lls,w,h){
  const lo=lls.map(p=>p[0]),la=lls.map(p=>p[1]);const l0=Math.min(...lo),l1=Math.max(...lo),a0=Math.min(...la),a1=Math.max(...la);
  const k=Math.max(0.35,Math.cos((a0+a1)/2*Math.PI/180));const A=w/h;
  let dl=Math.max((l1-l0)*1.45,38),da=Math.max((a1-a0)*1.6,18);
  if(dl*k/da<A)dl=A*da/k;else da=dl*k/A;
  if(da>142){da=142;dl=Math.min(360,A*da/k)}
  let ca=(a0+a1)/2+da*0.04;const cl=(l0+l1)/2;
  if(ca+da/2>84)ca=84-da/2;if(ca-da/2<-62)ca=-62+da/2;
  return {L0:cl-dl/2,L1:cl+dl/2,A0:ca-da/2,A1:ca+da/2};
}
function projM(ll,w,h){return [(ll[0]-MAPB.L0)/(MAPB.L1-MAPB.L0)*w,(MAPB.A1-ll[1])/(MAPB.A1-MAPB.A0)*h]}
function buildMap(w,h){
  const pl=map.pl;MAPB=fitBounds([pl.me.ll,...pl.kh.map(x=>x.ll)],w,h);
  const span=MAPB.L1-MAPB.L0;const pitch=w<520?4.6:5.4,cols=Math.floor(w/pitch),rows=Math.floor(h/pitch),ox=(w-cols*pitch)/2+pitch/2,oy=(h-rows*pitch)/2+pitch/2;
  const glow=Math.max(1.4,span*0.03);const iran=pl.me.cc==='IR'||pl.me.cc==='IR?';
  const pts=[];const ir=projM(pl.me.ll,w,h);let md=1;
  for(let j=0;j<rows;j++)for(let i=0;i<cols;i++){const sx=ox+i*pitch,sy=oy+j*pitch;const lon=MAPB.L0+sx/w*(MAPB.L1-MAPB.L0),lat=MAPB.A1-sy/h*(MAPB.A1-MAPB.A0);
    const land=isLand(lon,lat);const d=Math.hypot(sx-ir[0],sy-ir[1]);if(d>md)md=d;
    // which endpoint lights this dot: -1 this server, n = kharej n, null none
    let hit=null;if(land){if(iran?regionOf(lon,lat):Math.hypot(lon-pl.me.ll[0],(lat-pl.me.ll[1])*1.4)<glow)hit=-1;else for(let n=0;n<pl.kh.length;n++)if(Math.hypot(lon-pl.kh[n].ll[0],(lat-pl.kh[n].ll[1])*1.4)<glow){hit=n;break}}
    pts.push([sx,sy,land?1:0,hit,hash(i,j),d])}
  map.pts=pts;map.md=md;map.pitch=pitch;
}
function mapPlaces(){
  if(!S.ov)return;const pl=places();const sig=JSON.stringify([pl.me.ll,pl.kh.map(x=>x.ll)]);map.pl=pl;
  if(sig!==map.sig&&map.g){map.sig=sig;buildMap(map.g.w,map.g.h);map.t0=performance.now()}
  placeTips();
}
function placeTips(){
  const c=$('#map');const w=c.clientWidth,h=c.clientHeight;const wrap=$('#mapw');wrap.querySelectorAll('.tip').forEach(t=>t.remove());if(!S.ov||!map.pl)return;
  const tip=(ll,dot,name,sub)=>{const p=projM(ll,w,h);const cls=p[0]>w*0.72?'lf':p[1]<h*0.3?'dn':'up';
    const t=el('div','tip '+cls+(S.mapShown?' on':''));const i=el('i');i.style.background=dot;t.append(i,el('b',null,name),el('span','lab',sub));t.style.left=p[0]+'px';t.style.top=p[1]+'px';wrap.appendChild(t);
    // close places (Amsterdam/Nuremberg): try the other sides until the label overlaps no earlier one and stays inside
    const W=wrap.getBoundingClientRect();const hit=r=>r.left<W.left||r.right>W.right||r.top<W.top||r.bottom>W.bottom||put.some(q=>r.left<q.right&&r.right>q.left&&r.top<q.bottom&&r.bottom>q.top);
    for(const k of [cls,'up','dn','rt','lf']){t.className='tip '+k+(S.mapShown?' on':'');if(!hit(t.getBoundingClientRect()))break}
    if(hit(t.getBoundingClientRect()))t.className='tip '+cls+(S.mapShown?' on':'');put.push(t.getBoundingClientRect())};
  const put=[];
  const me=map.pl.me;tip(me.ll,'var(--violet)',me.city||(S.ov.host.name||'this server'),me.city?'this server':'this server · place unknown');
  map.pl.kh.forEach(x=>tip(x.ll,x.k.online?'var(--green)':'var(--red)',x.city||x.k.host,(x.city?x.k.host+' · ':'')+(x.k.online?kTun(x.k):'unreachable')));
}
function startMap(){
  S.mapStarted=true;const c=$('#map');map.g=fitCanvas(c);map.sig='';mapPlaces();
  new ResizeObserver(()=>{map.g=fitCanvas(c);if(map.pl){buildMap(map.g.w,map.g.h);placeTips()}}).observe(c);
  map.t0=performance.now();setTimeout(()=>{S.mapShown=true;document.querySelectorAll('.tip').forEach(t=>t.classList.add('on'))},RM?0:2100);
  const draw=(now)=>{
    requestAnimationFrame(draw);
    if(document.hidden||$('#vOverview').hidden||!map.pts||modal())return;
    const {x,w,h}=map.g;const t=(now-map.t0)/1000;x.clearRect(0,0,w,h);const fdt=Math.min(0.1,(now-(map.last||now))/1000);map.last=now;map.ph=map.ph||{};
    const kh=map.pl.kh;
    const intro=RM?1:Math.min(1,t/1.5);const r=map.pitch*0.24;
    for(const p of map.pts){
      const f=Math.max(0,Math.min(1,(intro*1.25*map.md-p[5])/(map.md*0.18)));if(f<=0)continue;
      const kc=p[3]===null?null:p[3]<0?C_IR:(kh[p[3]]&&kh[p[3]].k.online?C_OK:C_BAD);
      if(kc){x.fillStyle=`rgba(${kc},${(0.92*f).toFixed(3)})`;x.beginPath();x.arc(p[0],p[1],r*1.08,0,6.283);x.fill()}
      else if(p[2]){x.fillStyle=`rgba(236,236,240,${((0.36+0.2*p[4])*f).toFixed(3)})`;x.beginPath();x.arc(p[0],p[1],r,0,6.283);x.fill()}
      else{x.fillStyle=`rgba(236,236,240,${(0.06*f).toFixed(3)})`;x.beginPath();x.arc(p[0],p[1],r*0.75,0,6.283);x.fill()}
    }
    const a=projM(map.pl.me.ll,w,h);const ar=RM?1:Math.max(0,Math.min(1,(t-1.1)/1.0));
    kh.forEach((pk,i)=>{const k=pk.k;
      const b=projM(pk.ll,w,h);const col=k.online?C_OK:C_BAD;
      const mx=(a[0]+b[0])/2,my=(a[1]+b[1])/2,lx=b[0]-a[0],ly=b[1]-a[1],len=Math.hypot(lx,ly)||1;
      let nx=-ly/len,ny=lx/len;if(ny>0){nx=-nx;ny=-ny}const qx=mx+nx*len*.14,qy=my+ny*len*.14;
      const B=(s)=>{const v=1-s;return [v*v*b[0]+2*v*s*qx+s*s*a[0],v*v*b[1]+2*v*s*qy+s*s*a[1]]};
      const n=Math.floor(len/4);
      for(let j=0;j<=n*ar;j++){const q=B(j/n);x.fillStyle='rgba(255,255,255,0.28)';x.beginPath();x.arc(q[0],q[1],0.8,0,6.283);x.fill()}
      // packets: speed follows the live rate to this host; none when unreachable
      const rate=mb(hostRate(k));
      // the phase advances by speed x frame time, so a new live rate changes the pace, never the position
      if(ar>=1&&k.online&&rate>0.01){const sp=0.05+Math.min(0.3,rate/120);const ph0=map.ph[k.host]=((map.ph[k.host]??i*0.27)+sp*fdt)%1;
        for(let m=0;m<2;m++){const head=(ph0+m*0.5)%1;for(let j=0;j<26;j++){const s=head-j*0.007;if(s<0)break;const q=B(s);const al=1-j/26;x.fillStyle=`rgba(${col},${(al*0.95).toFixed(3)})`;x.beginPath();x.arc(q[0],q[1],j===0?2.2:0.6+1.2*al,0,6.283);x.fill()}}}
      const ph=(t*0.5+i*0.3)%1;x.strokeStyle=`rgba(${col},${((1-ph)*0.55).toFixed(3)})`;x.lineWidth=1;x.beginPath();x.arc(b[0],b[1],3+ph*18,0,6.283);x.stroke();
      x.fillStyle='#f3f3f4';x.beginPath();x.arc(b[0],b[1],2.6,0,6.283);x.fill();
    });
    const ph=(t*0.5+.5)%1;x.strokeStyle=`rgba(${C_IR},${((1-ph)*0.6).toFixed(3)})`;x.beginPath();x.arc(a[0],a[1],3+ph*22,0,6.283);x.stroke();
    x.fillStyle='#f3f3f4';x.beginPath();x.arc(a[0],a[1],3,0,6.283);x.fill();
  };
  requestAnimationFrame(draw);
}

/* ---------- tunnel drawer ---------- */
// drawerHead fills the parts of the open drawer that follow the tunnel's state; S.dKey remembers what the action
// buttons were built for, so a start or stop (here, from the quick menu or by the watchdog) rebuilds them
function drawerHead(t){
  $('#dName').textContent=t.name;$('#dSub').textContent=[t.role,t.carrier,t.reverse?'reverse':'',t.uptime?'up '+t.uptime:''].filter(Boolean).join(' · ');
  const info=$('#dInfo');info.textContent='';
  const kv=(k,v)=>{const d=el('div','kv');d.append(el('span',null,k),el('span','n',v));info.appendChild(d)};
  if(t.peer)kv('Kharej',t.peer);kv('Ports',(t.ports||[]).join(', ')||'–');kv('Paired',t.paired?'yes':'no');kv('Starts at boot',t.enabled?'yes':'no');
  const [pc,pw]=statusOf(t);const pl=$('#dPill');pl.textContent='';const pp=el('span','pill '+pc);pp.append(el('i'),pw);pl.appendChild(pp);
  const key=[t.active,t.enabled,t.paired,t.carrier].join('/');
  if(S.dKey!==key){S.dKey=key;if(window.PANEL&&PANEL.onDrawer)PANEL.onDrawer(t.name,t)}
}
function syncDrawer(){if(!S.drawer||!S.ov)return;const t=S.ov.tunnels.find(x=>x.name===S.drawer);if(t)drawerHead(t)}
async function openDrawer(name){
  S.drawer=name;S.dKey=null;S.hAt=Date.now();$('#drawer').hidden=false;const t=S.ov.tunnels.find(x=>x.name===name)||{name};
  drawerHead(t);drawerLive();$('#dX').focus();
  const [h,l]=await Promise.all([api('tunnels/'+encodeURIComponent(name)+'/history').catch(()=>null),api('tunnels/'+encodeURIComponent(name)+'/logs?n=200').catch(()=>null)]);
  if(S.drawer!==name)return;
  drawHist(h&&h.ok&&Array.isArray(h.j)?h.j:[]);
  showLog(l);
}
function showLog(l){const pre=$('#dLog');pre.textContent=l&&l.ok?(l.j.lines.join('\n')||'(empty)'):'Could not read the log.';pre.scrollTop=pre.scrollHeight}
$('#dLogR').addEventListener('click',async()=>{if(!S.drawer)return;showLog(await api('tunnels/'+encodeURIComponent(S.drawer)+'/logs?n=200').catch(()=>null))});
function drawerLive(){const l=S.live[S.drawer]||{};const now=Date.now();if(now-(S.hAt||0)>5000){S.hAt=now;const nm=S.drawer;api('tunnels/'+encodeURIComponent(nm)+'/history').then(h=>{if(S.drawer===nm&&h&&h.ok&&Array.isArray(h.j))drawHist(h.j)}).catch(()=>{})}const set=(id,v,u)=>{const e=$(id);e.textContent=v;if(u)e.appendChild(el('span','unit',u))};
  set('#dDown',l.metrics?fmtRate(l.down):'–',l.metrics?'MB/s':'');set('#dUp',l.metrics?fmtRate(l.up):'–',l.metrics?'MB/s':'');set('#dRtt',l.metrics&&l.rtt?l.rtt.toFixed(0):'–',l.metrics&&l.rtt?'ms':'');set('#dLoss',l.metrics?l.loss.toFixed(1):'–',l.metrics?'%':'')}
// The drawer's 5 minutes: download and upload from the engine's byte totals (4.0.1+; down = bytes in on Iran, bytes
// out on Kharej, as the live rates), latency dashed. An older engine has no totals: its pacing rate stands in, labelled.
function drawHist(d){
  const svg=$('#dChart');const W=640,H=180,L=40,T=12,B=24;
  if(d.length<2){svg.innerHTML='<text x="320" y="90" text-anchor="middle">No history yet: the tunnel keeps 5 minutes once it runs.</text>';$('#dLegend').textContent='';return}
  const t=S.ov&&S.ov.tunnels.find(x=>x.name===S.drawer),kh=t&&t.role==='Kharej',real=d.every(s=>s.bytes_in!==undefined);
  let dn=[],up=[],r=[],ts=[];
  if(real){for(let i=1;i<d.length;i++){const dt=Math.max(1,d[i].t-d[i-1].t);let a=d[i].bytes_in-d[i-1].bytes_in,b=d[i].bytes_out-d[i-1].bytes_out;if(a<0||b<0){a=0;b=0}if(kh)[a,b]=[b,a];dn.push(mb(a/dt));up.push(mb(b/dt));r.push(d[i].srtt_ms||0);ts.push(d[i].t)}}
  else{d.forEach(s=>{dn.push(mb(s.rate_bps||0));r.push(s.srtt_ms||0);ts.push(s.t)})}
  const n=dn.length;if(n<2){svg.innerHTML='<text x="320" y="90" text-anchor="middle">Collecting: the graph fills in over the next seconds.</text>';return}
  const top=Math.max(1,Math.ceil(Math.max(...dn,...up)/5)*5),rt=Math.max(10,Math.max(...r)*1.2);
  const X=i=>L+i*(W-L-4)/(n-1),Y=x=>T+(1-x/top)*(H-T-B),YR=x=>T+(1-x/rt)*(H-T-B),path=(v,f)=>v.map((x,i)=>(i?'L':'M')+X(i).toFixed(1)+' '+f(x).toFixed(1)).join('');
  let s='';for(let k=0;k<=4;k++){const y=top*k/4;s+=`<line x1="${L}" x2="${W}" y1="${Y(y).toFixed(1)}" y2="${Y(y).toFixed(1)}" class="gl"/><text x="0" y="${(Y(y)+3.5).toFixed(1)}">${y.toFixed(y<10?1:0)}</text>`}
  s+=`<path d="${path(r,YR)}" fill="none" stroke="#9a8cff" stroke-width="1.2" stroke-dasharray="3 3" opacity=".8"/>`;
  if(up.length)s+=`<path d="${path(up,Y)}" fill="none" stroke="#5aa9ff" stroke-width="1.6"/>`;
  s+=`<path d="${path(dn,Y)}" fill="none" stroke="#3ee08a" stroke-width="2"/>`;
  s+=`<text x="${L}" y="${H-4}">${fmtDur(ts[n-1]-ts[0])} ago</text><text x="${W}" y="${H-4}" text-anchor="end">MB/s · latency max ${Math.max(...r).toFixed(0)} ms</text>`;
  svg.innerHTML=s;
  $('#dLegend').textContent=real?'— download · — upload · - - latency':'— pacing rate (update this tunnel for real traffic) · - - latency';
  svg.onpointermove=e=>{const bx=svg.getBoundingClientRect();const i=Math.max(0,Math.min(n-1,Math.round(((e.clientX-bx.left)/bx.width*W-L)/((W-L-4)/(n-1)))));
    svg.setAttribute('aria-label',dn[i].toFixed(2)+' MB/s');svg.querySelector('title')||svg.appendChild(document.createElementNS('http://www.w3.org/2000/svg','title'));svg.querySelector('title').textContent=new Date(ts[i]*1000).toLocaleTimeString()+'  ↓ '+dn[i].toFixed(2)+(up.length?'  ↑ '+up[i].toFixed(2):'')+' MB/s  '+r[i].toFixed(0)+' ms'};
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
$('#tfStart').addEventListener('click',()=>busy($('#tfStart'),tfStart()));
async function tfStart(){
  const r=await api('settings/2fa/setup',{method:'POST'});if(!r.ok){PANEL.toast(r.j.error||'Could not start the setup.',true);return}
  $('#tfQR').innerHTML=r.j.svg;$('#tfKey').textContent=r.j.secret;$('#tfSetup').hidden=false;$('#tfStart').hidden=true;$('#tfCode').focus();
}
$('#tfOn').addEventListener('click',()=>busy($('#tfOn'),tfOn()));
$('#tfCode').addEventListener('keydown',e=>{if(e.key==='Enter')$('#tfOn').click()});
async function tfOn(){
  const code=$('#tfCode').value.trim();if(!/^\d{6}$/.test(code)){$('#tfErr').textContent='Type the 6 digits the app shows.';return}
  const r=await api('settings/2fa/enable',{method:'POST',body:{code}});
  if(!r.ok){$('#tfErr').textContent=r.j.error||'Failed.';return}
  $('#tfErr').textContent='';$('#tfSetup').hidden=true;$('#tfStart').hidden=false;$('#tfCode').value='';
  await loadSettings();$('#tfRec').hidden=false;$('#tfRecList').textContent=r.j.recovery.join('\n');loadOverview();PANEL.toast('Two-factor sign-in is on. Keep the recovery codes.');
}
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

/* the light under the pointer: primary buttons bend it like liquid, Kharej cards catch it like foil (--mx/--my in px) */
if(!RM){let pe=null,raf=0;document.addEventListener('pointermove',e=>{pe=e;if(!raf)raf=requestAnimationFrame(()=>{raf=0;
  const t=pe.target.closest&&pe.target.closest('.btn.pri,.ksrv,.fx-holo');if(!t)return;const r=t.getBoundingClientRect();
  t.style.setProperty('--mx',(pe.clientX-r.left).toFixed(0)+'px');t.style.setProperty('--my',(pe.clientY-r.top).toFixed(0)+'px');
  if(t.classList.contains('fx-holo')){t.style.setProperty('--ty',(((pe.clientX-r.left)/r.width-.5)*12).toFixed(1)+'deg');t.style.setProperty('--tx',(-((pe.clientY-r.top)/r.height-.5)*16).toFixed(1)+'deg')}})},{passive:true});
  // a press sends a ripple out from the finger instead of squashing the button
  document.addEventListener('pointerdown',e=>{const b=e.target.closest&&e.target.closest('.btn');if(!b||b.disabled)return;const r=b.getBoundingClientRect();
    b.style.setProperty('--mx',(e.clientX-r.left).toFixed(0)+'px');b.style.setProperty('--my',(e.clientY-r.top).toFixed(0)+'px');
    const s=document.createElement('span');s.className='rip';s.style.setProperty('--rx',(e.clientX-r.left)+'px');s.style.setProperty('--ry',(e.clientY-r.top)+'px');
    s.style.setProperty('--rs',(Math.hypot(r.width,r.height)*2)+'px');b.appendChild(s);setTimeout(()=>s.remove(),700);
    if(b.classList.contains('fx-aurora'))edgeGlow()},{passive:true})}
// fx-aurora: the screen's edge glows in the aurora's colours once, like a payment going through
function edgeGlow(){const g=document.createElement('div');g.className='edge-glow';g.append(document.createElement('i'),document.createElement('i'));
  document.body.appendChild(g);setTimeout(()=>g.remove(),2000)}
/* phones: the bottom bar and the quick action button are liquid glass. A lens with a squircle bevel: the middle stays
   clear, the rim bends what scrolls under it (Snell, IOR 3) and splits it slightly by colour (blue bends most); a hairline
   catches a light that follows the pointer, the phone's tilt or the scroll. Only Chromium can bend the page
   (backdrop-filter: url()); every other browser keeps the rim, tint and light over a light frost. A 3 px frost under the lens keeps text
   that scrolls beneath from reading as sharp as the page around it. */
(()=>{
  const SV='http://www.w3.org/2000/svg',mq=matchMedia('(max-width:760px)'),de=document.documentElement;
  if('userAgentData' in navigator)de.classList.add('lg-refract');
  const host=document.createElementNS(SV,'svg');host.setAttribute('width','0');host.setAttribute('height','0');host.setAttribute('aria-hidden','true');host.setAttribute('class','lg-defs');
  host.setAttribute('color-interpolation-filters','sRGB');document.body.appendChild(host);
  const sq=x=>Math.pow(1-Math.pow(1-x,4),.25);
  function profile(th,bz,n=128){const eta=1/3,o=new Float64Array(n);
    for(let i=0;i<n;i++){const x=i/n,y=sq(x),dx=x<1?1e-4:-1e-4,d=(sq(x+dx)-y)/dx,m=Math.hypot(d,1),nx=-d/m,ny=-1/m,k=1-eta*eta*(1-ny*ny);
      if(k<0)continue;const q=Math.sqrt(k),rx=-(eta*ny+q)*nx,ry=eta-(eta*ny+q)*ny;o[i]=rx*((y*bz+th)/ry)}return o}
  // displacement map of a rounded rect, drawn at 2x: R/G = x/y shift around 128, pointing inward along the edge normal
  function dmap(w,h,r,bz,th){const P=profile(th,bz),N=P.length;let mx=0;for(const v of P)mx=Math.max(mx,Math.abs(v));mx=mx||1;
    const S=2,W=w*S,H=h*S,c=document.createElement('canvas');c.width=W;c.height=H;const x=c.getContext('2d'),im=x.createImageData(W,H),d=im.data;
    for(let j=0;j<H;j++)for(let i=0;i<W;i++){const px=(i+.5)/S-w/2,py=(j+.5)/S-h/2,qx=Math.abs(px)-(w/2-r),qy=Math.abs(py)-(h/2-r);
      let f,nx=0,ny=0;if(qx>0&&qy>0){const l=Math.hypot(qx,qy);f=r-l;nx=Math.sign(px)*qx/l;ny=Math.sign(py)*qy/l}
      else if(qx>qy){f=r-qx;nx=Math.sign(px)}else{f=r-qy;ny=Math.sign(py)}
      const o=(j*W+i)*4;d[o+2]=0;d[o+3]=255;
      if(f<0||f>=bz){d[o]=d[o+1]=128;continue}
      const v=P[Math.min(N-1,(f/bz*N)|0)]/mx,op=Math.min(1,f);d[o]=128+(-nx*v)*127*op;d[o+1]=128+(-ny*v)*127*op}
    x.putImageData(im,0,0);return [c.toDataURL(),mx]}
  function build(el,id){const w=el.offsetWidth,h=el.offsetHeight;if(!w||!h)return;const key=w+'x'+h;if(el.dataset.lg===key)return;el.dataset.lg=key;
    const r=Math.min(h/2,w/2,parseFloat(getComputedStyle(el).borderTopLeftRadius)||h/2),bz=Math.min(r-1,14),[url,mx]=dmap(w,h,r,bz,18);
    const old=host.querySelector('#'+id);if(old)old.remove();const f=document.createElementNS(SV,'filter');f.id=id;
    ['x','y'].forEach(a=>f.setAttribute(a,'0'));f.setAttribute('width','100%');f.setAttribute('height','100%');
    const sc=k=>(mx*k).toFixed(1),ch=(n,i)=>{const m=Array(20).fill(0);m[i*6]=1;m[18]=1;return `<feColorMatrix in="d${n}" type="matrix" values="${m.join(' ')}" result="c${n}"/>`};
    f.innerHTML=`<feGaussianBlur in="SourceGraphic" stdDeviation="3" result="s"/><feImage href="${url}" x="0" y="0" width="${w}" height="${h}" preserveAspectRatio="none" result="m"/>`+
      [['r',.94],['g',1],['b',1.06]].map(([n,k])=>`<feDisplacementMap in="s" in2="m" scale="${sc(k)}" xChannelSelector="R" yChannelSelector="G" result="d${n}"/>`).join('')+
      ch('r',0)+ch('g',1)+ch('b',2)+`<feComposite in="cr" in2="cg" operator="arithmetic" k2="1" k3="1" result="rg"/><feComposite in="rg" in2="cb" operator="arithmetic" k2="1" k3="1"/>`;
    host.appendChild(f);el.style.setProperty('--lg-filter','url(#'+id+')')}
  const els=[['#nav','lgNav'],['#fab','lgFab']].map(([q,id])=>[$(q),id]).filter(([e])=>e);
  if(de.classList.contains('lg-refract')){const ro=new ResizeObserver(()=>{if(mq.matches)els.forEach(([e,id])=>build(e,id))});els.forEach(([e])=>ro.observe(e))}
  // the light: pointer (mouse), else the phone's tilt, else a slow sway with the scroll
  if(RM)return;let a=-45,raf=0;const put=v=>{a=v;if(!raf)raf=requestAnimationFrame(()=>{raf=0;de.style.setProperty('--a',a.toFixed(1)+'deg')})};
  addEventListener('pointermove',e=>{if(e.pointerType!=='mouse'||!mq.matches)return;const b=$('#nav').getBoundingClientRect();put(Math.atan2(e.clientX-(b.left+b.width/2),-(e.clientY-(b.top+b.height/2)))*180/Math.PI)},{passive:true});
  let tilt=false;addEventListener('deviceorientation',e=>{if(e.gamma==null)return;tilt=true;put(-45+Math.max(-60,Math.min(60,e.gamma*2)))},{passive:true});
  addEventListener('scroll',()=>{if(!tilt&&mq.matches)put(-45+Math.sin(scrollY/260)*40)},{passive:true});
})();
/* an element leaves as dust: its box breaks into specks that drift off and fade (toasts, mostly) */
function dust(n){
  if(RM||!n.isConnected){n.remove();return}
  const r=n.getBoundingClientRect(),cv=document.createElement('canvas'),d=devicePixelRatio||1,W=r.width+160,H=r.height+80;
  cv.width=W*d;cv.height=H*d;cv.className='dust';cv.style.left=(r.left-40)+'px';cv.style.top=(r.top-60)+'px';cv.style.width=W+'px';cv.style.height=H+'px';
  document.body.appendChild(cv);const x=cv.getContext('2d');x.scale(d,d);
  const col=getComputedStyle(n).color,ps=[];
  for(let i=0;i<Math.min(420,r.width*r.height/40);i++){const px=40+Math.random()*r.width,py=60+Math.random()*r.height;
    ps.push({x:px,y:py,vx:.6+Math.random()*1.8,vy:-(.2+Math.random()*1.1),d:(px-40)/r.width*260+Math.random()*120,s:1+Math.random()*1.6})}
  n.classList.add('dusting');const t0=performance.now();
  (function f(now){const t=now-t0;x.clearRect(0,0,W,H);x.fillStyle=col;let live=0;
    for(const p of ps){const k=t-p.d;if(k<0){live++;continue}const a=1-k/700;if(a<=0)continue;live++;
      x.globalAlpha=a*.85;x.fillRect(p.x+p.vx*k/16,p.y+p.vy*k/16-k*k/90000,p.s,p.s)}
    if(t>220&&n.isConnected)n.remove();
    if(live&&t<1600)requestAnimationFrame(f);else cv.remove()})(t0)}
window.PANEL={dust,api,el,$,S,busy,ico,dm,dd,DM_KINDS,newer,placeInd,flaps,render,loadOverview,fmtBytes,fmtDur,fmtRate,mb,openDrawer,closeDrawer,VIEWS,setView,statusOf,sparkCells,gaugeArc:null};

/* ---------- boot ---------- */
markDots();
document.querySelectorAll('[data-title]').forEach(e=>{e.textContent=document.title});
api('me',{auth:true}).then(r=>{if(r.ok)enterApp();else showLogin()}).catch(()=>showLogin());
})();
