"use strict";
const $ = id => document.getElementById(id);
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
let de = localStorage.language === "de", dark = localStorage.theme === "dark";
let report, model, project, evidence, selectedNode, expanded, query = "", limit = 75, busy = false, message = "";
const views = ["overview","components","graph","lab"];
const view = () => views.includes(location.hash.slice(1)) ? location.hash.slice(1) : "overview";
const t = key => words[key]?.[Number(de)] ?? key;
const fmt = (value, digits=2) => Number(value).toLocaleString(de?"de-DE":"en-US",{maximumFractionDigits:digits,minimumFractionDigits:digits});
const pill = (key, style="") => '<span class="pill '+style+'">'+esc(t(key))+'</span>';
const paths = {
 overview:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
 components:'<path d="m12 3 9 5-9 5-9-5z M3 12l9 5 9-5 M3 16l9 5 9-5"/>',
 graph:'<circle cx="5" cy="12" r="3"/><circle cx="19" cy="5" r="3"/><circle cx="19" cy="19" r="3"/><path d="m8 11 8-5 M8 13l8 5"/>',
 lab:'<path d="M8 3h8 M10 3v7L4 19q-.6 2 2 2h12q2.6 0 2-2l-6-9V3 M7 15h10"/>',
 file:'<path d="M5 3h9l5 5v13H5z M14 3v6h5 M8 13h8 M8 17h6"/>'
};
const icon = key => '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24">'+paths[key]+'</svg>';
const title = (heading,sub) => '<div class="headline"><h1>'+t(heading)+'</h1><p>'+t(sub)+'</p></div>';
const panel = (key,body,extra="") => '<section class="panel"><div class="panel-head"><h2>'+t(key)+'</h2>'+extra+'</div>'+body+'</section>';
const metric = (key,value,caption) => '<div class="metric"><div class="metric-label">'+t(key)+'</div><div class="big num">'+esc(value)+'</div><small>'+esc(t(caption))+'</small></div>';
const scope = c => c.depth===null?"unknown":c.depth===0?"root":c.depth===1?"direct":"transitive";
const list = () => report?.components ?? [];
const empty = () => '<section class="panel empty"><h2>'+t("noData")+'</h2><p>'+t("noDataHint")+'</p><button data-action="import">'+t("import")+'</button></section>';
function render(){
 document.documentElement.lang=de?"de":"en"; document.body.classList.toggle("dark",dark);
 document.querySelectorAll("[data-t]").forEach(el=>el.textContent=t(el.dataset.t));
 document.querySelectorAll(".close").forEach(el=>el.setAttribute("aria-label",t("close")));
 $("language").textContent=de?"EN / 𝗗𝗘":"𝗘𝗡 / DE"; $("language").title=t("language"); $("language").setAttribute("aria-label",t("language")+" · "+(de?"Deutsch":"English"));
 $("theme").textContent=t(dark?"light":"dark"); $("theme").title=t("switchTheme");
 $("crumb").textContent=t(view()); $("nav").innerHTML=views.map(k=>'<button data-view="'+k+'" '+(view()===k?'aria-current="page"':'')+'>'+icon(k)+t(k)+'</button>').join("");
 $("scan").hidden=!project;
 if(view()==="lab") $("content").innerHTML=lab();
 else if(view()==="components") $("content").innerHTML=title("components","componentsSub")+(report?components():empty());
 else if(view()==="graph") $("content").innerHTML=title("graph","graphSub")+(report?graph():empty());
 else $("content").innerHTML=title("overviewTitle","overviewSub")+(report?overview():empty());
 $("status").textContent=message?t(message):"";
}
function ratio(key,n,total,style=""){
 return '<div class="summaryline"><span>'+t(key)+'</span><span class="num">'+n+' / '+total+'</span></div><div class="bar '+style+'"><i style="width:'+100*n/(total||1)+'%"></i></div>';
}
function overview(){
 const all=list(), n=all.length, queried=all.filter(c=>["checked","partial"].includes(c.intelligence));
 const advisoryIds=new Set(all.flatMap(c=>c.advisories.filter(a=>!a.malicious).map(a=>a.id)));
 const flags=all.filter(c=>c.prediction?.review), hits=all.filter(c=>c.provenance==="verified");
 const queue=all.filter(c=>c.advisories.length||c.prediction?.review).sort((a,b)=>b.advisories.length-a.advisories.length||(b.prediction?.score??0)-(a.prediction?.score??0));
 const dates=queried.map(c=>c.checked_at).filter(Boolean).sort();
 const state=all.some(c=>c.intelligence==="partial"||c.intelligence==="unavailable")?"partial":queried.length?"complete":"local";
 const observed=all.some(c=>["checked","partial"].includes(c.intelligence));
 let html='<div class="sourcebar"><span class="source-icon">'+icon("file")+'</span><div><strong>'+esc(report.title)+'</strong><small>'+esc(report.format)+' · '+t("local")+'</small></div>'+pill(state,"green")+'</div>';
 html+='<div class="metrics">'+metric("components",n,"compSmall")+metric("advisories",observed?advisoryIds.size:"—","unique")+metric("flags",flags.length,"reviewSmall")+metric("verified",hits.length,"verifiedSmall")+'</div>';
 html+='<div class="cols">'+panel("signal",'<div class="panel-body">'+ratio("scored",all.filter(c=>c.prediction).length,n)+ratio("lookup",queried.length,n)+ratio("linked",all.filter(c=>c.depth!==null).length,n)+'</div>')+
 panel("prov",'<div class="panel-body"><p>'+t("provHint")+'</p><p>'+pill(hits.length?"verified":"noneVerified",hits.length?"green":"")+'</p><div class="actions"><button data-action="verify">'+t("verify")+'</button></div></div>')+'</div>';
 html+=panel("review",queue.length?table(queue.slice(0,5)):('<div class="panel-body muted">'+t("noReview")+'</div>'),'<button class="link" data-view="components">'+t("viewAll")+'</button>');
 if(evidence) html+=verification();
 return html+'<p class="caption">'+t("fresh")+' · '+(dates.length?esc(new Date(dates[0]).toLocaleString(de?"de-DE":"en-GB")):t("notChecked"))+'</p>';
}
function verification(){
 const matches=list().filter(c=>c.sha256.includes(evidence.sha256)).length;
 return panel("verification",'<div class="panel-body">'+pill(evidence.status)+' '+pill(evidence.kind)+'<p class="mono">'+esc(evidence.sha256)+'</p>'+
 (evidence.builder?'<p>'+t("builder")+' · '+esc(evidence.builder)+'</p>':'')+'<p>'+t("matches")+' · '+matches+'</p><p class="caption">'+t("verifyNote")+'</p></div>');
}
function table(rows){
 return '<div class="tablewrap"><table><thead><tr>'+["package","version","scope","intel","risk"].map(k=>'<th>'+t(k)+'</th>').join("")+'</tr></thead><tbody>'+rows.map(c=>{
 const a=c.advisories.length, checked=["checked","partial"].includes(c.intelligence);
 return '<tr><td><button class="link mono" data-component="'+esc(c.id)+'" aria-expanded="'+(expanded===c.id)+'">'+esc(c.name)+'</button></td><td class="num">'+esc(c.version||"—")+'</td><td>'+pill(scope(c))+'</td><td>'+(a?pill(a,"alert"):checked?'0':pill(c.intelligence))+'</td><td>'+(c.prediction?'<span class="num">'+fmt(c.prediction.score)+'</span> '+(c.prediction.review?pill("reviewFlag","warn"):""):"—")+'</td></tr>'+
 (expanded===c.id?'<tr><td colspan="5" class="detail">'+detail(c)+'</td></tr>':'');
 }).join("")+'</tbody></table></div>';
}
function detail(c){
 const meta='<p>'+t("ecosystem")+' · '+esc(t(c.ecosystem))+' &nbsp; '+t("prov")+' · '+t(c.provenance)+' &nbsp; OSV · '+t(c.intelligence)+'</p>';
 const findings=c.advisories.map(a=>'<p><strong>'+esc(a.id)+'</strong> '+(a.malicious?pill("reported","alert"):"")+' · '+esc(t(a.severity||"severe"))+'<br>'+a.exploitation.map(x=>esc(x.cve)+' · EPSS '+(x.epss?fmt(100*x.epss.score,3)+'% ('+esc(x.epss.date)+')':t("unavailable"))+' · KEV '+t(x.kev===null?"unavailable":x.kev?"yes":"no")).join("<br>")+'</p>').join("");
 const signals=(c.prediction?.signals??[]).map(s=>t(s.feature)+" +"+fmt(s.difference)).join(" · ");
 const explanation=signals?'<p><b>'+t("signals")+'</b> · '+esc(signals)+'</p><p class="caption">'+t("deltaHint")+'</p>':"";
 const inputs=c.prediction?'<p><b>'+t("predInputs")+'</b></p><div class="featuregrid">'+Object.entries(c.prediction.features).map(([k,v])=>'<span>'+t(k)+' · '+fmt(v,Number.isInteger(v)?0:2)+'</span>').join("")+'</div><p class="caption">'+t("scoreHint")+'</p>':t("modelNA");
 return meta+(findings||(c.intelligence==="checked"?'<p>'+t("noAdvisory")+'</p>':""))+explanation+inputs;
}
function filtered(){return list().filter(c=>(c.name+" "+c.ecosystem+" "+c.version).toLowerCase().includes(query.toLowerCase()));}
function inventoryTable(){
 const rows=filtered();
 return panel("components",rows.length?table(rows.slice(0,limit)):'<p class="panel-body">'+t("noMatch")+'</p>',pill(rows.length))+
 (rows.length>limit?'<button data-action="more">'+t("loadMore")+'</button>':"");
}
function components(){return '<div class="toolbar"><input id="search" type="search" value="'+esc(query)+'" placeholder="'+t("search")+'" aria-label="'+t("search")+'">'+pill(report.format)+'</div><div id="inventoryTable">'+inventoryTable()+'</div>';}
function graph(){
 if(!report.edges.length)return '<section class="panel empty"><h2>'+t("noGraph")+'</h2><p>'+t("graphHint")+'</p></section>';
 const byId=new Map(list().map(c=>[c.id,c])), linked=new Set(report.edges.flat());
 const ids=[...linked].sort((a,b)=>depth(a)-depth(b)||a.localeCompare(b)).slice(0,60);
 function depth(id){return report.roots.includes(id)?0:byId.get(id)?.depth??99;}
 const levels=[...new Set(ids.map(depth))], counts=new Map(), positions=new Map();
 ids.forEach(id=>{
   const level=depth(id), row=counts.get(level)??0;
   positions.set(id,[24+levels.indexOf(level)*192,34+row*62]);counts.set(level,row+1);
 });
 const maxRows=Math.max(...counts.values());
 positions.forEach((position,id)=>position[1]+=26+(maxRows-counts.get(depth(id)))*31);
 const width=levels.length*192+32,height=Math.max(220,maxRows*62+74);
 const headings=levels.map((level,i)=>'<text class="level-name" x="'+(24+i*192)+'" y="29">'+esc(t(level===0?"root":level===1?"direct":level===99?"unknown":"transitive"))+'</text>').join("");
 const edges=report.edges.filter(([a,b])=>positions.has(a)&&positions.has(b));
 const lines=edges.map(([a,b])=>{
   const [x,y]=positions.get(a),[u,v]=positions.get(b), start=x+150,end=u, mid=(start+end)/2;
   return '<path class="edge" marker-end="url(#arrow)" d="M'+start+' '+(y+18)+' C'+mid+' '+(y+18)+','+mid+' '+(v+18)+','+(end-3)+' '+(v+18)+'"/>';
 }).join("");
 const nodes=ids.map(id=>{
   const c=byId.get(id), [x,y]=positions.get(id), name=c?.name??report.title;
   const state=report.roots.includes(id)?"root":c?.advisories.length?"affected":c?.prediction?.review?"review":"";
   return '<g tabindex="0" role="button" aria-label="'+esc(name)+'" class="node '+state+(id===selectedNode?" selected":"")+'" data-node="'+esc(id)+'" transform="translate('+x+' '+y+')"><title>'+esc(name)+'</title><rect width="150" height="36" rx="4"/><text x="10" y="23">'+esc(name.length>17?name.slice(0,16)+"…":name)+'</text></g>';
 }).join("");
 const current=byId.get(selectedNode), children=report.edges.filter(([a])=>a===selectedNode).map(([,b])=>byId.get(b)?.name??b);
 return panel("graph",'<div class="graph"><svg role="group" aria-label="'+t("graph")+'" width="'+width+'" height="'+height+'"><defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0L10 5L0 10" fill="currentColor"/></marker></defs>'+headings+lines+nodes+'</svg></div>',
 '<span class="muted">'+linked.size+' '+t("nodes")+' · '+report.edges.length+' '+t("edges")+'</span>')+
 '<div class="legend">'+pill("root","green")+pill("affected","alert")+pill("reviewFlag","warn")+'</div><p class="caption">'+t("selectNode")+(linked.size>60?" "+t("limited"):"")+'</p>'+
 (selectedNode?'<div class="panel panel-body"><h2>'+esc(current?.name??report.title)+'</h2><p>'+t("dependencies")+' · '+esc(children.join(", ")||t("isolated"))+'</p>'+(current?detail(current):"")+'</div>':"");
}
function lab(){
 if(!model)return '<p>'+t("working")+'</p>';
 const winner=model.results[model.winner], conf=winner.confusion.flat(), metrics=["accuracy","precision","recall","f1","average_precision"];
 let html=title("lab","labSub")+'<div class="sourcebar"><span class="source-icon">'+icon("lab")+'</span><div><strong>'+t(model.winner)+'</strong><small>'+t("selected")+' · npm</small></div>'+pill("cv")+" <b class='num'>"+fmt(winner.cv_ap,3)+'</b></div>'+
 '<div class="metrics">'+metric("cohort",model.positive+model.negative,"observations")+metric("malicious",model.positive,"documented")+metric("training",model.training,"early")+metric("testing",model.testing,"late")+'</div>';
 html+=panel("comparison",'<div class="tablewrap"><table><thead><tr><th>'+t("model")+'</th>'+["accuracy","precision","recall","F1","AP"].map(k=>'<th>'+t(k)+'</th>').join("")+'</tr></thead><tbody>'+
 Object.entries(model.results).sort((a,b)=>b[1].cv_ap-a[1].cv_ap).map(([k,r])=>'<tr><td>'+esc(t(k))+'</td>'+metrics.map(m=>'<td class="num">'+fmt(r[m],3)+'</td>').join("")+'</tr>').join("")+'</tbody></table></div>');
 const importance=Object.entries(model.importance).sort((a,b)=>b[1]-a[1]).slice(0,4);
 html+='<div class="cols">'+panel("matrix",'<div class="panel-body"><div class="matrix">'+["tn","fp","fn","tp"].map((k,i)=>'<div class="'+(i===0||i===3?"hit":"miss")+'">'+t(k)+'<b class="num">'+conf[i]+'</b></div>').join("")+'</div><p class="caption">'+t("cutoff")+' · '+esc(model.cutoff)+'</p></div>')+
 panel("importance",'<div class="panel-body">'+importance.map(([k,v])=>'<div class="summaryline"><span>'+t(k)+'</span><span class="num">'+fmt(v,3)+'</span></div><div class="bar"><i style="width:'+Math.max(0,100*v/(importance[0][1]||1))+'%"></i></div>').join("")+'<p class="caption">'+t("importanceHint")+'</p></div>')+'</div>';
 return html+'<div class="notice"><b>'+t("limits")+'</b> · '+t("limitsText")+'</div>';
}
async function api(action, body, online=false){
 const response=await fetch("/api/"+action+(online?"?online=1":""),{method:"POST",headers:{"X-SBoom":"local"},body});
 const result=await response.json();
 if(!response.ok)throw new Error(result.error||"request_failed");
 return result;
}
async function run(action){
 if(busy)return;
 const file=$("file").files[0];
 if(action==="analyze"&&!file){message="pickFile";$("importer").close();render();return;}
 if(action==="analyze"&&file.size>12*1024*1024){message="too_large";$("importer").close();render();return;}
 if($("importer").open)$("importer").close();
 if($("verification").open)$("verification").close();
 busy=true;message=action==="verify"?"verifying":"working";$("import").disabled=true;render();
 try{
   if(action==="verify"){
     evidence=await api(action,new FormData($("verifyForm")));
     if(evidence.kind==="provenance"){
       list().filter(c=>c.sha256.includes(evidence.sha256)).forEach(c=>{if(c.provenance!=="verified")c.provenance=evidence.status;});
     }
   }else{
     report=await api(action,action==="analyze"?file:null,$("online").checked);
     query="";expanded=null;selectedNode=null;evidence=null;limit=75;
   }
   location.hash="overview";message="";
 }catch(error){message=words[error.message]?error.message:"request_failed";}
 finally{busy=false;$("import").disabled=false;render();}
}
function showImport(){$("online").checked=false;message="";render();$("importer").showModal();}
$("import").onclick=showImport;
$("load").onclick=()=>run("analyze");$("example").onclick=()=>run("example");$("scan").onclick=()=>run("scan");
$("verifyForm").onsubmit=e=>{e.preventDefault();run("verify");};
$("language").onclick=()=>{de=!de;localStorage.language=de?"de":"en";render();};
$("theme").onclick=()=>{dark=!dark;localStorage.theme=dark?"dark":"light";render();};
document.addEventListener("input",e=>{if(e.target.id==="search"){query=e.target.value;limit=75;$("inventoryTable").innerHTML=inventoryTable();}});
document.addEventListener("click",e=>{
 const el=e.target.closest("[data-view],[data-action],[data-component],[data-node]");if(!el)return;
 if(el.dataset.view){location.hash=el.dataset.view;return;}
 if(el.dataset.action==="import"){showImport();return;}
 if(el.dataset.action==="verify"){$("verification").showModal();return;}
 if(el.dataset.action==="more")limit+=75;
 if(el.hasAttribute("data-component"))expanded=expanded===el.dataset.component?null:el.dataset.component;
 if(el.hasAttribute("data-node"))selectedNode=el.dataset.node;
 render();
 if(el.hasAttribute("data-component")||el.hasAttribute("data-node")){
   const attr=el.hasAttribute("data-component")?"data-component":"data-node";
   document.querySelector("["+attr+"="+CSS.escape(el.getAttribute(attr))+"]")?.focus();
 }
});
document.addEventListener("keydown",e=>{if(e.target.hasAttribute("data-node")&&["Enter"," "].includes(e.key)){e.preventDefault();e.target.dispatchEvent(new MouseEvent("click",{bubbles:true}));}});
window.addEventListener("hashchange",()=>{render();$("content").focus({preventScroll:true});window.scrollTo(0,0);});
render();
fetch("/api/model").then(r=>{if(!r.ok)throw Error();return r.json();}).then(data=>{model=data.benchmark;project=data.project;render();}).catch(()=>{message="request_failed";render();});
