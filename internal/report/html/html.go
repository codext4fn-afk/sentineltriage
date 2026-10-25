// Package html renders a single, dependency-free HTML report that mirrors the
// terminal dashboard.
//
// Security model: the report embeds attacker-influenced strings (file paths,
// matched snippets, command lines), so it is defended in depth. Finding data
// is carried in a non-executable application/json block, already HTML-escaped
// by the JSON encoder, and parsed by a static script that builds the DOM with
// textContent only. A strict Content-Security-Policy pins that script and the
// stylesheet by SHA-256 and forbids every network origin, so even a string
// that defeats escaping cannot execute or exfiltrate.
package html

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	"github.com/codext4fn-afk/sentineltriage/internal/attack"
	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/report/jsonout"
)

// Write renders the report for r into w.
//
// The page is assembled directly rather than through html/template. Every
// inserted value is either a fixed constant or JSON produced below, so a
// template engine would have nothing to escape; avoiding it also keeps the
// report off html/template's vulnerability surface.
func Write(w io.Writer, r *engine.Result, m jsonout.Meta) error {
	// Technique names travel with the data so the page needs no lookup table
	// of its own; only IDs that appear in this run are included.
	names := map[string]string{}
	for _, f := range r.Findings {
		for _, id := range f.Techniques {
			if t, ok := attack.Lookup(id); ok {
				names[id] = t.Name
			}
		}
	}
	payload := struct {
		Report     jsonout.Document  `json:"report"`
		Techniques map[string]string `json:"techniques"`
	}{jsonout.Build(r, m), names}
	// json.Marshal escapes <, >, and & as \u003c, \u003e, and \u0026, so the
	// payload contains no literal "<" and cannot close the <script> element.
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// The CSP is built only from fixed directives and base64 hashes
	// ([A-Za-z0-9+/=]), so it needs no attribute escaping.
	csp := strings.Join([]string{
		"default-src 'none'",
		"style-src 'sha256-" + cspHash(styleCSS) + "'",
		"script-src 'sha256-" + cspHash(appJS) + "'",
		"base-uri 'none'",
		"form-action 'none'",
	}, "; ")

	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="`)
	b.WriteString(csp)
	b.WriteString(`">
<title>sentinel report</title>
<style>`)
	b.WriteString(styleCSS)
	b.WriteString(`</style>
</head>
<body>
<main id="app">loading report...</main>
<script id="data" type="application/json">`)
	b.Write(data)
	b.WriteString(`</script>
<script>`)
	b.WriteString(appJS)
	b.WriteString(`</script>
</body>
</html>
`)
	_, err = io.WriteString(w, b.String())
	return err
}

// cspHash returns the base64 SHA-256 of s for a CSP hash source. It must match
// the exact bytes emitted between the tags, which Write copies verbatim.
func cspHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

const styleCSS = `
:root{--bg:#1d1f21;--fg:#c5c8c6;--hi:#e0e0e0;--mute:#969896;--line:#7c7f84;--head:#4d5057;
--crit:#cc6666;--high:#de935f;--med:#f0c674;--low:#81a2be;--info:#969896;--ok:#b5bd68;--teal:#8abeb7;--sel:#c397d8}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:13px/1.45 ui-monospace,"Cascadia Mono","JetBrains Mono",SFMono-Regular,Menlo,Consolas,monospace}
main{padding:10px 14px;max-width:1500px}
.bar{white-space:pre-wrap;margin-bottom:6px}
.bar b{color:var(--hi)}
.m{color:var(--mute)}.hi{color:var(--hi)}.t{color:var(--teal)}.y{color:var(--med)}.ok{color:var(--ok)}
.crit{color:var(--crit);font-weight:bold}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.info{color:var(--info)}
fieldset{border:1px solid var(--line);margin:0 0 6px;padding:2px 8px 6px;min-width:0}
fieldset.active{border-color:var(--crit)}
legend{padding:0 2px;color:var(--hi)}
legend span{color:var(--mute)}
.row{display:flex;gap:6px;flex-wrap:wrap}
.row>fieldset{flex:1 1 300px}
.row>fieldset.sev{flex:0 0 230px}
.vbars{display:flex;gap:10px;align-items:flex-end;height:78px;padding-top:6px}
.vcol{width:30px;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}
.vcol i{display:block;width:24px;min-height:0}
.vlab{display:flex;gap:10px}.vlab span{width:30px;text-align:center}
.hrow{display:grid;grid-template-columns:minmax(0,1fr) 40% 3ch;gap:8px;align-items:center}
.hrow .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}
.hrow i{display:block;height:11px}
.hrow .n,.num{text-align:right;color:var(--hi)}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th{background:var(--head);color:#fff;font-weight:bold;text-align:left;padding:1px 6px;white-space:nowrap;cursor:default}
th.sort{cursor:pointer;user-select:none}
td{padding:1px 6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;vertical-align:top}
tr.f{cursor:pointer}
tr.f.sel td,tr.f.sel td *{color:var(--sel);font-weight:bold}
.keys{color:var(--mute)}
.keys button{font:inherit;color:var(--mute);background:none;border:0;padding:0;cursor:pointer}
.keys button.on{color:var(--med)}
.detail div{white-space:pre-wrap}
.detail .k{display:inline-block;width:9ch;color:var(--mute)}
.warn{color:var(--med)}
.foot{margin-top:4px}
`

// appJS mirrors the terminal dashboard. It builds the DOM exclusively through
// createElement and textContent; report data never reaches an HTML parser.
const appJS = `
(function(){
"use strict";
var SEV=["critical","high","medium","low","info"],SHORT={critical:"CRIT",high:"HIGH",medium:"MED",low:"LOW",info:"INFO"};
var RANK={info:0,low:1,medium:2,high:3,critical:4};
var data,NAMES;
try{var P=JSON.parse(document.getElementById("data").textContent);data=P.report;NAMES=P.techniques||{};}
catch(e){document.getElementById("app").textContent="report data is unreadable";return;}
var app=document.getElementById("app");app.textContent="";
function el(tag,cls,txt){var n=document.createElement(tag);if(cls)n.className=cls;if(txt!=null)n.textContent=String(txt);return n;}
function add(p){for(var i=1;i<arguments.length;i++)p.appendChild(arguments[i]);return p;}
function panel(title,count,cls){var f=el("fieldset",cls),l=el("legend",null,title);if(count!=null)l.appendChild(el("span",null," ["+count+"]"));f.appendChild(l);return f;}
function loc(L){L=L||{};if(L.path)return L.path+(L.start_line?":"+L.start_line:(L.artifact?" "+L.artifact:""));if(L.pid)return "pid "+L.pid;return L.artifact||"";}
function dur(ms){return ms<1000?ms+"ms":(ms/1000).toFixed(2)+"s";}

var run=data.run||{},sum=data.summary||{},tool=data.tool||{},F=data.findings||[],C=data.collectors||[];
var counts=sum.by_severity||{},total=F.length,cov=Math.round((run.coverage||0)*100);

var bar=el("div","bar");
add(bar,el("b",null,"sentinel"),el("span","m"," "+(tool.version||"")));
function field(t,c){add(bar,el("span","m"," ["),el("span",c||"hi",t),el("span","m","]"));}
field((run.os||"")+"/"+(run.arch||""));if(run.hostname)field(run.hostname);
field(total+" findings");field("coverage "+cov+"%",cov<100?"y":"ok");field(dur(run.duration_ms||0));field("fail-on "+(sum.fail_on||""));
field("ATT&CK "+(tool.attack_version||""),"m");
app.appendChild(bar);
if(run.interrupted||run.budget_exceeded)app.appendChild(el("div","warn",run.interrupted?"run interrupted: results are partial":"time budget exhausted: results are partial"));

var row=el("div","row");app.appendChild(row);
var sp=panel("Severity",total,"sev"),vb=el("div","vbars"),vl=el("div","vlab"),peak=1;
SEV.forEach(function(s){peak=Math.max(peak,counts[s]||0);});
SEV.forEach(function(s){
  var c=el("div","vcol"),b=el("i");b.style.height=((counts[s]||0)/peak*100)+"%";b.style.background="var(--"+(s==="critical"?"crit":s==="medium"?"med":s)+")";
  add(c,b);vb.appendChild(c);
});
var vn=el("div","vlab");SEV.forEach(function(s){vn.appendChild(el("span",s,counts[s]||0));});
SEV.forEach(function(s){vl.appendChild(el("span","m",SHORT[s].toLowerCase()));});
add(sp,vb,vn,vl);row.appendChild(sp);

var byLoc={};F.forEach(function(f){var k=(f.location||{}).path||(f.location||{}).artifact||"";var a=byLoc[k]||(byLoc[k]={k:k,n:0,w:0});a.n++;a.w=Math.max(a.w,RANK[f.severity]);});
var locs=Object.keys(byLoc).map(function(k){return byLoc[k];}).sort(function(a,b){return b.n-a.n||b.w-a.w||(a.k<b.k?-1:1);});
var lp=panel("Locations",locs.length),lpeak=locs.length?locs[0].n:1;
locs.slice(0,8).forEach(function(a){
  var r=el("div","hrow"),i=el("i");i.style.width=(a.n/lpeak*100)+"%";var s=SEV[4-a.w];i.style.background="var(--"+(s==="critical"?"crit":s==="medium"?"med":s)+")";
  var w=el("div");w.appendChild(i);add(r,el("span","name",a.k),w,el("span","n",a.n));lp.appendChild(r);
});
if(!locs.length)lp.appendChild(el("div","m","no findings"));
row.appendChild(lp);

var tc={};F.forEach(function(f){(f.attack_techniques||[]).forEach(function(t){tc[t]=(tc[t]||0)+1;});});
var techs=Object.keys(tc).sort(function(a,b){return tc[b]-tc[a]||(a<b?-1:1);});
var ap=panel("ATT&CK",techs.length+" techniques");
techs.slice(0,8).forEach(function(t){
  var r=el("div","hrow"),nm=(NAMES[t]||"").split(": ").pop();r.style.gridTemplateColumns="11ch minmax(0,1fr) 3ch";
  var n=el("span","name",nm);n.style.direction="ltr";add(r,el("span","t",t),n,el("span","n",tc[t]));ap.appendChild(r);
});
if(!techs.length)ap.appendChild(el("div","m","no findings"));
row.appendChild(ap);

var cp=panel("Collectors",C.length),ct=el("table"),ch=el("tr");
[["NAME","34%"],["STATUS","12%"],["TIME","8%"],["FINDINGS","9%"],["GAPS","6%"],["NOTE","31%"]].forEach(function(h){var th=el("th",null,h[0]);th.style.width=h[1];ch.appendChild(th);});
ct.appendChild(ch);
C.forEach(function(c){
  var gaps=(c.degradations||[]).length+(c.dropped_degradations||0),note=c.error||((c.degradations||[])[0]?c.degradations[0].reason+" "+c.degradations[0].scope:"");
  var st=c.status==="ok"?"ok":(c.status==="degraded"||c.status==="timeout"||c.status==="unsupported")?"y":"crit";
  var tr=el("tr");add(tr,el("td",null,c.name),el("td",st,c.status),el("td","num",(c.duration_ms||0)+"ms"),el("td","num",c.findings||0),el("td","num m",gaps),el("td","m",note));ct.appendChild(tr);
});
cp.appendChild(ct);app.appendChild(cp);

var COLS=[["SEV","7%",function(f){return RANK[f.severity];}],["RULE","24%",function(f){return f.rule_id;}],
  ["LOCATION","22%",function(f){return loc(f.location);}],["ATT&CK","10%",function(f){return (f.attack_techniques||[]).join(",");}],
  ["FINDING","37%",function(f){return f.title;}]];
var state={col:0,asc:false,min:0,sel:0};
var fp=panel("Findings",total,"active"),keys=el("span","keys"),fbtn=el("button");
add(keys,document.createTextNode("  navigate [j/k]  sort [click header]  filter "),fbtn);
fp.firstChild.appendChild(keys);
var ft=el("table");add(fp,ft);app.appendChild(fp);
var dp=panel("Detail",null,"detail");app.appendChild(dp);
fbtn.addEventListener("click",function(){cycle();});

function rows(){
  var get=COLS[state.col][2];
  return F.filter(function(f){return RANK[f.severity]>=state.min;}).sort(function(a,b){
    var x=get(a),y=get(b),c=x<y?-1:x>y?1:0;return state.asc?c:-c;
  });
}
function cycle(){state.min=(state.min+1)%5;state.sel=0;draw();}
function draw(){
  var R=rows();state.sel=Math.max(0,Math.min(state.sel,R.length-1));
  fbtn.textContent="[f] "+(state.min?">= "+SEV[4-state.min]:"all");fbtn.className=state.min?"on":"";
  fp.firstChild.firstChild.nextSibling.textContent=" ["+R.length+"]";
  ft.textContent="";var hr=el("tr");
  COLS.forEach(function(c,i){
    var th=el("th","sort",(i===state.col?(state.asc?"↑":"↓"):"")+c[0]);th.style.width=c[1];
    th.addEventListener("click",function(){if(state.col===i)state.asc=!state.asc;else{state.col=i;state.asc=i!==0;}draw();});
    hr.appendChild(th);
  });
  ft.appendChild(hr);
  R.forEach(function(f,i){
    var tr=el("tr","f"+(i===state.sel?" sel":""));
    add(tr,el("td",f.severity,SHORT[f.severity]),el("td",null,f.rule_id),el("td","m",loc(f.location)),
      el("td","t",(f.attack_techniques||[]).join(",")),el("td",null,f.title));
    tr.title=f.title;
    tr.addEventListener("click",function(){state.sel=i;draw();});
    ft.appendChild(tr);
  });
  if(!R.length){var tr=el("tr"),td=el("td","m",total?"nothing at this filter level":"no findings");td.colSpan=5;add(ft,add(tr,td));}
  detail(R[state.sel]);
}
function line(k,v,c){var d=el("div");add(d,el("span","k",k),el("span",c||null,v));dp.appendChild(d);}
function detail(f){
  while(dp.childNodes.length>1)dp.removeChild(dp.lastChild);
  if(!f){dp.appendChild(el("div","m","select a finding"));return;}
  var h=el("div");add(h,el("span",f.severity,SHORT[f.severity]),el("b",null,"  "+f.rule_id),el("span","m","  confidence "+f.confidence));dp.appendChild(h);
  dp.appendChild(el("div","hi",f.title));
  line("where",loc(f.location));
  if(f.description)line("why",f.description);
  if(f.remediation)line("fix",f.remediation);
  if((f.attack_techniques||[]).length)line("att&ck",f.attack_techniques.map(function(t){return NAMES[t]?t+" "+NAMES[t]:t;}).join("; "),"t");
  Object.keys(f.evidence||{}).sort().forEach(function(k){line(k,f.evidence[k],"m");});
}
document.addEventListener("keydown",function(e){
  var R=rows();
  if(e.key==="j"||e.key==="ArrowDown"){state.sel=Math.min(state.sel+1,R.length-1);}
  else if(e.key==="k"||e.key==="ArrowUp"){state.sel=Math.max(state.sel-1,0);}
  else if(e.key==="f"){cycle();return;}
  else return;
  e.preventDefault();draw();
  var s=ft.querySelector("tr.sel");if(s&&s.scrollIntoView)s.scrollIntoView({block:"nearest"});
});
draw();

var foot=el("div","foot"),bad=sum.threshold_breached;
add(foot,el("span",bad?"crit":"ok",bad?"gate FAIL":"gate pass"),el("span","m","  findings at or above "+(sum.fail_on||"")+": "),
  el("span","hi",F.filter(function(f){return RANK[f.severity]>=RANK[sum.fail_on||"high"];}).length));
app.appendChild(foot);
})();
`
