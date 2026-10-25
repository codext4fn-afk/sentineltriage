// Package html renders a single, dependency-free HTML triage dashboard.
//
// Security model: the report embeds attacker-influenced strings (file paths,
// matched snippets, process command lines), so it is defended in depth.
// Finding data is carried in a non-executable application/json block, already
// HTML-escaped by the JSON encoder, and parsed by a static script. A strict
// Content-Security-Policy pins that script and the stylesheet by SHA-256 hash
// and forbids all network origins, so even a string that defeats escaping
// cannot exfiltrate or execute.
package html

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"strings"

	"github.com/codext4fn-afk/sentineltriage/internal/engine"
	"github.com/codext4fn-afk/sentineltriage/internal/report/jsonout"
)

// Write renders the dashboard for r into w.
func Write(w io.Writer, r *engine.Result, m jsonout.Meta) error {
	doc := jsonout.Build(r, m)
	// Default HTML escaping turns <, >, & into < etc., so the payload
	// contains no literal "<" and cannot terminate the <script> element.
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	csp := strings.Join([]string{
		"default-src 'none'",
		"img-src data:",
		"style-src 'sha256-" + sriHash(styleCSS) + "'",
		"script-src 'sha256-" + sriHash(appJS) + "'",
		"base-uri 'none'",
		"form-action 'none'",
	}, "; ")

	// The CSP is emitted as a complete, trusted <meta> tag so its single
	// quotes are not entity-escaped by attribute-context escaping. This is
	// safe because the value is built only from fixed directives and base64
	// hashes (chars [A-Za-z0-9+/=]); it contains no HTML-significant byte and
	// no user-controlled data.
	metaTag := template.HTML(`<meta http-equiv="Content-Security-Policy" content="` + csp + `">`)

	return page.Execute(w, pageData{
		CSPMeta: metaTag,
		Style:   template.CSS(styleCSS),
		Script:  template.JS(appJS),
		Data:    template.JS(data),
	})
}

type pageData struct {
	CSPMeta template.HTML
	Style   template.CSS
	Script  template.JS
	Data    template.JS
}

// sriHash returns the base64 SHA-256 of s for a CSP hash source. It must be
// computed over the exact bytes emitted; html/template renders template.CSS
// and template.JS values verbatim, so the hashes stay valid.
func sriHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

var page = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{.CSPMeta}}
<title>SentinelTriage Report</title>
<style>{{.Style}}</style>
</head>
<body>
<main id="app" class="loading">Rendering report…</main>
<script id="data" type="application/json">{{.Data}}</script>
<script>{{.Script}}</script>
</body>
</html>
`))

const styleCSS = `
:root{color-scheme:light dark;--bg:#0b0e14;--panel:#141a24;--fg:#e6edf3;--muted:#8b949e;--line:#263040;
--crit:#ff5c6c;--high:#ff8c42;--med:#ffd166;--low:#4aa3ff;--info:#8b949e;--ok:#3fb950}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 24px}
.tiles{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px}
.tile{flex:1;min-width:110px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile .n{font-size:26px;font-weight:700}
.tile .l{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.06em}
.tile.crit .n{color:var(--crit)}.tile.high .n{color:var(--high)}.tile.med .n{color:var(--med)}
.tile.low .n{color:var(--low)}.tile.info .n{color:var(--info)}
.bar{height:8px;border-radius:6px;overflow:hidden;display:flex;background:var(--line);margin-bottom:24px}
.bar>span{display:block}
.meta{display:flex;flex-wrap:wrap;gap:16px;color:var(--muted);margin-bottom:24px;font-size:13px}
.meta b{color:var(--fg);font-weight:600}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.filters button{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:999px;padding:5px 12px;cursor:pointer;font:inherit}
.filters button[aria-pressed=true]{border-color:var(--low);color:var(--low)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
tr:last-child td{border-bottom:none}
.sev{font-weight:700;font-size:12px;text-transform:uppercase;white-space:nowrap}
.sev.critical{color:var(--crit)}.sev.high{color:var(--high)}.sev.medium{color:var(--med)}
.sev.low{color:var(--low)}.sev.info{color:var(--info)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--fg);word-break:break-all}
.loc{color:var(--muted);font-size:12px}
.tech{display:inline-block;background:var(--line);border-radius:4px;padding:1px 6px;font-size:11px;margin:1px 2px 0 0}
.rem{color:var(--muted);font-size:12px;margin-top:4px}
.empty{padding:40px;text-align:center;color:var(--ok);font-size:16px}
.warn{background:#3a2a12;border:1px solid var(--high);color:var(--med);padding:10px 14px;border-radius:8px;margin-bottom:16px}
footer{color:var(--muted);font-size:12px;margin-top:24px;text-align:center}
`

// appJS reads the embedded JSON and builds the DOM entirely via createElement /
// textContent. It never uses innerHTML with report data, which keeps untrusted
// strings out of any HTML-parsing path even before the CSP applies.
const appJS = `
(function(){
  "use strict";
  var SEV=["critical","high","medium","low","info"];
  var data;
  try{ data=JSON.parse(document.getElementById("data").textContent); }
  catch(e){ document.getElementById("app").textContent="Failed to parse report data."; return; }
  var app=document.getElementById("app"); app.className=""; app.textContent="";
  function el(tag,cls,txt){var n=document.createElement(tag);if(cls)n.className=cls;if(txt!=null)n.textContent=txt;return n;}
  function pct(n,t){return t>0?(100*n/t).toFixed(0):0;}

  var sum=data.summary||{by_severity:{}}, run=data.run||{}, counts=sum.by_severity||{}, total=sum.total||0;

  app.appendChild(el("h1","","SentinelTriage Report"));
  app.appendChild(el("p","sub",(data.tool?data.tool.name+" "+data.tool.version:"")+" · ATT&CK "+(data.tool?data.tool.attack_version:"")));

  if(run.interrupted||run.budget_exceeded){
    app.appendChild(el("div","warn",run.interrupted?"Run interrupted — results are partial.":"Time budget exhausted — results are partial."));
  }

  var tiles=el("div","tiles");
  SEV.forEach(function(s){
    var t=el("div","tile "+s);
    t.appendChild(el("div","n",String(counts[s]||0)));
    t.appendChild(el("div","l",s));
    tiles.appendChild(t);
  });
  app.appendChild(tiles);

  var bar=el("div","bar");
  SEV.forEach(function(s){var w=pct(counts[s]||0,total);if(w>0){var seg=el("span");seg.style.width=w+"%";seg.style.background="var(--"+ (s==="critical"?"crit":s==="high"?"high":s==="medium"?"med":s==="low"?"low":"info") +")";bar.appendChild(seg);}});
  if(total>0)app.appendChild(bar);

  var meta=el("div","meta");
  function m(label,val){var d=el("div");d.appendChild(el("b","",val));d.appendChild(document.createTextNode(" "+label));return d;}
  meta.appendChild(m("findings",String(total)));
  meta.appendChild(m("coverage",pct((run.coverage||0)*100,100)+"%"));
  meta.appendChild(m("duration",(run.duration_ms||0)+" ms"));
  meta.appendChild(m("host",(run.os||"")+"/"+(run.arch||"")));
  meta.appendChild(m("gate",(sum.threshold_breached?"FAIL":"pass")+" (fail-on "+(sum.fail_on||"")+")"));
  app.appendChild(meta);

  var findings=(data.findings||[]).slice();
  if(findings.length===0){app.appendChild(el("div","empty","No findings. Nothing at or above the configured threshold."));return;}

  var active={}; SEV.forEach(function(s){active[s]=true;});
  var filters=el("div","filters");
  SEV.forEach(function(s){
    if(!counts[s])return;
    var b=el("button",null,s+" ("+counts[s]+")");b.setAttribute("aria-pressed","true");
    b.addEventListener("click",function(){active[s]=!active[s];b.setAttribute("aria-pressed",active[s]?"true":"false");render();});
    filters.appendChild(b);
  });
  app.appendChild(filters);

  var host=el("div"); app.appendChild(host);
  function render(){
    host.textContent="";
    var table=el("table"),thead=el("thead"),tr=el("tr");
    ["Severity","Rule","Finding","Location","ATT&CK"].forEach(function(h){tr.appendChild(el("th",null,h));});
    thead.appendChild(tr);table.appendChild(thead);
    var tb=el("tbody");
    findings.filter(function(f){return active[f.severity];}).forEach(function(f){
      var r=el("tr");
      r.appendChild(el("td","sev "+f.severity,f.severity));
      var rule=el("td"); rule.appendChild(el("code",null,f.rule_id)); r.appendChild(rule);
      var d=el("td"); d.appendChild(el("div",null,f.title));
      if(f.remediation)d.appendChild(el("div","rem",f.remediation)); r.appendChild(d);
      var loc=el("td","loc"); var L=f.location||{};
      loc.textContent=L.path?(L.path+(L.start_line?":"+L.start_line:"")):(L.pid?("pid "+L.pid):(L.artifact||"")); r.appendChild(loc);
      var tc=el("td"); (f.attack_techniques||[]).forEach(function(t){tc.appendChild(el("span","tech",t));}); r.appendChild(tc);
      tb.appendChild(r);
    });
    table.appendChild(tb); host.appendChild(table);
  }
  render();
  app.appendChild(el("footer","","Generated by SentinelTriage · self-contained, no external resources"));
})();
`
