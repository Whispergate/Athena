"""Read-only web dashboard — stdlib only, localhost-bound, token-auth.

The ARL lesson by design: binds 127.0.0.1, requires a bearer token (auto-
generated to ~/.athena/web_token unless ATHENA_TOKEN is set), and opens the
database in read-only mode. It can observe the timeline; it can never mutate.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import report as rep
from .paths import ATHENA_HOME


def get_or_create_token() -> str:
    import os

    env = os.environ.get("ATHENA_TOKEN", "").strip()
    if env:
        return env
    f = ATHENA_HOME / "web_token"
    f.parent.mkdir(parents=True, exist_ok=True)
    if f.exists():
        return f.read_text(encoding="utf-8").strip()
    tok = secrets.token_urlsafe(24)
    f.write_text(tok, encoding="utf-8")
    return tok


class Dash:
    """Read-only queries backing the API endpoints."""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    def _ro(self) -> sqlite3.Connection:
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def scopes(self) -> list[dict]:
        with self._ro() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT scope, COUNT(*) scans, MAX(ts) last_scan FROM snapshots "
                "GROUP BY scope")]
            evc = {r["scope"]: r["n"] for r in c.execute(
                "SELECT scope, COUNT(*) n FROM events GROUP BY scope")}
        for r in rows:
            r["events"] = evc.get(r["scope"], 0)
        return rows

    def timeline(self, scope: str) -> dict:
        with self._ro() as c:
            scans = [dict(r) for r in c.execute(
                "SELECT id, ts, asset_count assets FROM snapshots WHERE scope=? "
                "ORDER BY id DESC LIMIT 60", (scope,))][::-1]
            events = [dict(r) for r in c.execute(
                "SELECT created_at, kind, asset_key, severity FROM events "
                "WHERE scope=? ORDER BY id DESC LIMIT 200", (scope,))]
        return {"scans": scans, "events": events}

    def events(self, scope: str, limit: int = 100) -> list[dict]:
        with self._ro() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT * FROM events WHERE scope=? ORDER BY severity DESC, "
                "id DESC LIMIT ?", (scope, limit))]
        for r in rows:
            r["techniques"] = json.loads(r.pop("techniques") or "[]")
            r["kev_cves"] = json.loads(r.pop("kev_cves") or "[]")
            r.pop("detail_json", None)
            r.pop("dedup_key", None)
        return rows

    def vectors(self, scope: str) -> list[dict]:
        return rep.dedupe_vectors(rep.entry_vectors(self.events(scope, 500), {}))

    def assets(self, scope: str, kind: str, q: str, limit: int) -> list[dict]:
        lim = max(1, min(limit, 1000))
        with self._ro() as c:
            if kind == "subdomain":
                rows = [dict(r) for r in c.execute(
                    "SELECT key, kind, first_seen, last_seen, confidence, "
                    "sources_json, attrs_json FROM assets WHERE kind='subdomain' "
                    "AND (key = ? OR key LIKE ?) "
                    + ("AND key LIKE ? " if q else "") + "LIMIT ?",
                    (("sub:" + scope, "sub:%." + scope)
                     + (("%" + q + "%",) if q else ()) + (lim,)))]
            else:
                rows = [dict(r) for r in c.execute(
                    "SELECT a.key, a.kind, a.first_seen, a.last_seen, a.confidence, "
                    "a.sources_json, a.attrs_json FROM assets a WHERE a.kind=? AND "
                    "a.key IN (SELECT sa.asset_key FROM snapshot_assets sa JOIN "
                    "snapshots s ON sa.snap_id=s.id WHERE s.scope=?) "
                    + ("AND a.key LIKE ? " if q else "") + "LIMIT ?",
                    ((kind, scope) + (("%" + q + "%",) if q else ()) + (lim,)))]
        for r in rows:
            r["sources"] = json.loads(r.pop("sources_json") or "[]")
            r["attrs"] = json.loads(r.pop("attrs_json") or "{}")
        return rows


PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<title>ATHENA</title><style>
:root{--bg:#0d0d11;--panel:#15151a;--line:#26262f;--dim:#8a8a96;--crim:#e5484d}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:#d6d6de;font:13px/1.5 "Cascadia Code",Consolas,monospace;padding:24px}
h1{font-size:20px;letter-spacing:4px}h1 span{color:var(--crim)}
select,input{background:var(--panel);color:#d6d6de;border:1px solid var(--line);border-radius:6px;padding:6px 10px;font:inherit}
input{width:220px}
.top{display:flex;gap:14px;align-items:baseline;border-bottom:1px solid var(--line);padding-bottom:12px;flex-wrap:wrap}
.stats{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 14px}
.stat .n{font-size:18px;font-weight:700;color:#fff}.stat .l{font-size:10px;color:#6a6a76;letter-spacing:1px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
h2{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#6a6a76;margin:14px 0 8px}
.tl{display:flex;gap:2px;align-items:flex-end;height:90px}
.bar{flex:1;background:#2a2a35;border-radius:2px 2px 0 0;position:relative;min-width:3px}
.dot{position:absolute;top:-6px;left:50%;transform:translateX(-50%);width:7px;height:7px;border-radius:50%}
table{width:100%;border-collapse:collapse}td,th{padding:4px 8px;text-align:left;border-bottom:1px solid var(--line)}
th{color:#6a6a76;font-size:10px;letter-spacing:1px;text-transform:uppercase}
.crit{color:var(--crim)}.high{color:#f5a524}.med{color:#e2c94d}.low{color:#6ca0dd}
.tabs{display:flex;gap:6px;margin-bottom:10px}.tab{cursor:pointer;padding:3px 12px;border:1px solid var(--line);border-radius:999px}
.tab.on{border-color:var(--crim);color:var(--crim)}
.vec{border:1px solid var(--line);border-left:3px solid var(--line);border-radius:6px;padding:10px 12px;margin-bottom:8px}
.vec.crit{border-left-color:var(--crim)}.vec.high{border-left-color:#f5a524}
.vec.med{border-left-color:#e2c94d}.vec.low{border-left-color:#6ca0dd}
.muted{color:var(--dim)}footer{margin-top:20px;color:#5c5c68;font-size:11px}
</style></head><body>
<div class="top"><h1>ATH<span>U</span>NA</h1>
<select id="scope"></select><input id="q" placeholder="filter assets…">
<span class="muted" id="meta"></span></div>
<div class="stats" id="stats"></div>
<div class="grid"><div><h2>asset timeline</h2><div class="panel"><div class="tl" id="tl"></div>
<div class="muted" id="tlaxis" style="font-size:10px"></div></div>
<h2>event stream</h2><div class="panel" style="max-height:320px;overflow:auto"><table id="ev"></table></div></div>
<div><h2>ranked entry vectors</h2><div id="vecs" style="max-height:260px;overflow:auto"></div>
<h2>assets</h2><div class="tabs" id="tabs"></div>
<div class="panel" style="max-height:420px;overflow:auto"><table id="as"></table></div></div></div>
<footer>athena dashboard · read-only · touch=passive · findings are hypotheses — verify before relying</footer>
<script>
const T=new URLSearchParams(location.search).get("token");
const H={"Authorization":"Bearer "+T};
const $=id=>document.getElementById(id);
let kind="subdomain";
async function api(p){const r=await fetch(p,{headers:H});if(r.status==401){document.body.innerHTML="unauthorized";throw 0}return r.json()}
function sev(s){return s>=8.5?["crit","CRITICAL"]:s>=6.5?["high","HIGH"]:s>=4?["med","MEDIUM"]:["low","LOW"]}
async function load(){
 const sc=await api("/api/scopes");
 if(!$("scope").options.length)for(const s of sc)$("scope").add(new Option(s.scope,s.scope));
 if(!$("scope").value&&sc.length)$("scope").value=sc[0].scope;
 const S=$("scope").value;if(!S)return;
 const tl=await api("/api/timeline?scope="+S);
 const ev=await api("/api/events?scope="+S);
 const vc=await api("/api/vectors?scope="+S);
 const st={assets:tl.scans.at(-1)?.assets??0,scans:sc.find(x=>x.scope==S)?.scans??0,events:sc.find(x=>x.scope==S)?.events??0,
  kev:ev.filter(e=>e.kev_cves.length).length};
 $("stats").innerHTML=["assets","scans","events","kev hits"].map(k=>`<div class="stat"><div class="n">${st[k.replace(" ","")]}</div><div class="l">${k}</div></div>`).join("");
 const mx=Math.max(1,...tl.scans.map(s=>s.assets));
 $("tl").innerHTML=tl.scans.map(s=>`<div class="bar" style="height:${Math.max(4,s.assets/mx*100)}%" title="${s.ts} · ${s.assets} assets"></div>`).join("");
 $("ev").innerHTML="<tr><th>when</th><th>sev</th><th>kind</th><th>asset</th></tr>"+
  ev.slice(0,60).map(e=>`<tr><td class="muted">${e.created_at.slice(5,16)}</td><td class="${sev(e.severity)[0]}">${sev(e.severity)[1]} ${e.severity}</td><td>${e.kind}</td><td>${e.asset_key}${e.kev_cves.length?' <span class="crit">KEV</span>':""}</td></tr>`).join("");
 $("vecs").innerHTML=vc.slice(0,10).map(v=>`<div class="vec ${sev(v.severity)[0]}"><b class="${sev(v.severity)[0]}">${sev(v.severity)[1]} ${v.severity}</b> <b>${v.asset}</b>${v.kev_cves.length?` · <span class="crit">KEV ${v.kev_cves.join(",")}</span>`:""}<div class="muted">${(v.techniques||[]).join(" · ")}</div></div>`).join("")||"<div class='muted'>no findings recorded</div>";
 const as=await api(`/api/assets?scope=${S}&kind=${kind}&q=${$("q").value}&limit=300`);
 $("as").innerHTML="<tr><th>asset</th><th>sources</th><th>conf</th><th>first seen</th></tr>"+
  as.map(a=>`<tr><td>${a.key}</td><td class="muted">${a.sources.join(",")}</td><td>${a.confidence}</td><td class="muted">${a.first_seen.slice(0,10)}</td></tr>`).join("");
}
for(const k of["subdomain","service","ip","domain"]){const t=document.createElement("div");t.className="tab"+(k==kind?" on":"");t.textContent=k;
 t.onclick=()=>{kind=k;document.querySelectorAll(".tab").forEach(x=>x.classList.remove("on"));t.classList.add("on");load()};$("tabs").append(t)}
$("scope").onchange=load;$("q").oninput=()=>load();
load();setInterval(load,30000);
</script></body></html>"""


def create_server(db_path: Path, bind: str = "127.0.0.1", port: int = 7777,
                  token: str = "") -> ThreadingHTTPServer:
    dash = Dash(db_path)

    class Handler(BaseHTTPRequestHandler):
        def _authed(self) -> bool:
            hdr = self.headers.get("Authorization", "")
            ok = hdr == f"Bearer {token}"
            if not ok:
                q = parse_qs(urlparse(self.path).query)
                ok = q.get("token", [""])[0] == token
            return ok

        def _send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _int_param(self, q: dict, name: str, default: int,
                       lo: int, hi: int) -> int | None:
            """Clamped integer query param; None signals a client error (400)."""
            raw = q.get(name, [str(default)])[0]
            try:
                v = int(raw)
            except ValueError:
                return None
            return max(lo, min(v, hi))

        def do_GET(self):
            if not self._authed():
                self._send(401, b"unauthorized", "text/plain")
                return
            u = urlparse(self.path)
            q = parse_qs(u.query)
            try:
                if u.path == "/":
                    self._send(200, PAGE.encode(), "text/html; charset=utf-8")
                elif u.path == "/api/scopes":
                    self._send(200, json.dumps(dash.scopes()).encode(),
                               "application/json")
                elif u.path == "/api/timeline":
                    self._send(200, json.dumps(dash.timeline(
                        q.get("scope", [""])[0])).encode(), "application/json")
                elif u.path == "/api/events":
                    lim = self._int_param(q, "limit", 100, 1, 1000)
                    if lim is None:
                        self._send(400, b'{"error": "limit must be an integer"}',
                                   "application/json")
                        return
                    self._send(200, json.dumps(dash.events(
                        q.get("scope", [""])[0], lim)).encode(),
                        "application/json")
                elif u.path == "/api/vectors":
                    self._send(200, json.dumps(dash.vectors(
                        q.get("scope", [""])[0])).encode(), "application/json")
                elif u.path == "/api/assets":
                    lim = self._int_param(q, "limit", 300, 1, 1000)
                    if lim is None:
                        self._send(400, b'{"error": "limit must be an integer"}',
                                   "application/json")
                        return
                    self._send(200, json.dumps(dash.assets(
                        q.get("scope", [""])[0], q.get("kind", ["subdomain"])[0],
                        q.get("q", [""])[0], lim)).encode(),
                        "application/json")
                else:
                    self._send(404, b"not found", "text/plain")
            except Exception as e:  # never leak stack traces; report cleanly
                self._send(500, json.dumps({"error": str(e)[:200]}).encode(),
                           "application/json")

        def log_message(self, fmt, *args):  # quiet default access log
            pass

    return ThreadingHTTPServer((bind, port), Handler)


def serve(db_path: Path, bind: str = "127.0.0.1", port: int = 7777) -> None:
    token = get_or_create_token()
    srv = create_server(db_path, bind, port, token)
    print(f"[*] athena dashboard · http://{bind}:{port}/?token={token}")
    print("[*] read-only · localhost-bound · Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] dashboard stopped")
    finally:
        srv.server_close()
