"""Unit tests — plain asserts, no test framework dependency.
Run: python tests/test_unit.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from athena.diff import diff_snapshots, material_diff
from athena.enrich import enrich_event, severity_label
from athena.normalize import Assets, build_assets
from athena.store import Store

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {extra}")


# ---------------------------------------------------------------- normalize
print("[normalize]")
a = Assets()
a.add("svc:vpn.x.com:443", "service", {"ip": "1.2.3.4", "product": "Citrix NetScaler"}, "shodan")
a.add("svc:vpn.x.com:443", "service", {"title": "VPN"}, "fofa")
lst = a.list()
check("merge keeps one asset", len(lst) == 1)
check("sources union", lst[0]["sources"] == ["shodan", "fofa"], lst[0]["sources"])
check("attrs union fills gap", lst[0]["attrs"].get("title") == "VPN")
check("confidence rises with corroboration", lst[0]["confidence"] == 65, lst[0]["confidence"])

# empty values must not clobber
a.add("svc:vpn.x.com:443", "service", {"title": ""}, "quake")
check("empty value does not clobber", a.by_key["svc:vpn.x.com:443"]["attrs"]["title"] == "VPN")

# in-scope hostname preferred over out-of-scope for identity
recs = [{"source": "shodan", "kind": "service", "ip": "9.9.9.9", "port": 443,
         "hostnames": ["cdn.other.net", "vpn.x.com"], "product": "x"}]
assets = build_assets(recs, "x.com", resolve=lambda hs: {h: [] for h in hs})
check("in-scope hostname wins identity",
      any(k == "svc:vpn.x.com:443" for k in assets.by_key), list(assets.by_key))

# dangling cname flag
recs2 = [{"source": "otx", "kind": "dns_record", "fqdn": "old.x.com",
          "type": "CNAME", "value": "gone.herokuapp.com"}]
def fake_resolve(hs):
    return {h: [] for h in hs}  # nothing resolves
assets2 = build_assets(recs2, "x.com", resolve=fake_resolve)
sub = assets2.by_key.get("sub:old.x.com")
check("dangling cname flagged", bool(sub and sub["attrs"].get("dangling")))

# ---------------------------------------------------------------- diff
print("[diff]")
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
    store = Store(Path(td) / "t.db")
    snap1 = [{"key": "sub:a.x.com", "kind": "subdomain", "attrs": {"a": ["1.1.1.1"]},
              "sources": ["crt.sh"], "first_seen": "t", "last_seen": "t", "confidence": 50},
             {"key": "sub:b.x.com", "kind": "subdomain", "attrs": {"a": ["2.2.2.2"]},
              "sources": ["crt.sh", "vt"], "first_seen": "t", "last_seen": "t", "confidence": 65}]
    store.upsert_assets(snap1)
    store.write_snapshot("x.com", snap1, "test")
    evs = diff_snapshots(store, "x.com", 1)
    check("baseline scan yields no events", evs == [])

    # scan 2: a.x.com changes IP, b disappears, c appears (2 sources)
    snap2 = [{"key": "sub:a.x.com", "kind": "subdomain", "attrs": {"a": ["3.3.3.3"]},
              "sources": ["crt.sh"], "first_seen": "t", "last_seen": "t2", "confidence": 50},
             {"key": "sub:c.x.com", "kind": "subdomain", "attrs": {"a": ["4.4.4.4"]},
              "sources": ["crt.sh", "otx"], "first_seen": "t2", "last_seen": "t2", "confidence": 65}]
    store.upsert_assets(snap2)
    sid2 = store.write_snapshot("x.com", snap2, "test")
    evs = diff_snapshots(store, "x.com", sid2)
    kinds = sorted(e["kind"] for e in evs)
    # young baseline: c is new vs baseline -> fires; b vanished -> held (grace)
    check("appeared (new vs baseline) + attr_changed fire; disappearance held",
          kinds == ["appeared", "attr_changed"], kinds)
    check("appeared asset is the new one",
          any(e["asset_key"] == "sub:c.x.com" for e in evs if e["kind"] == "appeared"))
    check("stable asset not falsely flagged",
          all(e["asset_key"] != "sub:a.x.com" for e in evs if e["kind"] == "appeared"))

    # scan 3: b.x.com still absent; disappearance needs 3 consecutive absences
    store.upsert_assets(snap2)
    sid3 = store.write_snapshot("x.com", snap2, "test")
    evs3 = diff_snapshots(store, "x.com", sid3)
    check("disappearance held after 2 absent scans",
          all(e["kind"] != "disappeared" for e in evs3), [e["kind"] for e in evs3])

    # scan 4: third consecutive absence -> disappearance fires
    store.upsert_assets(snap2)
    sid4 = store.write_snapshot("x.com", snap2, "test")
    evs4 = diff_snapshots(store, "x.com", sid4)
    check("disappearance fires after 3 absent scans",
          any(e["kind"] == "disappeared" and e["asset_key"] == "sub:b.x.com" for e in evs4),
          [e["kind"] for e in evs4])

    # dedup: re-run diff -> events re-derived but insert dedups
    evs2 = diff_snapshots(store, "x.com", sid2)
    stored = sum(store.insert_event("x.com", e["kind"], e["asset_key"], e["detail"],
                                    e["severity"], e["techniques"], e["kev_cves"]) for e in evs)
    stored_again = sum(store.insert_event("x.com", e["kind"], e["asset_key"], e["detail"],
                                          e["severity"], e["techniques"], e["kev_cves"]) for e in evs2)
    check("dedup blocks repeat events", stored_again == 0, f"{stored} then {stored_again}")

    # material_diff ignores volatile attrs
    md = material_diff({"last_seen": "t1", "a": ["1.1.1.1"]}, {"last_seen": "t2", "a": ["1.1.1.1"]})
    check("volatile attrs ignored", md == {})
    store.close()

# rotation-noise rules
print("[rotation]")
md = material_diff({"a": ["10.0.154.19"]}, {"a": ["10.0.155.19"]})
check("twin-IP flip (same /16 + host octet) suppressed", md == {})
md = material_diff({"a": ["10.0.154.19"]}, {"a": ["8.8.8.8"]})
check("genuine A-record change fires", "a" in md)
md = material_diff({"a": ["1.1.1.1", "2.2.2.2"]}, {"a": ["2.2.2.2", "1.1.1.1"]})
check("order-only change suppressed", md == {})
md = material_diff({"a": ["1.1.1.1", "2.2.2.2"]}, {"a": ["1.1.1.1", "3.3.3.3"]})
check("partial overlap rotation suppressed", md == {})

# ---------------------------------------------------------------- enrich
print("[enrich]")
kev_fake = {"CVE-2023-3519": {"vendor": "citrix", "product": "netscaler adc",
                              "ransomware": False, "note": "rce", "due": "2023-10-31"}}
ev = {"kind": "appeared", "asset_key": "svc:vpn.x.com:443", "asset_kind": "service",
      "severity": 3.0, "techniques": [],
      "detail": {"attrs": {"product": "Citrix NetScaler", "version": "13.0",
                           "cves": ["CVE-2023-3519", "CVE-2020-0001"]},
                 "sources": ["shodan", "fofa"]}}
ev = enrich_event(ev, kev_fake)
check("edge appliance maps to T1190", any("T1190" in t for t in ev["techniques"]), ev["techniques"])
check("KEV match detected", ev["kev_cves"] == ["CVE-2023-3519"])
check("severity boosted to critical-ish", ev["severity"] >= 9.0, ev["severity"])
check("claim language present", "consistent with" in ev["detail"]["claim"])

ev2 = {"kind": "appeared", "asset_key": "svc:x.com:3389", "asset_kind": "service",
       "severity": 3.0, "techniques": [],
       "detail": {"attrs": {"port": 3389}, "sources": ["shodan"]}}
ev2 = enrich_event(ev2, kev_fake)
check("RDP port maps to T1021.001", any("T1021.001" in t for t in ev2["techniques"]))

ev3 = {"kind": "appeared", "asset_key": "sub:old.x.com", "asset_kind": "subdomain",
       "severity": 3.0, "techniques": [],
       "detail": {"attrs": {"dangling": True, "cname": "gone.herokuapp.com"}, "sources": ["otx"]}}
ev3 = enrich_event(ev3, kev_fake)
check("dangling cname maps to T1583.001", any("T1583.001" in t for t in ev3["techniques"]))

check("severity labels sane",
      severity_label(9.1) == "CRITICAL" and severity_label(7.0) == "HIGH"
      and severity_label(5.0) == "MEDIUM" and severity_label(2.0) == "LOW")

# ---------------------------------------------------------------- provider fixtures
print("[provider parsers]  (mocked HTTP — recorded response shapes)")
import athena.providers as P


def with_mock(resp, fn):
    """Run fn with _req mocked to return (200, resp)."""
    real = P._req
    P._req = lambda *a, **k: (200, resp)
    try:
        return fn()
    finally:
        P._req = real

# shodan search — real shape captured from live run
shodan_resp = {"matches": [{
    "ip_str": "10.0.155.73", "port": 443, "transport": "tcp",
    "hostnames": ["example-corp.com"], "product": None, "version": None,
    "http": {"title": "Request Rejected", "server": None},
    "cpe": ["cpe:/a:f5:big-ip_application_security_manager"],
    "data": "HTTP/1.1 200 OK\r\nX-Frame-Options: SAMEORIGIN",
    "ssl": {"cert": {"subject": {"CN": "example-corp.com"}, "expires": 1793011200}},
}]}
recs, err = with_mock(shodan_resp, lambda: P.shodan_search("K", "example-corp.com"))
check("shodan parse", err is None and len(recs) == 1
      and recs[0]["ip"] == "10.0.155.73" and recs[0]["port"] == 443
      and recs[0]["cert_cn"] == "example-corp.com"
      and "f5:big-ip" in recs[0]["cpe"][0], err)

# otx passive dns — the shape the original bug missed (passive_dns key)
otx_resp = {"count": 2, "passive_dns": [
    {"hostname": "www.example-corp.com", "record_type": "A", "address": "10.0.154.20"},
    {"hostname": "old.example-corp.com", "record_type": "CNAME",
     "address": "gone.herokuapp.com."},
]}
recs, err = with_mock(otx_resp, lambda: P.otx_passive_dns("", "example-corp.com"))
kinds = {r["kind"] for r in recs}
cn = [r for r in recs if r["kind"] == "dns_record" and r["type"] == "CNAME"]
check("otx passive_dns key parsed (regression)", err is None
      and kinds == {"dns_record"} and len(cn) == 1
      and cn[0]["value"] == "gone.herokuapp.com", (err, kinds))
# (subdomain extraction only fires for non-A/CNAME hostnames — A/CNAME become dns_records)

# virustotal — free-tier limit=40 request, data[].id subdomains
vt_resp = {"data": [{"id": "portal.example-corp.com"}, {"id": "mail.example-corp.com"}]}
recs, err = with_mock(vt_resp, lambda: P.virustotal_subdomains("K", "example-corp.com"))
check("virustotal parse", err is None and len(recs) == 2
      and recs[0]["fqdn"] == "portal.example-corp.com", err)

# securitytrails — subdomains list of labels
st_resp = {"subdomains": ["vpn", "mail"]}
recs, err = with_mock(st_resp, lambda: P.securitytrails_subdomains("K", "example-corp.com"))
check("securitytrails parse", err is None and {r["fqdn"] for r in recs}
      == {"vpn.example-corp.com", "mail.example-corp.com"}, err)

# quake — code!=0 must surface an error, not crash
recs, err = with_mock({"code": 301, "message": "unauth"}, lambda: P.quake_search("K", "d"))
check("quake error surfaces", err is not None and recs == [])

# fofa — errmsg shape
recs, err = with_mock({"error": True, "errmsg": "unauthorized"},
                      lambda: P.fofa_search("K", "e@x.com", "d"))
check("fofa error surfaces", err is not None and recs == [])

# netlas (experimental) — documented items shape
netlas_resp = {"items": [{"ip": "1.2.3.4", "port": 443, "protocol": ["https"],
                          "hostname": "a.x.com",
                          "data": {"http": {"title": "T", "server": "nginx"}}}]}
recs, err = with_mock(netlas_resp, lambda: P.netlas_search("K", "x.com"))
check("netlas parse (experimental)", err is None and len(recs) == 1
      and recs[0]["proto"] == "https" and recs[0]["title"] == "T", err)

# zoomeye (experimental) — documented portinfo shape
zm_resp = {"items": [{"ip": "1.2.3.4", "portinfo": {"port": 8080, "service": "http",
                                                    "title": "J", "product": "Jetty"}}]}
recs, err = with_mock(zm_resp, lambda: P.zoomeye_search("K", "x.com"))
check("zoomeye parse (experimental)", err is None and len(recs) == 1
      and recs[0]["port"] == 8080 and recs[0]["product"] == "Jetty", err)

# ---------------------------------------------------------------- alert payloads
print("[alert payloads]  (mocked HTTP)")
import athena.alert as A

_captured = {}
def mock_req(url, method="GET", headers=None, body=None, **kw):
    _captured["url"], _captured["body"] = url, body
    return 204, ""

vecs = [{"asset": "svc:x:443", "kind": "service", "event": "appeared",
         "severity": 6.8, "label": "HIGH", "techniques": ["T1190 edge"],
         "kev_cves": ["CVE-2023-44487"], "attrs": {"product": "F5"},
         "notes": ["n1"], "sources": ["shodan"]}]

real_req = A._req
A._req = mock_req
try:
    ok, msg = A.send_discord("https://discord/wh", "x.com", vecs, {"assets": 10})
    body = _captured["body"]
    emb = body["embeds"][0]
    check("discord embed shape", ok and emb["color"] == 0xF5A524
          and emb["title"].startswith("ATHENA")
          and any("CVE-2023-44487" in f["value"] for f in emb["fields"]), msg)

    ok, msg = A.send_slack("https://slack/hook", "x.com", vecs, {"assets": 10})
    text = _captured["body"]["text"]
    check("slack payload shape", ok and "*HIGH 6.8*" in text
          and "CVE-2023-44487" in text and "`svc:x:443`" in text, msg)

    ok, msg = A.send_generic("https://gw/hook", "x.com", vecs, {"assets": 10})
    g = _captured["body"]
    check("generic payload shape", ok and g["tool"] == "athena"
          and g["findings"][0]["kev_cves"] == ["CVE-2023-44487"]
          and g["touch"] == "passive", msg)

    # severity floor: quiet vectors send nothing
    ok, msg = A.send_discord("https://discord/wh", "x.com",
                             [{**vecs[0], "severity": 2.0}], {})
    check("severity floor holds", ok and "nothing" in msg)
finally:
    A._req = real_req


# ---------------------------------------------------------------- dashboard
print("[dashboard]  (real HTTP server on ephemeral port, temp DB)")
import json as _json_dash
import tempfile
import threading
import urllib.error
import urllib.request

from athena.store import Store as _Store
from athena.web import create_server

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
    _s = _Store(Path(td) / "w.db")
    _snap = [{"key": "sub:a.x.com", "kind": "subdomain", "attrs": {"a": ["1.1.1.1"]},
              "sources": ["crt.sh"], "first_seen": "t", "last_seen": "t", "confidence": 50},
             {"key": "svc:a.x.com:443", "kind": "service", "attrs": {"product": "nginx"},
              "sources": ["shodan"], "first_seen": "t", "last_seen": "t", "confidence": 50}]
    _s.upsert_assets(_snap)
    _s.write_snapshot("x.com", _snap, "test")
    _s.insert_event("x.com", "appeared", "svc:a.x.com:443",
                    {"attrs": {"product": "nginx"}, "sources": ["shodan"]},
                    6.8, ["T1190 edge"], [])
    _s.close()
    _srv = create_server(Path(td) / "w.db", "127.0.0.1", 0, "TESTTOKEN")
    _port = _srv.server_address[1]
    threading.Thread(target=_srv.serve_forever, daemon=True).start()
    _base = f"http://127.0.0.1:{_port}"

    def _get(path, token=None):
        req = urllib.request.Request(_base + path)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    _st, _ = _get("/api/scopes")
    check("dashboard: no token -> 401", _st == 401)
    _st, _ = _get("/api/scopes", token="WRONG")
    check("dashboard: wrong token -> 401", _st == 401)
    _st, _b = _get("/api/scopes", token="TESTTOKEN")
    _js = _json_dash.loads(_b)
    check("dashboard: scopes api shape", _st == 200 and _js[0]["scope"] == "x.com"
          and _js[0]["scans"] == 1 and _js[0]["events"] == 1, _js)
    _st, _b = _get("/api/vectors?scope=x.com", token="TESTTOKEN")
    _js = _json_dash.loads(_b)
    check("dashboard: vectors api shape", _st == 200 and _js
          and _js[0]["asset"] == "svc:a.x.com:443" and _js[0]["label"] == "HIGH", _js[:1])
    _st, _b = _get("/api/assets?scope=x.com&kind=subdomain", token="TESTTOKEN")
    _js = _json_dash.loads(_b)
    check("dashboard: assets api (subdomain)", _st == 200 and len(_js) == 1
          and _js[0]["sources"] == ["crt.sh"], _js)
    _st, _b = _get("/api/assets?scope=x.com&kind=service", token="TESTTOKEN")
    _js = _json_dash.loads(_b)
    check("dashboard: assets api (service via snapshot membership)",
          _st == 200 and len(_js) == 1 and _js[0]["key"] == "svc:a.x.com:443", _js)
    _st, _b = _get("/", token="TESTTOKEN")
    check("dashboard: page served", _st == 200 and b"ATH" in _b)
    _st, _ = _get("/nope", token="TESTTOKEN")
    check("dashboard: 404 for unknown route", _st == 404)
    _srv.shutdown()
    _srv.server_close()


# ---------------------------------------------------------------- standing conditions
print("[standing conditions]  (cert + domain expiry)")
from datetime import datetime as _dt
from datetime import timedelta as _td
from datetime import timezone as _tz

from athena.enrich import standing_events as _sev

_now = _dt.now(_tz.utc)
def _svc(exp):
    return {"key": "svc:x.com:443", "kind": "service",
            "attrs": {"cert_expires": exp}, "sources": ["shodan"]}

evs = _sev([_svc((_now + _td(days=5)).timestamp())])
check("cert expiring in 5d -> MEDIUM-tier event",
      len(evs) == 1 and evs[0]["kind"] == "cert_expiry" and 5.0 < evs[0]["severity"] <= 5.5,
      evs)
evs = _sev([_svc((_now + _td(days=60)).isoformat())])
check("cert 60d out -> no event", evs == [])
evs = _sev([_svc((_now - _td(days=3)).timestamp())])
check("cert EXPIRED -> HIGH phishing-enabler",
      len(evs) == 1 and evs[0]["severity"] == 7.5 and "phishing" in evs[0]["detail"]["notes"][0],
      evs)
evs = _sev([_svc("not-a-date")])
check("unparseable expiry ignored", evs == [])

_dmg = {"key": "dom:x.com", "kind": "domain",
        "attrs": {"expiry": (_now + _td(days=10)).date().isoformat()}, "sources": ["rdap"]}
evs = _sev([_dmg])
check("domain expiry 10d -> MEDIUM watch",
      len(evs) == 1 and evs[0]["kind"] == "domain_expiry" and evs[0]["severity"] == 4.5, evs)
_dmg2 = {"key": "dom:x.com", "kind": "domain",
         "attrs": {"expiry": (_now - _td(days=2)).date().isoformat()}, "sources": ["rdap"]}
evs = _sev([_dmg2])
check("domain EXPIRED -> HIGH + T1583.001 drop-catch",
      len(evs) == 1 and evs[0]["severity"] == 8.2
      and any("T1583.001" in t for t in evs[0]["techniques"]), evs)
# dedup material embeds expiry: renewal creates a NEW one-shot event
e1 = _sev([_svc((_now + _td(days=5)).timestamp())])[0]
check("cert event material embeds expiry date", "cert:" in e1["material"], e1["material"])

# rdap fixture (mocked)
rdap_resp = {"events": [{"eventAction": "registration", "eventDate": "2005-01-01T00:00:00Z"},
                        {"eventAction": "expiration", "eventDate": "2027-05-30T00:00:00Z"}],
             "status": ["active", "client transfer prohibited"]}
recs, err = with_mock(rdap_resp, lambda: P.rdap_domain("x.com"))
check("rdap parse: expiry + status extracted",
      err is None and len(recs) == 1 and recs[0]["expiry"].startswith("2027-05-30")
      and "active" in recs[0]["status"], (err, recs))
recs, err = with_mock({"events": []}, lambda: P.rdap_domain("x.com"))
check("rdap without expiry -> clean empty", err is None and recs == [])

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
