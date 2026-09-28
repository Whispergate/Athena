"""Athena CLI — doctor / scan / watch / events / report.

Run installed (`athena`), as a module (`python -m athena`), or from source.
All state lives in ATHENA_HOME (~/.athena) — never inside the repo.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time

from . import __version__, alert, config
from . import report as rep
from .diff import diff_snapshots
from .enrich import (
    ATTACK_TABLE,
    _fingerprint,
    enrich_event,
    load_kev,
    severity_label,
    standing_events,
)
from .normalize import build_assets, utcnow
from .paths import DB_PATH, OUT_DIR
from .paths import ensure as ensure_paths
from .providers import _req, collect_all, internetdb, resolve_many
from .store import Store

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass


def cmd_doctor(args):
    config.load_env()
    ensure_paths()
    print(f"athena v{__version__} · python {sys.version.split()[0]}")
    print("providers:")
    for name, ok, note in config.provider_status():
        mark = "OK " if ok else "-- "
        print(f"  [{mark}] {name:<16} {note}")
    key = config.get("SHODAN_API_KEY")
    if key:
        st, js = _req(f"https://api.shodan.io/api-info?key={key}")
        if st == 200 and isinstance(js, dict):
            print(f"  shodan account: plan={js.get('plan')} query_credits={js.get('query_credits')}")
        else:
            print(f"  shodan api-info: HTTP {st} {str(js)[:100]}")
    st, js = _req("https://internetdb.shodan.io/1.1.1.1", retries=1)
    print(f"  internetdb ping: HTTP {st}" + (" ok" if st == 200 else f" {str(js)[:80]}"))
    kev = load_kev()
    print(f"  CISA KEV catalog: {len(kev)} entries cached")
    wh = config.get("DISCORD_WEBHOOK")
    print(f"  discord webhook: {'configured' if wh else 'not set'}")
    print(f"  state dir: {DB_PATH.parent}")


def _mask(records) -> str:
    return ",".join(sorted({r["source"].split("-")[0] for r in records}))


def _load_extra_subs(path_str: str, scope: str) -> list[dict]:
    """Ingest external tool output (subfinder JSON-lines or plain hosts)."""
    from pathlib import Path

    path = Path(path_str)
    if not path.exists():
        print(f"[!] extra-subs file not found: {path}")
        return []
    n = 0
    records = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            host = json.loads(line).get("host", "").lower().strip(".")
        except ValueError:
            host = line.lower().strip(".")
        if host.endswith(scope):
            records.append({"source": "subfinder", "kind": "subdomain", "fqdn": host})
            n += 1
    print(f"[+] subfinder ingest: {n} hosts from {path.name}")
    return records


def run_scan(scope: str, do_alert: bool = True, extra_subs: str | None = None) -> dict:
    """One full scan cycle: collect -> normalize -> snapshot -> diff -> enrich
    -> report -> alert. Returns a summary dict."""
    config.load_env()
    ensure_paths()
    scope = scope.lower().strip()
    print(f"[*] athena scan · scope={scope} · touch=passive (+recursive DNS)")
    print("[*] collecting from third-party databases (0 packets to target)...")
    records, errors = collect_all(scope, progress=lambda m: print(m))

    if extra_subs:
        records.extend(_load_extra_subs(extra_subs, scope))

    def enrich_ip(ip):
        return internetdb(ip)

    store = Store(DB_PATH)
    prior_ips = [r["key"].split(":", 1)[1] for r in store.conn.execute(
        "SELECT key FROM assets WHERE kind='ip'")]
    assets = build_assets(records, scope, resolve=resolve_many, enrich_ip=enrich_ip,
                          extra_ips=prior_ips)
    asset_list = assets.list()
    stats = {
        "records": len(records),
        "assets": len(asset_list),
        "subdomains": sum(1 for a in asset_list if a["kind"] == "subdomain"),
        "services": sum(1 for a in asset_list if a["kind"] == "service"),
        "ips": sum(1 for a in asset_list if a["kind"] == "ip"),
        "providers_ok": len({r["source"] for r in records}),
    }
    print(f"[*] normalized: {stats['assets']} assets "
          f"({stats['subdomains']} subdomains · {stats['services']} services · {stats['ips']} ips)")

    store.upsert_assets(asset_list)
    snap_id = store.write_snapshot(scope, asset_list, _mask(records))

    events = diff_snapshots(store, scope, snap_id)
    print(f"[*] snapshot #{snap_id} · diff: {len(events)} raw event(s)")

    # standing conditions (cert/domain expiry) — true now, not scan-to-scan
    standing = standing_events(asset_list)
    if standing:
        print(f"[*] standing conditions: {len(standing)} expiry finding(s)")
        events = events + standing

    kev = load_kev()

    # baseline observations: standing exposures worth operator attention even
    # with no diff events (first run). Stored once — dedup prevents re-alerting.
    # IP-level matches are aggregated per /24 so an edge-device fleet reads as
    # one finding instead of fifty identical rows.
    if not events:
        import re as _re
        groups: dict[tuple, list[str]] = {}
        singles = []
        for a in asset_list:
            if a["kind"] not in ("service", "ip"):
                continue
            fp = _fingerprint(a)
            cls = next((name for pat, _t, name, _s in ATTACK_TABLE
                        if _re.search(pat, fp)), None)
            cves = a["attrs"].get("cves") or []
            risky_port = str(a["key"]).rsplit(":", 1)[-1] in ("3389", "5900", "445", "23")
            if a["kind"] == "ip" and cls and not cves:
                ip = a["key"].split(":", 1)[1]
                pref = ".".join(ip.split(".")[:3]) + ".0/24"
                groups.setdefault((cls, pref), []).append(ip)
            elif cls or cves or risky_port:
                singles.append(a)
        observed = []
        for a in singles:
            observed.append({
                "kind": "observed", "asset_key": a["key"], "asset_kind": a["kind"],
                "severity": 3.0, "techniques": [], "kev_cves": [],
                "detail": {"attrs": a["attrs"], "sources": a["sources"]},
                "material": "baseline",
            })
        for (cls, pref), ips in sorted(groups.items()):
            observed.append({
                "kind": "observed", "asset_key": f"range:{pref}", "asset_kind": "netblock",
                "severity": 3.0, "techniques": [], "kev_cves": [],
                "detail": {"attrs": {"product": cls, "host_count": len(ips),
                                     "ips_sample": ips[:5]},
                           "sources": ["internetdb", "shodan"]},
                "material": f"baseline|{cls}|{pref}",
            })
        events = observed
        print(f"[*] baseline scan: {len(observed)} notable standing exposure(s) "
              f"({len(groups)} aggregated netblock group(s))")

    enriched = [enrich_event(ev, kev) for ev in events]
    fired = []
    for ev in enriched:
        if store.insert_event(scope, ev["kind"], ev["asset_key"], ev["detail"],
                              ev["severity"], ev["techniques"], ev["kev_cves"]):
            fired.append(ev)
    dupes = len(enriched) - len(fired)
    if dupes:
        print(f"[*] {dupes} duplicate event(s) suppressed by dedup")
    enriched = fired  # alert/report only genuinely new findings

    stats["events_new"] = len(fired)
    stats["kev_hits"] = sum(1 for ev in fired if ev["kev_cves"])

    vectors = rep.entry_vectors(fired)
    ts = utcnow()
    print()
    print(rep.terminal(scope, stats, vectors, errors))

    md, js = rep.write_files(OUT_DIR, scope, stats, vectors, errors, ts, assets=asset_list)
    print(f"\n[*] full dossier (system of record): {md}")
    print(f"[*] hand-off json: {js}")

    if do_alert:
        for name, ok, msg in alert.dispatch(scope, vectors, stats):
            print(f"[*] {name}: {msg}" if ok else f"[!] {name} alert failed: {msg}")

    store.close()
    return {"stats": stats, "vectors": vectors, "dossier": str(md)}


def cmd_scan(args):
    run_scan(args.scope, do_alert=not args.no_alert, extra_subs=args.extra_subs)


# ---------------------------------------------------------------- scopes file

def _parse_scopes_yaml(text: str) -> list[dict]:
    """Minimal parser for the documented scopes-file subset:
    top-level `scopes:` with `- key: value` items; values are scalars or
    [comma, lists]. Deliberately stdlib-only (no yaml dependency)."""
    scopes: list[dict] = []
    cur: dict | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        s = line.strip()
        if s == "scopes:":
            continue
        if s.startswith("- "):
            cur = {}
            scopes.append(cur)
            s = s[2:]
        elif cur is None:
            continue
        if ":" in s:
            k, _, v = s.partition(":")
            k, v = k.strip(), v.strip()
            if v.startswith("[") and v.endswith("]"):
                v = [x.strip().strip("\"'") for x in v[1:-1].split(",") if x.strip()]
            cur[k] = v
    return scopes


def _load_scopes_file(path_str: str) -> list[dict]:
    from pathlib import Path

    path = Path(path_str)
    if not path.exists():
        sys.exit(f"[!] scopes file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    scopes = (json.loads(text).get("scopes", []) if path.suffix == ".json"
              else _parse_scopes_yaml(text))
    if not scopes:
        sys.exit(f"[!] no scopes parsed from {path}")
    for s in scopes:
        s.setdefault("domains", [])
        s.setdefault("interval_min", 60)
        s.setdefault("name", s["domains"][0] if s["domains"] else "unnamed")
    return scopes


def cmd_watch(args):
    """Monitoring mode: per-scope schedules until stopped."""
    if args.config:
        scopes = _load_scopes_file(args.config)
        print(f"[*] watch · {len(scopes)} scope(s) from {args.config}")
    else:
        scopes = [{"name": args.scope, "domains": [args.scope],
                   "interval_min": args.interval_min}]

    now = time.time()
    next_run = {s["name"]: now for s in scopes}
    cycle = 0
    try:
        while True:
            now = time.time()
            for s in scopes:
                if next_run[s["name"]] > now:
                    continue
                cycle += 1
                role = f" · role={s['role']}" if s.get("role") else ""
                print(f"\n===== watch cycle {cycle} · scope {s['name']}{role} · {utcnow()} =====")
                for domain in s["domains"]:
                    run_scan(domain, do_alert=not args.no_alert, extra_subs=args.extra_subs)
                interval = max(60, int(s["interval_min"]) * 60)
                if args.jitter:
                    interval += random.randint(-interval // 10, interval // 10)
                next_run[s["name"]] = time.time() + interval
            wait = max(1.0, min(next_run.values()) - time.time())
            m, sec = int(wait // 60), int(wait % 60)
            print(f"[*] next scan in {m}m{sec:02d}s — Ctrl+C to stop")
            time.sleep(min(wait, 60))
    except KeyboardInterrupt:
        print("\n[*] watch stopped")


def cmd_events(args):
    config.load_env()
    store = Store(DB_PATH)
    evs = store.events(args.scope, args.since)
    if not evs:
        print("[]" if args.json else "no events stored")
        return
    if args.json:
        out = []
        for e in evs:
            e = dict(e)
            e["techniques"] = json.loads(e.pop("techniques") or "[]")
            e["kev_cves"] = json.loads(e.pop("kev_cves") or "[]")
            out.append(e)
        print(json.dumps(out, indent=2, default=str))
        return
    print(f"{len(evs)} event(s):")
    for e in evs:
        tech = ", ".join(json.loads(e["techniques"] or "[]"))
        kev = ", ".join(json.loads(e["kev_cves"] or "[]"))
        print(f" {e['created_at']} {severity_label(e['severity']):<8} {e['severity']:<4} "
              f"{e['kind']:<13} {e['asset_key']}"
              + (f" · KEV {kev}" if kev else "") + (f" · {tech}" if tech else ""))


def cmd_report(args):
    config.load_env()
    store = Store(DB_PATH)
    evs = store.events(args.scope)
    assets_by_key = {}
    for e in evs:
        if e["asset_key"] not in assets_by_key:
            a = store.asset(e["asset_key"])
            if a:
                assets_by_key[e["asset_key"]] = a
    vectors = rep.entry_vectors(evs, assets_by_key)
    stats = {"assets": len(assets_by_key)}
    ts = utcnow()
    if args.format == "json":
        print(json.dumps(rep.to_json(args.scope, vectors, ts), indent=2, default=str))
    else:
        print(rep.markdown(args.scope, stats, vectors, [], ts))


def cmd_export(args):
    """Export the asset registry + event timeline as a JSON feed
    (IntelliBird-ingestible: assets, IOCs, events)."""
    config.load_env()
    ensure_paths()
    store = Store(DB_PATH)
    scope = args.scope.lower().strip()
    scoped = []
    for row in store.conn.execute("SELECT * FROM assets ORDER BY key"):
        a = dict(row)
        # keep assets whose key is in-scope (subdomains of the domain, or linked
        # via stored snapshots of this scope)
        if a["kind"] == "subdomain" and (a["key"][4:] == scope
                                         or a["key"][4:].endswith("." + scope)):
            scoped.append(a)
        elif a["kind"] in ("service", "ip"):
            snap_hit = store.conn.execute(
                "SELECT 1 FROM snapshot_assets sa JOIN snapshots s ON sa.snap_id=s.id "
                "WHERE s.scope=? AND sa.asset_key=? LIMIT 1", (scope, a["key"])).fetchone()
            if snap_hit:
                scoped.append(a)
    import json as _json
    payload = {
        "tool": "athena", "scope": scope, "generated": utcnow(), "touch": "passive",
        "assets": [{
            "kind": a["kind"], "value": a["key"].split(":", 1)[1],
            "first_seen": a["first_seen"], "last_seen": a["last_seen"],
            "confidence": a["confidence"], "sources": _json.loads(a["sources_json"]),
            "attrs": _json.loads(a["attrs_json"]),
        } for a in scoped],
        "iocs": sorted(
            ({a["key"][4:]: {"type": "domain", "value": a["key"][4:]}
              for a in scoped if a["kind"] == "subdomain"}
             | {a["key"][3:]: {"type": "ip", "value": a["key"][3:]}
                for a in scoped if a["kind"] == "ip"}).values(),
            key=lambda d: d["value"]),
        "events": [{k: e[k] for k in ("kind", "asset_key", "severity", "created_at")}
                   | {"techniques": _json.loads(e["techniques"] or "[]"),
                      "kev_cves": _json.loads(e["kev_cves"] or "[]")}
                   for e in store.events(scope)],
    }
    out = OUT_DIR / f"{scope}-export.json"
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"[*] export: {out} · {len(payload['assets'])} assets · "
          f"{len(payload['iocs'])} iocs · {len(payload['events'])} events")
    store.close()


def cmd_handoff(args):
    """Emit the versioned Erebus hand-off contract (entry-vectors JSON)."""
    config.load_env()
    ensure_paths()
    store = Store(DB_PATH)
    scope = args.scope.lower().strip()
    evs = store.events(scope)
    assets_by_key = {}
    for e in evs:
        if e["asset_key"] not in assets_by_key:
            a = store.asset(e["asset_key"])
            if a:
                assets_by_key[e["asset_key"]] = a
    vectors = [v for v in rep.entry_vectors(evs, assets_by_key)
               if v["severity"] >= args.min_severity]
    vectors = rep.dedupe_vectors(vectors)
    payload = rep.handoff_payload(scope, vectors, utcnow(), __version__)
    out = OUT_DIR / f"{scope}-handoff.json"
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(json.dumps(payload, indent=2, default=str))
    print(f"\n[*] hand-off written: {out} · {len(vectors)} vector(s) >= "
          f"{args.min_severity}", file=sys.stderr)
    store.close()


def cmd_serve(args):
    """Read-only web dashboard (localhost + token auth)."""
    from .web import serve

    config.load_env()
    ensure_paths()
    serve(DB_PATH, bind=args.bind, port=args.port)


def main():
    p = argparse.ArgumentParser(prog="athena",
                                description="passive external attack-surface intelligence")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="check providers, keys, KEV feed, state dir")

    s = sub.add_parser("scan", help="passive scan of a scope")
    s.add_argument("--scope", required=True, help="domain, e.g. example-corp.com")
    s.add_argument("--no-alert", action="store_true", help="skip discord alert")
    s.add_argument("--extra-subs", help="subfinder JSON-lines or plain host list to ingest")

    w = sub.add_parser("watch", help="monitoring mode: rescan scopes on schedules")
    w.add_argument("--config", help="scopes.yaml / scopes.json with per-scope schedules")
    w.add_argument("--scope", help="single-scope convenience (no config file)")
    w.add_argument("--interval-min", type=int, default=60, help="minutes between scans")
    w.add_argument("--jitter", action="store_true", help="randomize intervals +-10%%")
    w.add_argument("--no-alert", action="store_true")
    w.add_argument("--extra-subs")

    e = sub.add_parser("events", help="list stored events")
    e.add_argument("--scope")
    e.add_argument("--since")
    e.add_argument("--json", action="store_true", help="emit JSON (scripting)")

    r = sub.add_parser("report", help="regenerate report from stored events")
    r.add_argument("--scope", required=True)
    r.add_argument("--format", choices=["md", "json"], default="md")

    x = sub.add_parser("export", help="export assets/IOCs/events as a JSON feed")
    x.add_argument("--scope", required=True)

    h = sub.add_parser("handoff", help="emit the Erebus entry-vectors contract")
    h.add_argument("--scope", required=True)
    h.add_argument("--min-severity", type=float, default=4.0)

    v = sub.add_parser("serve", help="read-only web dashboard (localhost + token)")
    v.add_argument("--port", type=int, default=7777)
    v.add_argument("--bind", default="127.0.0.1")

    args = p.parse_args()
    if args.cmd == "watch" and not args.config and not args.scope:
        p.error("watch needs --config or --scope")
    {"doctor": cmd_doctor, "scan": cmd_scan, "watch": cmd_watch, "events": cmd_events,
     "report": cmd_report, "export": cmd_export,
     "serve": cmd_serve, "handoff": cmd_handoff}[args.cmd](args)


if __name__ == "__main__":
    main()
