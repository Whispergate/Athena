"""Reporters: terminal summary, full-log Markdown dossier, JSON hand-off.

The .md dossier is the system of record: every event and every asset is
logged in full tables. The Discord alert is just the pager — it summarizes.
"""
from __future__ import annotations

import json
from pathlib import Path

from .enrich import severity_label


def _label(sev: float) -> str:
    return severity_label(sev)


def _as_list(v) -> list:
    """Events arrive in-memory (lists) or from the DB (JSON strings)."""
    if v is None:
        return []
    if isinstance(v, str):
        try:
            return json.loads(v)
        except (ValueError, TypeError):
            return []
    return v


def entry_vectors(events: list[dict], assets_by_key: dict[str, dict] | None = None) -> list[dict]:
    """Ranked hypotheses from events (and notable standing assets)."""
    rows = []
    for ev in events:
        a = (assets_by_key or {}).get(ev["asset_key"], {})
        detail = ev.get("detail") or {}
        if not detail and ev.get("detail_json"):
            try:
                detail = json.loads(ev["detail_json"])
            except (ValueError, TypeError):
                detail = {}
        rows.append({
            "asset": ev["asset_key"], "kind": ev.get("asset_kind") or a.get("kind", ""),
            "event": ev["kind"], "severity": ev["severity"],
            "label": _label(ev["severity"]),
            "techniques": _as_list(ev.get("techniques")),
            "kev_cves": _as_list(ev.get("kev_cves")),
            "attrs": detail.get("attrs") or a.get("attrs", {}),
            "notes": detail.get("notes", []),
            "sources": detail.get("sources") or a.get("sources", []),
        })
    rows.sort(key=lambda r: -r["severity"])
    return rows


def terminal(scope: str, stats: dict, vectors: list[dict], errors: list[tuple[str, str]]) -> str:
    lines = []
    lines.append(f"ATHENA v0.1 · scope {scope} · touch=passive (+recursive DNS) · 0 packets to target")
    lines.append(f"assets: {stats.get('assets', 0)} · records merged: {stats.get('records', 0)} "
                 f"· subdomains: {stats.get('subdomains', 0)} · services: {stats.get('services', 0)}")
    lines.append(f"new events: {stats.get('events_new', 0)}"
                 + (f" · KEV hits: {stats.get('kev_hits', 0)}" if stats.get("kev_hits") else "")
                 + f" · providers ok: {stats.get('providers_ok', 0)}"
                 + (f" · degraded: {', '.join(n for n, _ in errors)}" if errors else ""))
    lines.append("")
    if vectors:
        lines.append("RANKED ENTRY VECTORS (hypotheses — verify before relying)")
        for i, v in enumerate(vectors[:10], 1):
            attrs = v.get("attrs") or {}
            prod = attrs.get("product") or attrs.get("server") or attrs.get("title") or ""
            kev = f" · KEV: {', '.join(v['kev_cves'])}" if v["kev_cves"] else ""
            lines.append(f" {i}. {v['label']} {v['severity']:<4} {v['asset']}"
                         + (f" · {prod}" if prod else "") + kev)
            for t in v["techniques"][:2]:
                lines.append(f"      -> {t}")
        if len(vectors) > 10:
            lines.append(f" ...and {len(vectors) - 10} more — full log in the .md dossier")
    else:
        lines.append("No new events this scan (perimeter unchanged).")
    return "\n".join(lines)


# ---------------------------------------------------------------- markdown

def _md_escape(s) -> str:
    return str(s).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def _tbl(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(_md_escape(c) for c in r) + " |")
    return "\n".join(out)


def markdown(scope: str, stats: dict, vectors: list[dict], errors: list, ts: str,
             assets: list[dict] | None = None) -> str:
    assets = assets or []
    subdomains = [a for a in assets if a["kind"] == "subdomain"]
    services = [a for a in assets if a["kind"] == "service"]
    ips = [a for a in assets if a["kind"] == "ip"]

    L = [f"# ATHENA — Targeting Dossier — `{scope}`", ""]
    L.append(f"*generated {ts} · touch = passive (+recursive DNS) · 0 packets to target*  ")
    L.append("*claim language: consistent-with (passive banner data) — verify before relying*")
    L.append("")

    # executive summary
    L.append("## Executive summary")
    L.append("")
    L.append(_tbl(["metric", "value"], [
        ["assets tracked", stats.get("assets", len(assets))],
        ["subdomains", stats.get("subdomains", len(subdomains))],
        ["services", stats.get("services", len(services))],
        ["ip enrichments", stats.get("ips", len(ips))],
        ["raw records merged", stats.get("records", "?")],
        ["providers ok", stats.get("providers_ok", "?")],
        ["new events this scan", stats.get("events_new", "?")],
        ["KEV hits (this scan)", stats.get("kev_hits", 0)],
    ]))
    L.append("")

    # ranked entry vectors — full detail
    if vectors:
        L.append("## Ranked entry vectors")
        L.append("")
        L.append("*Hypotheses for operator verification — not verified vulnerabilities.*")
        L.append("")
        for i, v in enumerate(vectors, 1):
            attrs = v.get("attrs") or {}
            L.append(f"### {i}. [{v['label']} {v['severity']}] `{v['asset']}`")
            L.append("")
            rows = [["event", v["event"]], ["kind", v["kind"]]]
            for k in ("product", "version", "server", "title", "banner",
                      "host_count", "ips_sample"):
                if attrs.get(k):
                    val = str(attrs[k])
                    rows.append([k, val[:120] + "…" if len(val) > 120 else val])
            if v["techniques"]:
                rows.append(["techniques", "; ".join(v["techniques"])])
            if v["kev_cves"]:
                rows.append(["KEV", ", ".join(v["kev_cves"])])
            if v.get("sources"):
                rows.append(["sources", ", ".join(map(str, v["sources"]))])
            for n in (v.get("notes") or []):
                rows.append(["note", n])
            L.append(_tbl(["field", "value"], rows))
            L.append("")
    else:
        L.append("## Ranked entry vectors")
        L.append("")
        L.append("*No new events this scan — perimeter unchanged since last snapshot.*")
        L.append("")

    # full event log (everything that fired this scan)
    if vectors:
        L.append("## Event log (this scan, complete)")
        L.append("")
        L.append(_tbl(
            ["#", "severity", "kind", "asset", "techniques", "KEV"],
            [[i, f"{v['label']} {v['severity']}", v["event"], v["asset"],
              "; ".join(t.split(" ")[0] for t in v["techniques"]),
              ", ".join(v["kev_cves"])]
             for i, v in enumerate(vectors, 1)]))
        L.append("")

    # full asset inventory
    L.append("## Asset inventory (complete)")
    L.append("")

    domains = [a for a in assets if a["kind"] == "domain"]
    if domains:
        L.append(f"### Domains ({len(domains)})")
        L.append("")
        L.append(_tbl(["domain", "reg. expiry", "status", "sources"],
                      [[a["key"][4:], a["attrs"].get("expiry", "—"),
                        ", ".join(a["attrs"].get("status") or []) or "—",
                        ", ".join(a["sources"])] for a in domains]))
        L.append("")

    L.append(f"### Subdomains ({len(subdomains)})")
    L.append("")
    if subdomains:
        L.append(_tbl(["fqdn", "a records", "cname", "sources", "conf", "flags"],
                      [[a["key"][4:],
                        ", ".join(a["attrs"].get("a") or []) or "—",
                        a["attrs"].get("cname", "—"),
                        ", ".join(a["sources"]),
                        a["confidence"],
                        "**dangling**" if a["attrs"].get("dangling") else ""]
                       for a in subdomains]))
    else:
        L.append("*none recorded*")
    L.append("")

    L.append(f"### Services ({len(services)})")
    L.append("")
    if services:
        L.append(_tbl(["endpoint", "product", "version", "server", "title",
                       "cert cn", "sources"],
                      [[a["key"][4:],
                        a["attrs"].get("product", "—"),
                        a["attrs"].get("version", "—"),
                        a["attrs"].get("server", "—"),
                        (a["attrs"].get("title") or "—")[:60],
                        a["attrs"].get("cert_cn", "—"),
                        ", ".join(a["sources"])]
                       for a in services]))
    else:
        L.append("*none recorded*")
    L.append("")

    L.append(f"### IP enrichment ({len(ips)})")
    L.append("")
    if ips:
        L.append(_tbl(["ip", "open ports", "cves", "kev", "cpes"],
                      [[a["key"][3:],
                        ", ".join(map(str, a["attrs"].get("open_ports") or [])) or "—",
                        len(a["attrs"].get("cves") or []),
                        ", ".join(c for c in (a["attrs"].get("cves") or [])
                                  if c in _KEV_SET()) or "—",
                        ", ".join((a["attrs"].get("cpes") or [])[:2]) or "—"]
                       for a in ips]))
    else:
        L.append("*none recorded*")
    L.append("")

    # coverage mask
    L.append("## Coverage mask")
    L.append("")
    ok_list = ", ".join(f"`{n}` ✓" for n, ok, _ in _PROVIDERS() if ok)
    bad_list = ", ".join(f"`{n}` ✗" for n, ok, _ in _PROVIDERS() if not ok)
    L.append(f"- configured: {ok_list or '—'}")
    L.append(f"- missing/skipped: {bad_list or 'none'}")
    if errors:
        L.append("- degraded this scan: " + ", ".join(f"`{n}` ({e[:60]})" for n, e in errors))
    L.append("")

    L.append("---")
    L.append("*Athena is for authorized testing, education, and research. Findings are "
             "passive hypotheses, not verified vulnerabilities. BSD-2-Clause — the license "
             "does not override this disclaimer.*")
    return "\n".join(L)


# small caches so tables don't re-load provider/KEV state per row
_PROVIDERS_CACHE = None
_KEV_CACHE = None


def _PROVIDERS():
    global _PROVIDERS_CACHE
    if _PROVIDERS_CACHE is None:
        from . import config
        config.load_env()
        _PROVIDERS_CACHE = config.provider_status()
    return _PROVIDERS_CACHE


def _KEV_SET():
    global _KEV_CACHE
    if _KEV_CACHE is None:
        from .enrich import load_kev
        _KEV_CACHE = set(load_kev().keys())
    return _KEV_CACHE


def to_json(scope: str, vectors: list[dict], ts: str) -> dict:
    """The Erebus hand-off shape."""
    return {
        "tool": "athena", "version": "0.1.0", "scope": scope, "generated": ts,
        "touch": "passive",
        "entry_vectors": [
            {"rank": i, "asset": v["asset"], "kind": v["kind"], "severity": v["severity"],
             "techniques": [t.split(" ")[0] for t in v["techniques"]],
             "kev_cves": v["kev_cves"], "attrs": v["attrs"]}
            for i, v in enumerate(vectors, 1)
        ],
    }


def write_files(out_dir: Path, scope: str, stats: dict, vectors: list[dict],
                errors: list, ts: str, assets: list[dict] | None = None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = ts.replace(":", "").replace("-", "")[:15]
    md = out_dir / f"{scope}-{stamp}.md"
    js = out_dir / f"{scope}-{stamp}.json"
    md.write_text(markdown(scope, stats, vectors, errors, ts, assets=assets),
                  encoding="utf-8")
    js.write_text(json.dumps(to_json(scope, vectors, ts), indent=2, default=str),
                  encoding="utf-8")
    return md, js
