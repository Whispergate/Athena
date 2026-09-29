"""Discord webhook alerting — rich embeds, severity-colored.

The alert is a pager: top findings only, everything else lives in the .md
dossier (the system of record).
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import config
from .providers import _req


def _version() -> str:
    from . import __version__

    return __version__

COLORS = {"CRITICAL": 0xE5484D, "HIGH": 0xF5A524,
          "MEDIUM": 0xE2C94D, "LOW": 0x6CA0DD}
MAX_FIELDS = 20  # discord caps at 25; leave headroom


def send_discord(webhook: str | None, scope: str, vectors: list[dict],
                 stats: dict, min_severity: float = 4.0) -> tuple[bool, str]:
    """Post an embed alert. Returns (ok, message).
    Everything is recorded in the dossier; only MEDIUM+ pages."""
    webhook = webhook or config.get("DISCORD_WEBHOOK")
    if not webhook:
        return False, "no webhook configured"
    vectors = [v for v in vectors if v.get("severity", 0) >= min_severity]
    if not vectors:
        return True, "nothing at/above alert threshold (dossier records all)"

    worst = vectors[0]
    color = COLORS.get(worst.get("label"), 0x8A8A96)

    fields = []
    for v in vectors[:MAX_FIELDS]:
        val_lines = []
        for t in (v.get("techniques") or [])[:2]:
            val_lines.append(f"> {t}")
        if v.get("kev_cves"):
            val_lines.append(f"**KEV:** {', '.join(v['kev_cves'])}")
        for n in (v.get("notes") or [])[:1]:
            val_lines.append(f"*{n[:120]}*")
        attrs = v.get("attrs") or {}
        prod = attrs.get("product") or attrs.get("server") or attrs.get("title")
        if prod:
            val_lines.insert(0, f"`{str(prod)[:80]}`")
        fields.append({
            "name": f"{v['label']} {v['severity']} — {v['asset']}"[:256],
            "value": ("\n".join(val_lines) or "—")[:1024],
            "inline": False,
        })
    if len(vectors) > MAX_FIELDS:
        fields.append({"name": f"+{len(vectors) - MAX_FIELDS} more",
                       "value": "full log in the .md dossier", "inline": False})

    embed = {
        "title": f"ATHENA — {len(vectors)} new finding(s) · {scope}",
        "description": f"**{worst['label']} {worst['severity']}** top finding · "
                       f"{stats.get('assets', '?')} assets tracked · touch=passive",
        "color": color,
        "fields": fields,
        "footer": {"text": f"athena v{_version()} · scan of {scope} · dossier has full log"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    st, resp = _req(webhook, method="POST", body={"embeds": [embed]}, retries=1)
    if st in (200, 204):
        return True, (f"embed delivered ({len(vectors)} finding(s), "
                      f"color #{color:06x} by {worst['label']})")
    return False, f"webhook HTTP {st}: {str(resp)[:120]}"


def send_slack(webhook: str, scope: str, vectors: list[dict],
               stats: dict, min_severity: float = 4.0) -> tuple[bool, str]:
    """Slack incoming-webhook format ({"text": ...}). Pager: top findings only."""
    vectors = [v for v in vectors if v.get("severity", 0) >= min_severity]
    if not vectors:
        return True, "nothing at/above alert threshold"
    lines = [f"*ATHENA* — {len(vectors)} new finding(s) · `{scope}` · touch=passive"]
    for v in vectors[:MAX_FIELDS]:
        kev = f" · *KEV:* {', '.join(v['kev_cves'])}" if v.get("kev_cves") else ""
        tech = f"\n    {v['techniques'][0]}" if v.get("techniques") else ""
        lines.append(f"• *{v['label']} {v['severity']}* `{v['asset']}`{kev}{tech}")
    if len(vectors) > MAX_FIELDS:
        lines.append(f"…+{len(vectors) - MAX_FIELDS} more — full log in the .md dossier")
    st, resp = _req(webhook, method="POST", body={"text": "\n".join(lines)}, retries=1)
    ok = st in (200, 204)
    return (ok, f"slack delivered ({len(vectors)} finding(s))"
            if ok else f"slack HTTP {st}: {str(resp)[:100]}")


def send_generic(webhook: str, scope: str, vectors: list[dict],
                 stats: dict, min_severity: float = 0.0) -> tuple[bool, str]:
    """Raw JSON POST — machine consumption (SOAR, feed pipelines, IntelliBird)."""
    payload = {
        "tool": "athena", "scope": scope,
        "generated": datetime.now(timezone.utc).isoformat(),
        "touch": "passive", "stats": stats,
        "findings": [
            {"asset": v["asset"], "kind": v["kind"], "event": v["event"],
             "severity": v["severity"], "label": v["label"],
             "techniques": v["techniques"], "kev_cves": v["kev_cves"],
             "attrs": v.get("attrs", {})}
            for v in vectors if v.get("severity", 0) >= min_severity
        ],
    }
    st, resp = _req(webhook, method="POST", body=payload, retries=1)
    return (st in (200, 204), f"generic webhook delivered ({len(payload['findings'])} finding(s))"
            if st in (200, 204) else f"generic webhook HTTP {st}: {str(resp)[:100]}")


def dispatch(scope: str, vectors: list[dict], stats: dict) -> list[tuple[str, bool, str]]:
    """Fire every configured sink. Returns [(name, ok, message)]."""
    results = []
    if config.get("DISCORD_WEBHOOK"):
        ok, msg = send_discord(None, scope, vectors, stats)
        results.append(("discord", ok, msg))
    if config.get("SLACK_WEBHOOK"):
        ok, msg = send_slack(config.get("SLACK_WEBHOOK"), scope, vectors, stats)
        results.append(("slack", ok, msg))
    if config.get("GENERIC_WEBHOOK"):
        ok, msg = send_generic(config.get("GENERIC_WEBHOOK"), scope, vectors, stats)
        results.append(("generic", ok, msg))
    return results
