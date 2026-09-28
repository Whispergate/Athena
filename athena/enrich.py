"""Enrichment: KEV matching + ATT&CK technique mapping + severity scoring.

Claim contract: findings say "consistent with", never "vulnerable to".
Passive banner data is a hypothesis for operator verification, not proof.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .paths import DATA_DIR
from .providers import _req

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_CACHE = DATA_DIR / "kev.json"

# curated exposure-class table: (regex on product/banner/port, technique, name, base sev)
ATTACK_TABLE = [
    (r"citrix.{0,12}(netscaler|adc)|netscaler", "T1190", "Exploit Public-Facing Application — edge appliance RCE", 7.0),
    (r"ivanti.{0,12}(connect|policy)", "T1190", "Exploit Public-Facing Application — edge appliance RCE", 7.2),
    (r"fortinet|fortigate", "T1190", "Exploit Public-Facing Application — SSL-VPN edge", 6.8),
    (r"f5.{0,8}big-?ip|bigip", "T1190", "Exploit Public-Facing Application — edge appliance RCE", 6.8),
    (r"pulse.{0,8}(connect|secure)|globalprotect|anyconnect", "T1078", "Valid Accounts — VPN portal credential abuse", 5.5),
    (r"jenkins", "T1195", "Supply Chain Compromise — CI/CD pipeline access", 6.5),
    (r"\bgitlab\b|\bgithub enterprise\b|artifactory|nexus repository", "T1195", "Supply Chain Compromise — source/pipeline access", 6.0),
    (r"\bowa\b|outlook web|exchange\b|adfs", "T1078.004", "Valid Accounts: Cloud Accounts — mail/auth portal spray", 5.5),
    (r"veeam|backup exec", "T1005", "Data from Local System — backup console access", 5.8),
    (r"tomcat.{0,30}ajp|ajp13", "T1190", "Exploit Public-Facing Application — AJP exposure", 6.0),
    (r"palo alto|pan-os|globalprotect", "T1190", "Exploit Public-Facing Application — edge appliance", 6.6),
]
PORT_TECHNIQUES = {
    "3389": ("T1021.001", "Remote Services: RDP", 4.5),
    "5900": ("T1021", "Remote Services: VNC", 5.0),
    "445": ("T1021.002", "Remote Services: SMB/Admin Shares", 4.5),
    "22": ("T1021.004", "Remote Services: SSH", 3.5),
    "23": ("T1078", "Valid Accounts — telnet exposure", 5.0),
}
DANGLING = ("T1583.001", "Acquire Infrastructure: Domains — takeover candidate", 6.5)


def load_kev(force: bool = False) -> dict:
    """Download/cache CISA KEV. Returns {cve_id: {vendor, product, ransomware}}."""
    KEV_CACHE.parent.mkdir(parents=True, exist_ok=True)
    fresh = False
    if KEV_CACHE.exists() and not force:
        try:
            meta = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
            fetched = datetime.fromisoformat(meta["_fetched"])
            age = (datetime.now(timezone.utc) - fetched).total_seconds()
            fresh = age < 24 * 3600
        except Exception:
            fresh = False
    if not fresh:
        st, js = _req(KEV_URL, timeout=90, retries=1)
        if st == 200 and isinstance(js, dict) and js.get("vulnerabilities"):
            js["_fetched"] = datetime.now(timezone.utc).isoformat()
            KEV_CACHE.write_text(json.dumps(js), encoding="utf-8")
        elif KEV_CACHE.exists():
            pass  # fall back to stale cache
        else:
            return {}
    try:
        meta = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for v in meta.get("vulnerabilities", []):
        out[v.get("cveID", "")] = {
            "vendor": (v.get("vendorProject") or "").lower(),
            "product": (v.get("product") or "").lower(),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "note": v.get("shortDescription", "")[:160],
            "due": v.get("dueDate", ""),
        }
    return out


def _fingerprint(asset: dict) -> str:
    """Text blob used for regex matching."""
    a = asset.get("attrs", {})
    parts = [str(a.get("product", "")), str(a.get("version", "")),
             str(a.get("server", "")), str(a.get("title", "")),
             str(a.get("banner", ""))]
    for cpe in a.get("cpe", []) or a.get("cpes", []) or []:
        parts.append(str(cpe))
    return " ".join(parts).lower()


def enrich_event(ev: dict, kev: dict) -> dict:
    """Attach techniques + KEV matches + final severity to one diff event."""
    attrs = ev.get("detail", {}).get("attrs", {})
    fp = _fingerprint({"attrs": attrs})
    techniques: list[str] = []
    notes: list[str] = []
    base = ev["severity"]
    kev_hits: list[str] = []

    if attrs.get("dangling"):
        tech, name, sev = DANGLING
        techniques.append(f"{tech} {name}")
        base = max(base, sev)
        notes.append("dangling CNAME — passive takeover candidate; verify upstream name availability")

    for pattern, tech, name, sev in ATTACK_TABLE:
        if re.search(pattern, fp):
            techniques.append(f"{tech} {name}")
            base = max(base, sev)
            break  # strongest matching class only

    key_port = str(ev.get("asset_key", "").rsplit(":", 1)[-1])
    if key_port in PORT_TECHNIQUES:
        tech, name, sev = PORT_TECHNIQUES[key_port]
        techniques.append(f"{tech} {name}")
        base = max(base, sev)

    # KEV: intersect asset CVE list (internetdb) with the KEV catalog
    for cve in attrs.get("cves", []) or []:
        cve = str(cve).upper()
        if cve in kev:
            k = kev[cve]
            kev_hits.append(cve)
            base = min(base + 2.5, 9.6)
            notes.append(f"{cve} is in CISA KEV ({k['vendor']} {k['product']})"
                         + (" — ransomware-use" if k["ransomware"] else ""))
    if attrs.get("cves") and not kev_hits:
        notes.append(f"{len(attrs['cves'])} CVEs reported by internetdb — none in KEV")

    # corroboration boost
    n_src = len(ev.get("detail", {}).get("sources", []) or [])
    if n_src >= 2:
        base = min(base + 0.4, 9.7)

    ev["techniques"] = techniques
    ev["kev_cves"] = kev_hits
    ev["severity"] = round(min(base, 9.7), 1)
    ev["detail"]["notes"] = notes
    ev["detail"]["claim"] = "consistent with (passive banner data) — verify before relying"
    return ev


def severity_label(sev: float) -> str:
    if sev >= 8.5:
        return "CRITICAL"
    if sev >= 6.5:
        return "HIGH"
    if sev >= 4.0:
        return "MEDIUM"
    return "LOW"
