"""Normalization: raw provider records -> unified Asset model (merge by identity)."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def attr_hash(attrs: dict) -> str:
    return hashlib.blake2b(json.dumps(attrs, sort_keys=True, default=str).encode(),
                           digest_size=16).hexdigest()


class Assets:
    """In-memory asset set for one scan, keyed by canonical identity."""

    def __init__(self):
        self.by_key: dict[str, dict] = {}

    def add(self, key: str, kind: str, attrs: dict, source: str):
        a = self.by_key.get(key)
        if a is None:
            self.by_key[key] = {
                "key": key, "kind": kind, "attrs": dict(attrs),
                "sources": [source], "first_seen": utcnow(), "last_seen": utcnow(),
                "confidence": 50,
            }
        else:
            # union attrs: keep existing values, fill gaps, never clobber with empty
            for k, v in attrs.items():
                if v not in (None, "", [], {}) and not a["attrs"].get(k):
                    a["attrs"][k] = v
            if source not in a["sources"]:
                a["sources"].append(source)
            a["last_seen"] = utcnow()
        n = len(self.by_key[key]["sources"])
        self.by_key[key]["confidence"] = min(50 + 15 * (n - 1), 96)

    def list(self) -> list[dict]:
        return sorted(self.by_key.values(), key=lambda a: a["key"])


def _host_for_service(rec: dict, domain: str) -> str | None:
    """Pick the best hostname for a service record; fall back to the IP."""
    hostnames = [h for h in rec.get("hostnames") or [] if h]
    in_scope = [h for h in hostnames if h.lower().endswith(domain)]
    for h in in_scope:
        return h.lower().strip(".")
    if hostnames:
        return hostnames[0].lower().strip(".")
    ip = rec.get("ip")
    return ip


def build_assets(records: list[dict], domain: str, resolve,
                  enrich_ip=None, max_ips: int = 100, extra_ips: list[str] | None = None):
    """records -> Assets. `resolve` maps fqdn -> [ips]; `enrich_ip` (optional)
    is called per unique IP for internetdb data. `extra_ips` keeps the IP
    universe sticky across scans (DNS variance must not shrink it)."""
    assets = Assets()
    cname_map: dict[str, str] = {}
    fqdns: set[str] = set()

    # pass 1: dns records + subdomains
    for r in records:
        if r.get("kind") == "dns_record":
            fqdn = (r.get("fqdn") or "").lower().strip(".")
            val = (r.get("value") or "").strip(".")
            if not fqdn:
                continue
            fqdns.add(fqdn)
            if r.get("type") == "CNAME" and val:
                cname_map[fqdn] = val
        elif r.get("kind") == "subdomain":
            fq = (r.get("fqdn") or "").lower().strip(".")
            if fq:
                fqdns.add(fq)

    # pass 2: services reveal more hostnames
    for r in records:
        if r.get("kind") == "service":
            for h in r.get("hostnames") or []:
                h = h.lower().strip(".")
                if h.endswith(domain):
                    fqdns.add(h)

    # resolve everything (light touch, recursive only)
    resolutions: dict[str, list[str]] = resolve(sorted(fqdns))

    # subdomain assets
    for fq, ips in resolutions.items():
        attrs = {"a": ips}
        if fq in cname_map:
            attrs["cname"] = cname_map[fq]
        assets.add(f"sub:{fq}", "subdomain", attrs, "dns")
    for r in records:
        if r.get("kind") == "subdomain":
            fq = r["fqdn"].lower().strip(".")
            attrs = {}
            if fq in cname_map:
                attrs["cname"] = cname_map[fq]
            if resolutions.get(fq):
                attrs.setdefault("a", resolutions[fq])
            assets.add(f"sub:{fq}", "subdomain", attrs, r["source"])

    # service assets
    for r in records:
        if r.get("kind") != "service":
            continue
        host = _host_for_service(r, domain)
        port = r.get("port")
        if not host or not port:
            continue
        key = f"svc:{host}:{port}"
        attrs = {k: r.get(k) for k in
                 ("ip", "proto", "product", "version", "title", "server",
                  "banner", "cert_cn", "cert_expires") if r.get(k)}
        if r.get("cpe"):
            attrs["cpe"] = r["cpe"]
        assets.add(key, "service", attrs, r["source"])

    # dangling-CNAME detection (passive): known CNAME + unresolvable now +
    # CNAME target itself unresolvable -> takeover candidate
    for fq, target in cname_map.items():
        if target and not resolutions.get(fq):
            if target not in resolutions:
                resolutions[target] = resolve([target]).get(target, [])
            if not resolutions.get(target):
                assets.add(f"sub:{fq}", "subdomain",
                           {"cname": target, "dangling": True, "target_nxdomain": True},
                           "athena-analysis")

    # internetdb enrichment per unique IP (keyless)
    if enrich_ip is not None:
        ips = set()
        for a in assets.list():
            if a["attrs"].get("ip"):
                ips.add(a["attrs"]["ip"])
            ips.update(a["attrs"].get("a") or [])
        for ip in sorted(ips | set(extra_ips or []))[:max_ips]:
            info = enrich_ip(ip)
            if info:
                attrs = {}
                if info.get("vulns"):
                    attrs["cves"] = info["vulns"]
                if info.get("cpes"):
                    attrs["cpes"] = info["cpes"]
                if info.get("ports"):
                    attrs["open_ports"] = info["ports"]
                if info.get("hostnames"):
                    attrs["hostnames"] = [h for h in info["hostnames"]
                                          if isinstance(h, str)][:20]
                if attrs:
                    assets.add(f"ip:{ip}", "ip", attrs, "internetdb")

    return assets
