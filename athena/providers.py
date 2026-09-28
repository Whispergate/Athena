"""Provider adapters — every function is passive (queries third-party databases only).

Each returns (records, error) where records is a list of normalized-ish dicts
tagged with "source". Errors never raise; the collector degrades gracefully.
"""
from __future__ import annotations

import base64
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import config
from .paths import DATA_DIR

UA = "athena-recon/0.1 (authorized passive recon)"
TIMEOUT = 45


def _req(url: str, method: str = "GET", headers: dict | None = None,
         body: dict | None = None, timeout: int = TIMEOUT, retries: int = 2):
    """Robious HTTP: returns (status, parsed_json_or_text). Never raises."""
    last = None
    for attempt in range(retries + 1):
        try:
            data = json.dumps(body).encode() if body is not None else None
            h = {"User-Agent": UA, "Accept": "application/json"}
            if headers:
                h.update(headers)
            if data is not None:
                h["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=data, headers=h, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                try:
                    return r.status, json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    return r.status, raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode("utf-8", "replace")
            except Exception:
                return e.code, ""
        except Exception as e:  # network, tls, timeout
            last = str(e)
            time.sleep(1.5 * (attempt + 1))
    return 0, f"network error: {last}"


# ---------------------------------------------------------------- surface engines

def shodan_search(key: str, domain: str):
    q = urllib.parse.quote(f"hostname:{domain}")
    url = f"https://api.shodan.io/shodan/host/search?key={key}&query={q}"
    st, js = _req(url)
    if st != 200 or not isinstance(js, dict):
        return [], f"HTTP {st}: {str(js)[:180]}"
    out = []
    for m in js.get("matches", [])[:100]:
        http = m.get("http") or {}
        ssl = ((m.get("ssl") or {}).get("cert") or {})
        out.append({
            "source": "shodan", "kind": "service",
            "ip": m.get("ip_str"), "port": m.get("port"),
            "proto": m.get("transport"),
            "hostnames": m.get("hostnames") or [],
            "product": m.get("product"),
            "version": m.get("version"),
            "title": http.get("title"), "server": http.get("server"),
            "cpe": m.get("cpe") or [],
            "banner": (m.get("data") or "")[:400],
            "cert_cn": (ssl.get("subject") or {}).get("CN"),
            "cert_expires": ssl.get("expires"),
        })
    return out, None


def shodan_dns_domain(key: str, domain: str):
    """Subdomains + records (needs a Shodan account with API credits)."""
    url = f"https://api.shodan.io/dns/domain/{urllib.parse.quote(domain)}?key={key}"
    st, js = _req(url)
    if st != 200 or not isinstance(js, dict):
        return [], f"HTTP {st}: {str(js)[:180]}"
    out = []
    for rec in js.get("data", [])[:2000]:
        sub = rec.get("subdomain") or ""
        fqdn = f"{sub}.{domain}" if sub else domain
        out.append({
            "source": "shodan-dns", "kind": "dns_record",
            "fqdn": fqdn, "type": rec.get("type"), "value": rec.get("value"),
        })
    return out, None


def fofa_search(key: str, email: str, domain: str):
    qbase64 = base64.b64encode(f'domain="{domain}"'.encode()).decode()
    url = (f"https://fofa.info/api/v1/search/all?email={urllib.parse.quote(email)}"
           f"&key={key}&qbase64={urllib.parse.quote(qbase64)}&size=100"
           f"&fields=host,ip,port,protocol,title,server,domain")
    st, js = _req(url)
    if st != 200 or not isinstance(js, dict) or js.get("error"):
        return [], f"HTTP {st}: {str(js.get('errmsg') or js)[:180]}"
    fields = ["host", "ip", "port", "protocol", "title", "server", "domain"]
    out = []
    for row in js.get("results", [])[:100]:
        rec = dict(zip(fields, row))
        out.append({
            "source": "fofa", "kind": "service",
            "ip": rec.get("ip"), "port": int(rec["port"]) if str(rec.get("port", "")).isdigit() else None,
            "proto": rec.get("protocol"),
            "hostnames": [rec["host"]] if rec.get("host") else [],
            "title": rec.get("title"), "server": rec.get("server"),
        })
    return out, None


def quake_search(token: str, domain: str):
    url = "https://quake.360.net/api/v3/search/quake_service"
    body = {"query": f'domain:"{domain}"', "start": 0, "size": 100}
    st, js = _req(url, method="POST", headers={"X-QuakeToken": token}, body=body, timeout=60)
    if st != 200 or not isinstance(js, dict) or js.get("code") not in (0, "0"):
        msg = js.get("message") if isinstance(js, dict) else str(js)
        return [], f"HTTP {st}: {str(msg or js)[:180]}"
    out = []
    for it in (js.get("data") or [])[:100]:
        svc = it.get("service") or {}
        http = svc.get("http") or {}
        out.append({
            "source": "quake", "kind": "service",
            "ip": it.get("ip"), "port": it.get("port"), "proto": it.get("transport"),
            "hostnames": [h for h in [it.get("hostname")] if h] + (http.get("host") or []),
            "product": svc.get("product"), "version": svc.get("version"),
            "title": http.get("title"), "server": http.get("server"),
            "banner": (svc.get("banner") or "")[:400],
        })
    return out, None


def internetdb(ip: str):
    """Keyless per-IP enrichment: ports, CPEs, CVEs, tags. Returns dict or None.
    Positive results are cached (7-day TTL): internetdb intermittently 404s IPs
    it knows, and untreated that flapping becomes appeared/disappeared noise."""
    cache_file = DATA_DIR / "internetdb_cache.json"
    cache: dict = {}
    try:
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
    except Exception:
        pass
    hit = cache.get(ip)
    if hit and time.time() - hit["_ts"] < 7 * 86400:
        return hit["data"]
    st, js = _req(f"https://internetdb.shodan.io/{ip}", timeout=20, retries=1)
    if st == 200 and isinstance(js, dict):
        try:
            cache[ip] = {"_ts": time.time(), "data": js}
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(cache), encoding="utf-8")
        except Exception:
            pass
        return js
    if hit:  # transient failure -> stale cache beats flapping
        return hit["data"]
    return None


# ---------------------------------------------------------------- enumeration sources

def certspotter_subdomains(key: str, domain: str):
    url = (f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}"
           f"&include_subdomains=true&expand=dns_names")
    hdr = {"Authorization": f"Bearer {key}"} if key else {}
    st, js = _req(url, headers=hdr, timeout=60)
    if st != 200 or not isinstance(js, list):
        return [], f"HTTP {st}: {str(js)[:180]}"
    names = set()
    for iss in js[:5000]:
        for n in iss.get("dns_names", []):
            n = n.lower().strip(".")
            if not n.startswith("*") and n.endswith(domain):
                names.add(n)
    return [{"source": "certspotter", "kind": "subdomain", "fqdn": n} for n in sorted(names)], None


def crtsh_subdomains(domain: str):
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    st, js = _req(url, timeout=90, retries=1)
    if st != 200 or not isinstance(js, list):
        return [], f"HTTP {st}: {str(js)[:180]}"
    names = set()
    for entry in js[:20000]:
        for n in (entry.get("name_value") or "").split("\n"):
            n = n.lower().strip(".").strip()
            if n and not n.startswith("*") and n.endswith(domain):
                names.add(n)
    return [{"source": "crt.sh", "kind": "subdomain", "fqdn": n} for n in sorted(names)], None


def virustotal_subdomains(key: str, domain: str):
    # free tier caps limit at 40
    url = (f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}"
           f"/subdomains?limit=40")
    st, js = _req(url, headers={"x-apikey": key})
    if st != 200 or not isinstance(js, dict):
        return [], f"HTTP {st}: {str(js)[:180]}"
    out = []
    for d in (js.get("data") or [])[:200]:
        if d.get("id"):
            out.append({"source": "virustotal", "kind": "subdomain", "fqdn": d["id"].lower()})
    return out, None


def otx_passive_dns(key: str, domain: str):
    hdr = {"X-OTX-API-Key": key} if key else {}
    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}"
           f"/passive_dns?limit=500")
    st, js = _req(url, headers=hdr, timeout=60)
    if st != 200 or not isinstance(js, dict):
        return [], f"HTTP {st}: {str(js)[:180]}"
    entries = js.get("passive_dns") or js.get("results") or []
    out = []
    for r in entries[:2000]:
        host = (r.get("hostname") or r.get("indicator") or "").lower().strip(".")
        rtype = (r.get("record_type") or "").upper()
        val = (r.get("address") or r.get("value") or "").strip(".").strip()
        if not host:
            continue
        if rtype in ("A", "AAAA", "CNAME"):
            out.append({"source": "otx", "kind": "dns_record",
                        "fqdn": host, "type": rtype, "value": val})
        elif host.endswith(domain):
            out.append({"source": "otx", "kind": "subdomain", "fqdn": host})
    return out, None


def securitytrails_subdomains(key: str, domain: str):
    url = f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(domain)}/subdomains"
    st, js = _req(url, headers={"APIKEY": key, "Accept": "application/json"})
    if st != 200 or not isinstance(js, dict):
        return [], f"HTTP {st}: {str(js)[:180]}"
    subs = [f"{s}.{domain}" for s in (js.get("subdomains") or [])[:5000]]
    return [{"source": "securitytrails", "kind": "subdomain", "fqdn": s} for s in subs], None


def wayback_subdomains(domain: str):
    """Historical URLs from the Wayback Machine CDX index — keyless, passive,
    and backfills subdomains that existed before monitoring started."""
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{urllib.parse.quote(domain)}/*"
           f"&output=json&fl=original&collapse=urlkey&limit=8000")
    st, js = _req(url, timeout=120, retries=1)
    if st != 200 or not isinstance(js, list):
        return [], f"HTTP {st}: {str(js)[:150]}"
    hosts = set()
    for row in js[1:]:  # row 0 is the column header
        try:
            raw = row[0]
            host = raw.split("//", 1)[-1].split("/", 1)[0].split(":")[0].lower().strip(".")
            if host.endswith(domain) and host != domain:
                hosts.add(host)
        except Exception:
            continue
    return [{"source": "wayback", "kind": "subdomain", "fqdn": h} for h in sorted(hosts)], None


# ------------------------------------------------- experimental (endpoint gated)
# Implemented against documented schemas but NOT verified live:
# - netlas: free tier returns empty result sets for the responses search API
# - zoomeye: api.zoomeye.org geo-blocked -> api.zoomeye.ai (currently 502)
# Both degrade gracefully; they activate whenever account/plan/network allows.

def netlas_search(key: str, domain: str):
    url = f"https://app.netlas.io/api/responses/?q=domain:{domain}&size=100"
    st, js = _req(url, headers={"X-API-Key": key})
    if st != 200 or not isinstance(js, dict):
        return [], f"HTTP {st}: {str(js)[:150]}"
    out = []
    for it in (js.get("items") or [])[:100]:
        data = it.get("data") or {}
        http = data.get("http") or {}
        proto = it.get("protocol")
        if isinstance(proto, list):
            proto = proto[0] if proto else None
        out.append({
            "source": "netlas", "kind": "service", "ip": it.get("ip"),
            "port": it.get("port"), "proto": proto,
            "hostnames": [h for h in [it.get("hostname")] if h],
            "title": http.get("title"), "server": http.get("server"),
            "banner": (data.get("banner") or "")[:400],
        })
    return out, None


def zoomeye_search(key: str, domain: str):
    url = f"https://api.zoomeye.ai/api/v2/search/host?q={urllib.parse.quote(domain)}&size=100"
    st, js = _req(url, headers={"API-KEY": key})
    if st != 200 or not isinstance(js, dict):
        return [], f"HTTP {st}: {str(js)[:150]}"
    out = []
    for it in (js.get("items") or [])[:100]:
        pi = it.get("portinfo") or {}
        out.append({
            "source": "zoomeye", "kind": "service", "ip": it.get("ip"),
            "port": pi.get("port") or it.get("port"), "proto": pi.get("service"),
            "hostnames": [h for h in [it.get("hostname")] if h],
            "title": pi.get("title"), "product": pi.get("product"),
        })
    return out, None


# ---------------------------------------------------------------- dns (light touch)

def resolve_a(host: str) -> list[str]:
    """Recursive resolution via the OS resolver — never contacts the target directly."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def resolve_many(hosts: list[str], workers: int = 24) -> dict[str, list[str]]:
    hosts = list(dict.fromkeys(hosts))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(resolve_a, hosts))
    return dict(zip(hosts, results))


# ---------------------------------------------------------------- orchestrator

def collect_all(domain: str, progress=print) -> tuple[list[dict], list[tuple[str, str]]]:
    """Fan out every configured provider. Returns (records, provider_errors)."""
    records: list[dict] = []
    errors: list[tuple[str, str]] = []

    jobs = []  # (name, callable)
    if config.get("SHODAN_API_KEY"):
        jobs.append(("shodan", lambda: shodan_search(config.get("SHODAN_API_KEY"), domain)))
        jobs.append(("shodan-dns", lambda: shodan_dns_domain(config.get("SHODAN_API_KEY"), domain)))
    if config.get("FOFA_KEY") and config.get("FOFA_EMAIL"):
        jobs.append(("fofa", lambda: fofa_search(config.get("FOFA_KEY"), config.get("FOFA_EMAIL"), domain)))
    if config.get("QUAKE_TOKEN"):
        jobs.append(("quake", lambda: quake_search(config.get("QUAKE_TOKEN"), domain)))
    if config.get("CERTSPOTTER_API_KEY"):
        jobs.append(("certspotter", lambda: certspotter_subdomains(config.get("CERTSPOTTER_API_KEY"), domain)))
    jobs.append(("crt.sh", lambda: crtsh_subdomains(domain)))
    if config.get("VIRUSTOTAL_API_KEY"):
        jobs.append(("virustotal", lambda: virustotal_subdomains(config.get("VIRUSTOTAL_API_KEY"), domain)))
    jobs.append(("otx", lambda: otx_passive_dns(config.get("OTX_API_KEY"), domain)))
    if config.get("SECURITYTRAILS_API_KEY"):
        jobs.append(("securitytrails", lambda: securitytrails_subdomains(config.get("SECURITYTRAILS_API_KEY"), domain)))
    jobs.append(("wayback", lambda: wayback_subdomains(domain)))
    if config.get("NETLAS_API_KEY"):
        jobs.append(("netlas", lambda: netlas_search(config.get("NETLAS_API_KEY"), domain)))
    if config.get("ZOOMEYE_API_KEY"):
        jobs.append(("zoomeye", lambda: zoomeye_search(config.get("ZOOMEYE_API_KEY"), domain)))

    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(fn): name for name, fn in jobs}
        for fut, name in futures.items():
            try:
                recs, err = fut.result()
            except Exception as e:  # adapter bug must not kill the scan
                recs, err = [], f"adapter exception: {e}"
            if err:
                errors.append((name, err))
                progress(f"  [!] {name}: {err}")
            else:
                records.extend(recs)
                progress(f"  [+] {name}: {len(recs)} records")
    return records, errors
