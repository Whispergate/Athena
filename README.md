# ATHENA

<div align="center">

```
   ___    ________  ________  ________
  / _ |  / __/ __/ / __/ __ \/ __/ __/
 / __ |_\ \_\ \   _\ \ /_/ /\ \_\ \
/_/ |_/___/___/  /___/\____/___/___/
```

**A continuous external attack-surface diff engine for red teams.**

Passive by default · diff-native · provider-agnostic · zero packets to the target

</div>

---

> **CAUTION — AUTHORIZED USE ONLY.** Athena is for systems you own or have
> explicit written permission to assess. It collects third-party passive data
> (cyberspace search APIs, CT logs, passive DNS) about external perimeters.
> Findings are **hypotheses** ("consistent with", never "vulnerable to") —
> the operator verifies before acting.

## What it does

Athena answers one question: **"what changed on my target's perimeter since I
last looked?"** Point tools (subfinder, httpx, nmap) collect once and forget.
Athena remembers every scan, diffs consecutive snapshots, and alerts only on
change — correlated against the CISA KEV catalog and mapped to MITRE ATT&CK
initial-access techniques, ranked into entry-vector hypotheses.

- **Passive-first**: queries Shodan/FOFA/Quake/Censys/VT/OTX/SecurityTrails +
  CT logs + passive DNS. The target sees zero packets (`touch: passive`).
- **Stateful**: SQLite snapshots, immutable history, event timeline forever.
- **Noise-suppressed**: quorum confirmation, grace windows, dedup keys,
  DNS twin-IP rotation memory, netblock aggregation. Silence is trustworthy.
- **Honest claims**: every finding carries its evidence, sources, and a
  confidence score. No version → no CVE claim.

## Install

```bash
pipx install git+https://github.com/Whispergate/Athena     # or: pip install -e . from a clone
athena doctor        # verify providers, KEV feed, state dir
```

Python 3.10+ standard library only — no dependencies. From source without
installing: `python -m athena doctor`. All state (SQLite db, dossiers, caches)
lives in `~/.athena/` (override with `ATHENA_HOME`) — never inside the repo.

## Usage

```bash
# one-shot targeting dossier
athena scan --scope acme-corp.com

# ingest your existing tools' output (athena remembers, it doesn't replace)
subfinder -d acme-corp.com -json -o subs.json
athena scan --scope acme-corp.com --extra-subs subs.json

# continuous monitoring: copy scopes.example.yaml -> scopes.local.yaml
athena watch --config scopes.local.yaml --jitter

# review the change timeline / regenerate the report
athena events --scope acme-corp.com
athena report --scope acme-corp.com --format md
```

Set `DISCORD_WEBHOOK` (or `SLACK_WEBHOOK` / `GENERIC_WEBHOOK`) in `~/.athena/.env`
(or the repo `.env`) to page on MEDIUM+ findings — severity-colored embeds,
dedup-gated, quiet when the perimeter is quiet. Every scan writes a full-log
.md dossier (the system of record): all events, all subdomains, services, and
IP enrichments in tables. `athena export --scope X` emits an asset/IOC/event
JSON feed for intel platforms.

> **Operational invariant:** if you scan with `--extra-subs`, always scan with
> it (put it on the `watch` command too). Inconsistent ingest makes the
> subdomain universe swing, and the diff engine will correctly — but
> pointlessly — report the gap as disappearances/reappearations.

## Providers

| Tier | Providers | Notes |
|---|---|---|
| Native surface engines | Shodan (search + DNS), Quake, FOFA*, Censys* | rich per-host banners/ports/certs |
| Keyless | Shodan InternetDB (per-IP CVE/CPE), crt.sh, RDAP | zero-config coverage |
| Enumeration | SecurityTrails, VirusTotal, OTX, Certspotter | subdomains + passive DNS |
| Ingest pipe | subfinder / httpx / nmap / amass JSON | `--extra-subs` or records ingest |

*FOFA needs email+key; Censys needs id+secret — skipped gracefully otherwise.

## Data handling

Scope definitions, collected assets, and the event timeline are **engagement
data**: they live only in your local `ATHENA_HOME` (SQLite + dossiers, no
telemetry, no cloud sync). Handle them per your engagement agreement —
deleting `ATHENA_HOME` (or the scope's rows in its DB) is a complete removal.
API keys are read from the environment or local `.env` and never leave the
machine except as queries to the providers you configured.

## Credits

Built on the shoulders of: [ProjectDiscovery](https://github.com/projectdiscovery)
(subfinder), [Shodan InternetDB](https://internetdb.shodan.io) (prior art:
[s0md3v/Smap](https://github.com/s0md3v/Smap)), ARL / RedWarden lineage,
CISA KEV catalog. Forks and inspiration credited in code.

## License

BSD-2-Clause — see [LICENSE](LICENSE). The license does not override the
usage disclaimer above.
