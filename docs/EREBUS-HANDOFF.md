# Athena → Erebus Hand-off Contract

**Schema:** `athena/entry-vectors/1` · stable, versioned, additive-only changes.

Athena's job ends where Erebus's begins: Athena turns passive perimeter data
into **ranked entry-vector hypotheses**; Erebus turns an approved vector into
initial-access payloads. The contract between them is this JSON document.

```bash
athena handoff --scope acme-corp.com --min-severity 4.0
# writes ~/.athena/out/acme-corp.com-handoff.json and prints it
```

## Contract rules (binding on consumers)

1. **`operator_review_required: true` is binding.** Consumers must not act on
   vectors autonomously — a human approves each hop from vector to payload.
2. **Claim language.** Every vector is a *hypothesis* built from passive
   banner data: "consistent with", never "vulnerable to". `recommended_action`
   states the verification step for each vector.
3. **`touch: passive`** records that producing this document sent zero packets
   to the target. Consumers should preserve touch-level provenance when
   staging.

## Document shape

```json
{
  "schema": "athena/entry-vectors/1",
  "tool": "athena", "athena_version": "0.2.0",
  "scope": "acme-corp.com",
  "generated": "2026-09-28T12:00:00+00:00",
  "touch": "passive",
  "claim": "consistent-with (passive banner data) — verify before relying",
  "operator_review_required": true,
  "entry_vectors": [
    {
      "rank": 1,
      "asset": "svc:vpn.acme-corp.com:443",
      "kind": "service",
      "host": "vpn.acme-corp.com",
      "port": 443,
      "product": "Citrix NetScaler ADC",
      "version": "13.0-91.11",
      "cves": ["CVE-2023-3519"],
      "kev_cves": ["CVE-2023-3519"],
      "techniques": ["T1190"],
      "severity": 9.4,
      "label": "CRITICAL",
      "confidence": 96,
      "evidence": {
        "sources": ["shodan", "fofa"],
        "banner_excerpt": "HTTP/1.1 200 OK ...",
        "notes": ["CVE-2023-3519 is in CISA KEV (citrix netscaler adc)"]
      },
      "recommended_action": "verify affected version, then stage exploit chain
                             via erebus if rules of engagement permit"
    }
  ]
}
```

## Field notes

- `rank` — severity-descending; ties broken by confidence
- `kev_cves` — subset of `cves` present in the CISA KEV catalog (exploited in
  the wild); the strongest signal Athena produces
- `confidence` — 0–100, built from provider corroboration (single source ≈ 50,
  each independent source +15, capped 96)
- `evidence.banner_excerpt` — first 160 chars of the captured banner; the
  provenance chain for every claim
- `kind` — `service` (host:port), `ip`, `netblock` (aggregated /24), `domain`,
  `subdomain` (e.g. dangling-CNAME takeover candidates)

## Versioning

`schema` changes only in additive ways within `1`: new optional fields may
appear; existing fields never change meaning or disappear. A breaking change
bumps to `athena/entry-vectors/2`.
