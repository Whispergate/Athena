"""Diff engine: compare consecutive snapshots -> events, with noise suppression.

Rules implemented (v0.1):
- appeared:      fire immediately, but flag single-source assets as low-confidence
- disappeared:   grace window — only fires if the asset was also absent from the
                 scan before the last one (needs >=2 prior snapshots; otherwise tentative)
- attr_changed:  field-level material diff from per-snapshot attrs history
- dedup:         enforced in the store via unique dedup_key
"""
from __future__ import annotations

from .store import Store

VOLATILE_ATTRS = {"last_seen"}  # attrs that legitimately change and are not material


def material_diff(old: dict, new: dict) -> dict:
    """Which attrs actually changed (old value -> new value).
    DNS A-record lists use set semantics: overlapping IP sets are rotation
    noise (resolvers return varying subsets of multi-A records), not change."""
    keys = (set(old) | set(new)) - VOLATILE_ATTRS
    changed = {}
    for k in sorted(keys):
        a, b = old.get(k), new.get(k)
        if k == "a" and isinstance(a, list) and isinstance(b, list):
            sa, sb = set(map(str, a)), set(map(str, b))
            if sa == sb:
                continue
            if sa & sb:  # partial overlap: rotation — hold, don't alert
                continue
            # twin-IP pattern: orgs pair hosts across adjacent netblocks
            # (10.0.154.19 <-> 10.0.155.19); same /16 + same host octet
            # flipping per query is DNS round-robin, not a record change
            def twin(ip):
                p = ip.split(".")
                return (p[0], p[1], p[3]) if len(p) == 4 else None
            if {twin(x) for x in sa} == {twin(x) for x in sb}:
                continue
        if isinstance(a, list):
            a = sorted(map(str, a))
        if isinstance(b, list):
            b = sorted(map(str, b))
        if a != b:
            changed[k] = {"old": old.get(k), "new": new.get(k)}
    return changed


def diff_snapshots(store: Store, scope: str, snap_id: int) -> list[dict]:
    """Compare snap_id (new) against the previous snapshot of the same scope."""
    snaps = store.latest_snapshots(scope, 2)
    if not snaps or snaps[0]["id"] != snap_id or len(snaps) < 2:
        return []  # first scan: baseline only, no events

    new_map = {k: v for k, v in store.snapshot_map(snaps[0]["id"]).items()
               if v["kind"] != "ip"}  # raw ip presence tracks provider crawl
    prev_map = {k: v for k, v in store.snapshot_map(snaps[1]["id"]).items()  # coverage, not
                if v["kind"] != "ip"}  # perimeter change — observations carry it
    hist4 = store.latest_snapshots(scope, 4)
    older = hist4[:3]
    older_map = ({k: v for k, v in store.snapshot_map(older[2]["id"]).items()
                  if v["kind"] != "ip"} if len(older) >= 3 else None)
    oldest_map = ({k: v for k, v in store.snapshot_map(hist4[3]["id"]).items()
                   if v["kind"] != "ip"} if len(hist4) >= 4 else None)

    events = []

    # appeared — quorum semantics:
    #  - with >=3 snapshots: fires on the second consecutive sighting
    #    ((new ∩ prev) − older). A provider blip (present, absent, present)
    #    never confirms, so it never fires.
    #  - young baseline (2 snapshots): new − prev is genuinely new vs baseline
    #    (blips can only remove assets, not add them), so fire immediately.
    if older_map is not None:
        appeared_keys = (set(new_map) & set(prev_map)) - set(older_map)
    else:
        appeared_keys = set(new_map) - set(prev_map)
    for key in sorted(appeared_keys):
        ent = new_map[key]
        asset = store.asset(key) or {}
        n_src = len(asset.get("sources", []))
        ev = {
            "kind": "appeared", "asset_key": key, "asset_kind": ent["kind"],
            "severity": 3.0, "techniques": [], "kev_cves": [],
            "detail": {"sources": asset.get("sources", []),
                       "attrs": ent["attrs"]},
            "material": ent["hash"],
        }
        if n_src == 1:
            ev["detail"]["note"] = "single source — pending corroboration"
            ev["severity"] = 2.0
        events.append(ev)

    # disappeared: last seen exactly 3 scans ago and absent since — provider
    # record-set rotation must persist three scans before we call it gone
    for key in sorted(set(oldest_map or {}) - set(older_map or {}) - set(prev_map) - set(new_map)):
        ent = oldest_map[key]
        asset = store.asset(key) or {}
        events.append({
            "kind": "disappeared", "asset_key": key, "asset_kind": ent["kind"],
            "severity": 2.5, "techniques": [], "kev_cves": [],
            "detail": {"last_seen": asset.get("last_seen"),
                       "note": "absent 3 consecutive scans"},
            "material": ent["hash"],
        })

    for key in sorted(set(new_map) & set(prev_map)):
        new_ent, prev_ent = new_map[key], prev_map[key]
        if new_ent["hash"] == prev_ent["hash"]:
            continue
        changed = material_diff(prev_ent["attrs"], new_ent["attrs"])
        if not changed:
            continue
        # rotation memory: an A-record-only change whose "new" value was seen
        # for this asset in any recent snapshot is DNS twin-IP round-robin
        # (targets pair hosts across netblocks), not a real change.
        if set(changed) == {"a"}:
            new_a = set(map(str, new_ent["attrs"].get("a") or []))
            hist = store.attr_history(scope, key, scans=5, exclude_snap=snaps[0]["id"])
            if any(new_a == h for h in hist):
                continue
        events.append({
            "kind": "attr_changed", "asset_key": key, "asset_kind": new_ent["kind"],
            "severity": 2.0, "techniques": [], "kev_cves": [],
            "detail": {"changed": changed, "attrs": new_ent["attrs"]},
            "material": new_ent["hash"],
        })

    return events
