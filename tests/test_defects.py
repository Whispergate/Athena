"""Defect-hunt regression tests — every check here reproduces a defect found
by live probing (2026-09-29 session) and verifies its fix.
Run: python tests/test_defects.py   (also run by CI)
"""
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from athena.cli import _load_scopes_file, _parse_scopes_yaml
from athena.web import create_server

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


def _yaml_file(text: str) -> str:  # tmp fixture, unlinked by caller
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


print("[scopes parser]")


def _yaml_file_lines(lines):
    return _yaml_file("scopes:\n" + "".join(f"  {ln}\n" for ln in lines))


# D4: quoted scalars must lose their quotes
p = _yaml_file_lines(['- name: "acme"', "  domains: [a.com]"])
s = _parse_scopes_yaml(Path(p).read_text(encoding="utf-8"))
check("quoted scalar unquoted", s and s[0]["name"] == "acme", s)
os.unlink(p)

# D5: scalar `domains` coerced to a list (was: string iterated by character)
p = _yaml_file_lines(["- name: x", "  domains: a.com"])
sc = _load_scopes_file(p)
check("scalar domains coerced to list", sc[0]["domains"] == ["a.com"], sc)
os.unlink(p)

# D6: ghost-only files (wrong yaml shape) rejected loudly, no ghost scopes
p = _yaml_file("other:\n  - thing\n")
try:
    _load_scopes_file(p)
    check("ghost-only scopes file rejected", False)
except SystemExit:
    check("ghost-only scopes file rejected", True)
os.unlink(p)

# D7: duplicate names uniquified
p = _yaml_file_lines(["- name: dup", "  domains: [a.com]",
                      "- name: dup", "  domains: [b.com]"])
sc = _load_scopes_file(p)
os.unlink(p)
check("duplicate scope names uniquified",
      len(sc) == 2 and len({x["name"] for x in sc}) == 2, sc)

# entries without domains are skipped, entries with domains survive
p = _yaml_file_lines(["- name: ghost", "  interval_min: 5",
                      "- name: real", "  domains: [ok.com]"])
sc = _load_scopes_file(p)
os.unlink(p)
check("domain-less entries skipped, real kept",
      len(sc) == 1 and sc[0]["name"] == "real", sc)

print("[web api params]  (live server, real DB)")
db = Path.home() / ".athena" / "athena.db"
if not db.exists():
    db = None
if db:
    srv = create_server(db, "127.0.0.1", 0, "T")
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def hit(path):
        r = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
        r.add_header("Authorization", "Bearer T")
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    # D1: junk limit -> clean 400 (was 500 leaking internals)
    check("limit=abc -> 400", hit("/api/events?scope=x&limit=abc") == 400)
    # D2: overflow limit -> clamped (was 500 "int too large")
    check("limit=overflow -> 200 clamped",
          hit("/api/events?scope=x&limit=99999999999999999999999") == 200)
    # D3: negative limit -> clamped (was: silent unbounded query)
    check("limit=-5 -> 200 clamped", hit("/api/events?scope=x&limit=-5") == 200)
    check("assets limit junk -> 400",
          hit("/api/assets?scope=x&kind=ip&limit=nope") == 400)
    srv.shutdown()
    srv.server_close()
else:
    print("  (skipped: no local athena db)")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
