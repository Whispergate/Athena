"""Configuration: loads .env (repo dir for source runs, ATHENA_HOME for
installed runs) into os.environ without overwriting real env vars."""
import os
from pathlib import Path

from .paths import ATHENA_HOME

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_env(env_path: Path | None = None) -> None:
    candidates = ([env_path] if env_path
                  else [PROJECT_ROOT / ".env", ATHENA_HOME / ".env"])
    for path in candidates:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and k not in os.environ:  # real env vars win over .env
                os.environ[k] = v


def get(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def provider_status() -> list[tuple[str, bool, str]]:
    """(name, configured, note) for every provider adapter."""
    checks = [
        ("shodan", bool(get("SHODAN_API_KEY")), "search + dns/domain endpoints"),
        ("fofa", bool(get("FOFA_KEY") and get("FOFA_EMAIL")),
         "needs FOFA_KEY + FOFA_EMAIL" if not get("FOFA_EMAIL") else "ready"),
        ("quake", bool(get("QUAKE_TOKEN")), "quake_service search"),
        ("internetdb", True, "keyless (Shodan InternetDB)"),
        ("certspotter", bool(get("CERTSPOTTER_API_KEY")), "CT logs via API"),
        ("crt.sh", True, "keyless CT logs"),
        ("virustotal", bool(get("VIRUSTOTAL_API_KEY")), "passive DNS / subdomains"),
        ("otx", True, "passive DNS (key optional)"),
        ("securitytrails", bool(get("SECURITYTRAILS_API_KEY")), "subdomains + DNS"),
        ("wayback", True, "keyless historical URLs (CDX)"),
        ("netlas", bool(get("NETLAS_API_KEY")),
         "EXPERIMENTAL — free tier gates search data"),
        ("zoomeye", bool(get("ZOOMEYE_API_KEY")),
         "EXPERIMENTAL — geo-blocked / endpoint 502"),
        ("dns", True, "recursive resolver (light touch)"),
    ]
    return checks
