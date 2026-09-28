"""Filesystem layout: all state lives in ATHENA_HOME (~/.athena by default),
never inside the repo — nothing a push could accidentally leak."""

import os
from pathlib import Path

ATHENA_HOME = Path(os.environ.get("ATHENA_HOME") or Path.home() / ".athena")
DB_PATH = ATHENA_HOME / "athena.db"
OUT_DIR = ATHENA_HOME / "out"
DATA_DIR = ATHENA_HOME / "data"


def ensure() -> None:
    for p in (ATHENA_HOME, OUT_DIR, DATA_DIR):
        p.mkdir(parents=True, exist_ok=True)
