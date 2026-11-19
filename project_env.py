"""Load backend/.env for standalone root-level integration scripts.

Existing process environment variables take precedence. Values are never printed.
"""

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent


def load_backend_env() -> None:
    env_path = PROJECT_ROOT / "backend" / ".env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
