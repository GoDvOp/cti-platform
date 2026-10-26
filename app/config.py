"""No configuration side effects at import; secrets are never logged."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_env(path=None):
    path = Path(path or ROOT / '.env')
    if not path.exists():
        return
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if sep and key.strip().replace('_', '').isalnum():
            os.environ.setdefault(key.strip(), value.strip().strip('\"\''))
