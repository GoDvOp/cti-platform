"""Prepare local environment without downloading packages or replacing secrets."""
from pathlib import Path
import secrets
import sys
import venv

root = Path(__file__).resolve().parents[1]
if sys.version_info < (3, 11):
    raise SystemExit('Нужен Python 3.11 или новее')
if not (root / '.venv/bin/python').exists():
    venv.EnvBuilder(with_pip=False).create(root / '.venv')
env = root / '.env'
if not env.exists():
    text = (root / '.env.example').read_text(encoding='utf-8')
    text = text.replace('NEO4J_PASSWORD=\n', 'NEO4J_PASSWORD=' + secrets.token_urlsafe(24) + '\n')
    env.write_text(text, encoding='utf-8')
    env.chmod(0o600)
print('Готово. .env не перезаписывается. Внешние пакеты не нужны.')
print('Демонстрация: .venv/bin/python scripts/review.py')
print('Рабочая база: .venv/bin/python -m app.main init')
