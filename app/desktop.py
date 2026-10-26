"""User-scoped startup and desktop control; no root commands or embedded credentials."""
from pathlib import Path
import shutil
import subprocess

from .config import ROOT
from .graph_view import atomic_text
from .models import redact

UNIT = 'cti-platform-update.service'


def unit_quote(value):
    value = str(value)
    if '\n' in value or '\r' in value:
        raise ValueError('Перенос строки недопустим в пути запуска')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def unit_directory(value):
    """WorkingDirectory takes one literal path, unlike ExecStart's quoted words."""
    value = str(value)
    if not Path(value).is_absolute() or '\n' in value or '\r' in value:
        raise ValueError('Нужен абсолютный путь без переноса строки')
    # This directive expands unit specifiers, but neither shell variables nor
    # command-line quoting. Spaces and Unicode are literal path characters.
    return value.replace('%', '%%')


def desktop_quote(value):
    value = str(value)
    if '\n' in value or '\r' in value:
        raise ValueError('Перенос строки недопустим в пути запуска')
    value = value.replace('%', '%%')
    for char in ('\\', '"', '`', '$'):
        value = value.replace(char, '\\' + char)
    return '"' + value.replace('\\', '\\\\') + '"'


def service_text(root=ROOT):
    root = Path(root).resolve()
    python = root / '.venv/bin/python'
    helper = root / 'scripts/control_updates.py'
    command = ' '.join(unit_quote(v) for v in (python, '-m', 'app.main', 'worker', '--sync-graph'))
    before = ' '.join(unit_quote(v) for v in (python, helper, '--ensure-neo4j'))
    return f'''# Managed by CTI platform
[Unit]
Description=CTI passive collection and Neo4j refresh
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory={unit_directory(root)}
ExecStartPre=-{before}
ExecStart={command}
Restart=on-failure
RestartSec=15
TimeoutStartSec=120
TimeoutStopSec=90
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true

[Install]
WantedBy=default.target
'''


def desktop_text(root=ROOT):
    helper = Path(root).resolve() / 'scripts/control_updates.py'
    command = ' '.join(desktop_quote(v) for v in ('/usr/bin/python3', helper))
    return f'''[Desktop Entry]
Type=Application
Version=1.0
Name=CTI — аналитическая панель
Comment=Очередь проверки, доказательства, источники и обновление графа
Exec={command}
TryExec=/usr/bin/python3
Icon=network-workgroup
Terminal=false
Categories=Development;
Actions=Graph;Refresh;Stop;

[Desktop Action Graph]
Name=Открыть общий граф
Exec={command} --action graph

[Desktop Action Refresh]
Name=Обновить сейчас
Exec={command} --action refresh

[Desktop Action Stop]
Name=Приостановить сбор
Exec={command} --action stop
'''


def install(root=ROOT, home=None, desktop=None):
    home = Path(home) if home else Path.home()
    root = Path(root).resolve()
    unit = home / '.config/systemd/user' / UNIT
    entry = home / '.local/share/applications/cti-platform.desktop'
    atomic_text(unit, service_text(root))
    unit.chmod(0o644)
    atomic_text(entry, desktop_text(root))
    entry.chmod(0o755)
    # Enable the user unit through its normal WantedBy link. Starting it still
    # requires the user's session bus; installation itself needs only filesystem access.
    wanted = unit.parent / 'default.target.wants' / UNIT
    wanted.parent.mkdir(parents=True, exist_ok=True)
    if not wanted.exists() and not wanted.is_symlink():
        wanted.symlink_to(Path('..') / UNIT)
    paths = {'unit': str(unit), 'application': str(entry), 'autostart_link': str(wanted)}
    if desktop:
        launcher = Path(desktop) / 'CTI — граф и автообновление.desktop'
        atomic_text(launcher, desktop_text(root))
        launcher.chmod(0o755)
        paths['desktop'] = str(launcher)
    return paths


def _run(args, root=ROOT, timeout=15):
    try:
        done = subprocess.run(args, cwd=root, text=True, capture_output=True, timeout=timeout)
        return {'ok': done.returncode == 0, 'returncode': done.returncode,
                'output': redact((done.stdout + done.stderr).strip())[-2000:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'ok': False, 'output': type(exc).__name__}


def ensure_neo4j(root=ROOT):
    if not shutil.which('docker'):
        return {'ok': False, 'output': 'Docker не найден; сбор продолжится, Neo4j будет повторно проверяться.'}
    # Do not pull an image or request elevated access. An existing installation
    # can be started by a Docker-authorized desktop user.
    return _run(['docker', 'compose', '--profile', 'graph', 'up', '-d', '--no-build', '--pull', 'never', 'neo4j'], root, 90)


def service_status(root=ROOT):
    result = _run(['systemctl', '--user', 'is-active', UNIT], root, 3)
    return {'active': result['ok'] and result['output'].strip() == 'active',
            'message': result['output'], 'enabled': (Path.home() / '.config/systemd/user/default.target.wants' / UNIT).is_symlink()}


def control(action, root=ROOT):
    if action == 'start':
        install(root)
        reload = _run(['systemctl', '--user', 'daemon-reload'], root)
        if not reload['ok']:
            return reload
        return _run(['systemctl', '--user', 'restart', UNIT], root, 120)
    if action == 'stop':
        return _run(['systemctl', '--user', 'disable', '--now', UNIT], root, 100)
    if action == 'refresh':
        status = service_status(root)
        if not status['active']:
            return control('start', root)
        return _run(['systemctl', '--user', 'kill', '--kill-whom=main', '--signal=USR1', UNIT], root)
    raise ValueError('Неизвестное действие управления')
