"""Desktop panel for automatic passive collection and the combined CTI graph."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import threading
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.desktop import install, control, service_status, ensure_neo4j
from app.graph_view import atomic_text
from app.models import utcnow


def remember(action, result):
    value = {'checked_at': utcnow(), 'action': action, **result}
    atomic_text(ROOT / 'data/diagnostics/auto_update/control.json', json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    return value


def open_graph():
    path = ROOT / 'data/processed/real/graph_view.html'
    if path.exists():
        webbrowser.open(path.as_uri())
        return {'ok': True, 'output': 'Открыт общий граф. Страница обновляется раз в минуту.'}
    return {'ok': False, 'output': 'Граф ещё готовится. Включите автообновление и дождитесь первого прохода.'}


def main():
    parser = argparse.ArgumentParser(description='Панель CTI без терминала')
    parser.add_argument('--install-only', action='store_true')
    parser.add_argument('--ensure-neo4j', action='store_true')
    parser.add_argument('--action', choices=['start', 'stop', 'refresh', 'graph'])
    args = parser.parse_args()
    if args.ensure_neo4j:
        result = remember('ensure_neo4j', ensure_neo4j())
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result['ok'] else 1
    if args.install_only:
        desktop = subprocess.run(['xdg-user-dir', 'DESKTOP'], text=True, capture_output=True)
        folder = desktop.stdout.strip() if desktop.returncode == 0 else None
        paths = install(desktop=folder)
        result = remember('install', {'ok': True, 'paths': paths, 'output': 'Ярлык и автозапуск установлены. Панель открывается ярлыком; запуск службы описан в docs/auto_update.md.'})
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    from app.workbench_launcher import ensure_panel
    from app.workbench_control import request as panel_request
    from app.workbench_data import runtime
    try:
        if args.action in ('start', 'stop', 'refresh'):
            state = runtime(ROOT)
            if state['controls_available']:
                operation = {'start': 'resume', 'stop': 'pause', 'refresh': 'refresh'}[args.action]
                remember(args.action, panel_request(ROOT / 'data/diagnostics/auto_update', operation))
            elif args.action == 'start':
                remember(args.action, control('start'))
        url = ensure_panel()
        webbrowser.open(url + ('/graph' if args.action == 'graph' else '/'))
        print('Панель CTI: ' + url)
        return 0
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
