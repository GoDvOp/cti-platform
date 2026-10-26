"""Open or start the local workbench without starting a second collector."""
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen

from .config import ROOT


def ensure_panel(root=ROOT, port=8765):
    root = Path(root).resolve()
    url = f'http://127.0.0.1:{port}'
    def available():
        try:
            with urlopen(url + '/health', timeout=1) as response:
                return json.load(response).get('service') == 'cti-workbench'
        except (OSError, ValueError):
            return False
    if available():
        return url
    folder = root / 'data/diagnostics/workbench'
    folder.mkdir(parents=True, exist_ok=True)
    python = root / '.venv/bin/python'
    if not python.is_file():
        python = Path(sys.executable)
    with (folder / 'server.log').open('a') as log:
        child = subprocess.Popen([str(python), '-m', 'app.workbench', '--port', str(port)],
                                 cwd=root, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                 start_new_session=True, close_fds=True)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if available():
            return url
        if child.poll() is not None:
            break
        time.sleep(.1)
    raise ValueError('Панель не запустилась. Проверьте, свободен ли порт ' + str(port)
                     + ', и журнал data/diagnostics/workbench/server.log')
