"""Shared pause/refresh requests for desktop and container workers."""
import json
from pathlib import Path
import uuid

from .graph_view import atomic_text
from .models import utcnow


def read_json(path, default=None):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else ({} if default is None else default)
    except (OSError, ValueError):
        return {} if default is None else default


class WorkerControl:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.request_id = read_json(self.folder / 'request.json').get('id')

    @property
    def paused(self):
        return read_json(self.folder / 'preferences.json').get('paused') is True

    def refresh_requested(self):
        request = read_json(self.folder / 'request.json')
        if request.get('action') != 'refresh' or not isinstance(request.get('id'), str):
            return False
        if request['id'] == self.request_id:
            return False
        self.request_id = request['id']
        return True


def request(folder, action):
    folder = Path(folder)
    if action not in ('pause', 'resume', 'refresh'):
        raise ValueError('Неизвестное действие')
    if action in ('pause', 'resume'):
        atomic_text(folder / 'preferences.json', json.dumps({'paused': action == 'pause', 'changed_at': utcnow()}))
    else:
        if read_json(folder / 'preferences.json').get('paused') is True:
            raise ValueError('Сбор приостановлен. Сначала нажмите «Продолжить сбор».')
        atomic_text(folder / 'request.json', json.dumps({'id': uuid.uuid4().hex, 'action': 'refresh', 'requested_at': utcnow()}))
    return {'ok': True, 'action': action, 'requested_at': utcnow(),
            'message': {'pause': 'Сбор приостановится после текущего прохода.',
                        'resume': 'Сбор продолжится. Интервалы обращений к источникам сохраняются.',
                        'refresh': 'Обновление запрошено. Интервалы источников сохраняются.'}[action]}
