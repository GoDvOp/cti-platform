"""Editable company profiles, optimistic locking and persistent local overrides."""
import ipaddress
import json
import re
from urllib.parse import urlsplit

from .models import digest, utcnow
from .storage import dumps

FIELDS = {'name': 200, 'sector': 200, 'country': 100, 'description': 4000,
          'reference_url': 2000, 'domains': 50, 'aliases': 50}


def profile(company):
    return {key: company.get(key, [] if key in ('domains', 'aliases') else '') for key in FIELDS}


def revision(company):
    return digest(dumps(company))


def validate(data):
    if not isinstance(data, dict) or set(data) != set(FIELDS):
        raise ValueError('Заполните поля карточки компании')
    result = {}
    for key, limit in FIELDS.items():
        value = data[key]
        if key in ('domains', 'aliases'):
            if not isinstance(value, list) or len(value) > limit:
                raise ValueError('Не более 50 доменов и альтернативных названий')
            if any(not isinstance(v, str) or not v.strip() or len(v) > 253 for v in value):
                raise ValueError('Проверьте домены и альтернативные названия')
            value = list(dict.fromkeys(v.strip() for v in value))
        elif not isinstance(value, str) or len(value) > limit:
            raise ValueError('Поле слишком длинное или имеет неверный формат: ' + key)
        else:
            value = value.strip()
        result[key] = value
    if not result['name']:
        raise ValueError('Укажите название компании')
    domains = []
    for domain in result['domains']:
        try:
            domain = domain.rstrip('.').encode('idna').decode('ascii').lower()
        except UnicodeError:
            raise ValueError('Некорректный домен') from None
        if len(domain) > 253 or '.' not in domain or any(
                not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                for label in domain.split('.')):
            raise ValueError('Введите домен без URL, пути, порта или поискового запроса')
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError('Введите домен, а не IP-адрес')
        domains.append(domain)
    result['domains'] = list(dict.fromkeys(domains))
    url = result['reference_url']
    if url:
        try:
            parsed = urlsplit(url)
            valid = (parsed.scheme in ('http', 'https') and parsed.hostname
                     and not parsed.username and not parsed.password and parsed.port != 0
                     and not any(c.isspace() or ord(c) < 32 for c in url) and '\\' not in url)
        except ValueError:
            valid = False
        if not valid:
            raise ValueError('Укажите ссылку на сайт с http:// или https:// без пароля')
    return result


def save(store, body):
    if (not isinstance(body, dict) or set(body) != {'id', 'profile', 'revision'}
            or not isinstance(body['id'], str) or not isinstance(body['revision'], str)):
        raise ValueError('Передайте компанию, поля карточки и версию')
    values = validate(body['profile'])
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT data FROM companies WHERE id=?', (body['id'],)).fetchone()
        if not row:
            raise ValueError('Компания не найдена')
        before = json.loads(row['data'])
        if body['revision'] != revision(before):
            raise ValueError('Карточка уже изменена. Отмените редактирование, обновите страницу и повторите правку.')
        after = {**before, **values}
        if profile(before) != values:
            db.execute('UPDATE companies SET data=? WHERE id=?', (dumps(after), body['id']))
            db.execute('INSERT INTO company_overrides VALUES(?,?) ON CONFLICT(company_id) DO UPDATE SET data=excluded.data',
                       (body['id'], dumps(values)))
            db.execute('INSERT INTO company_edit_history(company_id,changed_at,before_data,after_data) VALUES(?,?,?,?)',
                       (body['id'], utcnow(), dumps(before), dumps(after)))
        else:
            after = before
    return {'status': 'ok', 'id': body['id'], 'profile': profile(after), 'revision': revision(after)}
