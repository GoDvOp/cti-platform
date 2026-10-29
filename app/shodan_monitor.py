"""Persistent domain discovery and daily refresh of analyst-confirmed public IPs."""
from datetime import datetime, timedelta
import ipaddress
import json
import os
import re

from . import shodan
from .models import date_iso, digest, utcnow

INTERVAL = 86400
SEARCH_LIMIT = 10


def configure_target(store, company_id, domain, enabled=True):
    if not isinstance(company_id, str) or not isinstance(domain, str) or type(enabled) is not bool:
        raise ValueError('Shodan: выберите компанию, домен и состояние наблюдения')
    domain = shodan._domain(domain)
    if not domain or '.' not in domain:
        raise ValueError('Shodan: нужен домен без URL, порта или поискового запроса')
    companies = {c['id']: c for c in store.companies()}
    company = companies.get(company_id)
    valid = (company and not company.get('is_demo') and
             domain in {shodan._domain(d) for d in company.get('domains', [])})
    identifier = digest(company_id + ':' + domain)
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        existing = db.execute('SELECT id FROM shodan_targets WHERE id=?', (identifier,)).fetchone()
        if not valid and (enabled or not existing):
            raise ValueError('Shodan: домен должен быть указан в каталоге реальной компании')
        if enabled:
            active = db.execute('SELECT count(*) FROM shodan_targets WHERE enabled=1 AND id<>?', (identifier,)).fetchone()[0]
            if active >= 50:
                raise ValueError('Shodan: не более 50 включённых доменов')
        db.execute('INSERT INTO shodan_targets VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled',
                   (identifier, company_id, domain, int(enabled), utcnow()))
    return {'status': 'ok', 'id': identifier, 'enabled': enabled}


def _runs(store):
    return {r['source_id']: dict(json.loads(r['details']), attempted_at=r['attempted_at'], status=r['status'])
            for r in store.source_status() if r['source_id'].startswith('shodan_')}


def _targets(store):
    companies = {c['id']: c for c in store.companies() if not c.get('is_demo')}
    with store.connect() as db:
        rows = [dict(r) for r in db.execute('SELECT * FROM shodan_targets ORDER BY created_at,id')]
    for row in rows:
        company = companies.get(row['company_id'], {})
        row['enabled'] = bool(row['enabled'])
        row['company_name'] = company.get('name', row['company_id'])
        row['catalog_valid'] = row['domain'] in {shodan._domain(d) for d in company.get('domains', [])}
    return rows


def monitor_status(store, now=None):
    at = datetime.fromisoformat(date_iso(now or utcnow()))
    runs = _runs(store)
    targets = _targets(store)
    for target in targets:
        target['last_run'] = runs.get('shodan_search_' + target['id'])
    with store.connect() as db:
        used = db.execute("SELECT count(*) FROM source_runs WHERE source_id LIKE 'shodan_search_%' "
                          "AND status='requested' AND attempted_at>?", ((at - timedelta(days=1)).isoformat(),)).fetchone()[0]
    return {'targets': targets, 'interval_hours': 24, 'search_limit_24h': SEARCH_LIMIT,
            'search_requests_24h': used, 'api_state': runs.get('shodan_api'),
            'host_refreshes': [dict(r, source_id=sid) for sid, r in runs.items() if sid.startswith('shodan_host_')]}


def fetch_domain(store, target_id, *, api_key=None, opener=None, now=None):
    target = next((t for t in _targets(store) if t['id'] == target_id), None)
    if not target or not target['enabled'] or not target['catalog_valid']:
        raise ValueError('Shodan: домен наблюдения отключён или отсутствует в каталоге')
    company = next(c for c in store.companies() if c['id'] == target['company_id'])
    domain = target['domain']

    def consume(payload, imported_at):
        if not isinstance(payload, dict) or not isinstance(payload.get('matches'), list):
            raise ValueError('invalid_search_response')
        matches, total = payload['matches'], payload.get('total')
        if type(total) is not int or total < len(matches) or len(matches) > 100:
            raise ValueError('invalid_search_response')
        rows = shodan.normalize_export(matches) if matches else []
        # Shodan hostname search can be broader than a DNS suffix. Keep only
        # independently visible matching names, never attribute by org or ASN.
        selected = [raw for raw, row in zip(matches, rows)
                    if ipaddress.ip_address(row['ip']).is_global and shodan._candidates(row, [company])
                    and any(h and (h == domain or h.endswith('.' + domain))
                            for h in [*(shodan._domain(v) for v in row['hostnames']), row['http_host']])]
        result = shodan.import_export(store, selected, imported_at=imported_at, origin='api_search') if selected else {
            'status': 'ok', 'observations': 0, 'counts': {}, 'ids': [], 'scores_changed_by_import': False}
        with store.connect() as db:
            db.executemany('INSERT OR IGNORE INTO shodan_discoveries VALUES(?,?)',
                           [(target_id, identifier) for identifier in result['ids']])
        return dict(result, domain=domain, company_id=target['company_id'], total=total,
                    returned=len(matches), discarded=len(matches) - len(selected), partial=total > len(matches))

    return shodan._api_request(store, '/shodan/host/search', {'query': 'hostname:"' + domain + '"', 'page': 1},
                               'shodan_search_' + target_id, consume, api_key=api_key,
                               opener=opener, now=now, interval=INTERVAL, search=True)


def _confirmed_hosts(store, companies):
    # A newer explicit revocation for a company/IP also stops polling that IP.
    latest = {}
    for o in shodan.observations(store):
        review = o.get('association_review')
        if not review or review['company_id'] not in companies:
            continue
        address = ipaddress.ip_address(o['ip'])
        if not address.is_global or address.is_multicast or address.is_reserved:
            continue
        key = (review['company_id'], o['ip'])
        current = latest.get(key)
        stamp = datetime.fromisoformat(date_iso(review['reviewed_at']))
        # On equal timestamps a revocation wins.
        priority = (stamp, review['status'] != 'confirmed')
        if current is None or priority >= current[0]:
            latest[key] = (priority, review['status'])
    return sorted({ip for (_, ip), (_, status) in latest.items() if status == 'confirmed'})


def poll(store, *, api_key=None, opener=None, now=None):
    """At most one request per worker tick; no sleeps or active target requests."""
    at = datetime.fromisoformat(date_iso(now or utcnow()))
    secret = api_key if api_key is not None else os.getenv('SHODAN_API_KEY', '')
    if not secret:
        return {'status': 'not_configured', 'message': 'Добавьте SHODAN_API_KEY в .env и пересоздайте воркер'}
    if not isinstance(secret, str) or not re.fullmatch(r'[A-Za-z0-9]{16,128}', secret):
        return {'status': 'invalid_key', 'message': 'Проверьте формат SHODAN_API_KEY в .env'}
    targets = [t for t in _targets(store) if t['enabled'] and t['catalog_valid']]
    if not targets:
        return {'status': 'no_targets', 'message': 'Выберите домены для наблюдения во вкладке Shodan'}
    runs = _runs(store)
    global_until = runs.get('shodan_api', {}).get('next_allowed_at')
    if global_until and at < datetime.fromisoformat(global_until):
        return {'status': 'cooldown', 'next_allowed_at': global_until}
    tasks = []
    budget = monitor_status(store, at.isoformat())['search_requests_24h'] >= SEARCH_LIMIT
    for target in targets:
        sid = 'shodan_search_' + target['id']
        last = runs.get(sid, {})
        until = last.get('next_allowed_at')
        if not budget and (not until or at >= datetime.fromisoformat(until)):
            tasks.append((last.get('attempted_at', ''), 'domain', target['id']))
    for ip in _confirmed_hosts(store, {t['company_id'] for t in targets}):
        sid = 'shodan_host_' + digest(ip)[:16]
        last = runs.get(sid, {})
        # Manual host lookups and worker lookups share cooldown state.
        until = last.get('next_allowed_at')
        if last.get('status') == 'ok':
            until = (datetime.fromisoformat(last['attempted_at']) + timedelta(days=1)).isoformat()
        if not until or at >= datetime.fromisoformat(until):
            tasks.append((last.get('attempted_at', ''), 'host', ip))
    if not tasks:
        return {'status': 'budget_exhausted' if budget else 'waiting', 'message':
                'Достигнут лимит поисковых запросов' if budget else 'Ожидание следующего обновления'}
    _, kind, value = min(tasks)
    try:
        result = (fetch_domain(store, value, api_key=secret, opener=opener, now=at.isoformat()) if kind == 'domain'
                  else shodan.fetch_host(store, value, api_key=secret, opener=opener, now=at.isoformat()))
    except ValueError:
        return {'status': 'error', 'message': 'Настройки наблюдения изменились; запрос отменён'}
    return dict(result, kind=kind, target=value)
