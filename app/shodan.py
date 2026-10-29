"""Read existing Shodan observations; never probe targets or request scans."""
from collections import Counter
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, parse_qsl
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .models import Publication, date_iso, digest, normalized, redact, utcnow

SOURCE = 'shodan_observations'
METHOD = 'shodan_existing_data'
MAX_BYTES = 2_000_000
MAX_RECORDS = 500
EXAMPLE = Path(__file__).resolve().parents[1] / 'examples/shodan_demo.json'


def _text(value, limit=300):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError('Shodan: текстовое поле имеет неверный тип')
    return redact(value.strip())[:limit] or None


def _strings(value, limit=100):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError('Shodan: слишком большой или неверный список')
    return sorted(set(filter(None, (_text(v) for v in value))))


def _timestamp(value):
    if value is None:
        return None, False
    if not isinstance(value, str):
        raise ValueError('Shodan: неверная дата наблюдения')
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('Shodan: неверная дата наблюдения') from None
    assumed = stamp.tzinfo is None
    if assumed:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).isoformat(timespec='seconds'), assumed


def _domain(value):
    value = (_text(value) or '').lower().rstrip('.')
    if not value:
        return None
    try:
        value = value.encode('idna').decode()
    except UnicodeError:
        return None
    if len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                                   for p in value.split('.')):
        return None
    return value


def decode_export(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('Shodan: импорт не более 2 МБ')
    try:
        text = raw.decode('utf-8-sig')
        def reject(value):
            raise ValueError('Shodan: нечисловое значение JSON')
        try:
            return json.loads(text, parse_constant=reject)
        except json.JSONDecodeError:
            return [json.loads(line, parse_constant=reject) for line in text.splitlines() if line.strip()]
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('Shodan: нужен JSON или JSONL в UTF-8') from None


def read_export(path):
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError('Shodan: файл превышает 2 МБ')
    if path.suffix == '.gz':
        try:
            with gzip.open(path, 'rb') as stream:
                raw = stream.read(MAX_BYTES + 1)
        except (OSError, EOFError):
            raise ValueError('Shodan: повреждённый gzip') from None
    else:
        raw = path.read_bytes()
    return decode_export(raw)


def normalize_export(payload, demo=False):
    """Whitelist service metadata; do not retain raw banners, cookies or API URLs."""
    parent = {}
    if isinstance(payload, dict):
        demo = demo or payload.get('_cti_example') == 'synthetic'
        if 'matches' in payload:
            records = payload['matches']
        elif isinstance(payload.get('data'), list):
            parent = payload
            records = payload['data']
        else:
            records = [payload]
    else:
        records = payload
    if not isinstance(records, list) or not records or len(records) > MAX_RECORDS:
        raise ValueError('Shodan: нужны от 1 до 500 наблюдений сервисов')
    result = []
    for raw in records:
        if not isinstance(raw, dict):
            raise ValueError('Shodan: запись сервиса должна быть объектом')
        try:
            address = raw.get('ip_str', parent.get('ip_str'))
            if not isinstance(address, str):
                raise ValueError()
            address = str(ipaddress.ip_address(address))
        except ValueError:
            raise ValueError('Shodan: нужен корректный ip_str') from None
        port, transport = raw.get('port'), raw.get('transport', 'tcp')
        if type(port) is not int or not 1 <= port <= 65535 or transport not in ('tcp', 'udp'):
            raise ValueError('Shodan: неверный порт или транспорт')
        observed, assumed = _timestamp(raw.get('timestamp'))
        hostnames = _strings(raw.get('hostnames', parent.get('hostnames')))
        domains = _strings(raw.get('domains', parent.get('domains')))
        http = raw.get('http')
        if http is None:
            http = {}
        if not isinstance(http, dict):
            raise ValueError('Shodan: неверное поле http')
        http_host = _domain(http.get('host'))
        vulnerabilities = raw.get('vulns')
        if vulnerabilities is None:
            vulnerabilities = {}
        if isinstance(vulnerabilities, list):
            if not all(isinstance(v, str) for v in vulnerabilities):
                raise ValueError('Shodan: некорректный список CVE')
            vulnerabilities = {v: {} for v in vulnerabilities}
        if not isinstance(vulnerabilities, dict) or len(vulnerabilities) > 200:
            raise ValueError('Shodan: неверный список CVE')
        vulns = []
        for cve, details in vulnerabilities.items():
            if not isinstance(cve, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve, re.I):
                raise ValueError('Shodan: некорректный CVE')
            if not isinstance(details, dict) or details.get('verified') not in (None, True, False):
                raise ValueError('Shodan: неверный статус проверки CVE')
            flag = details.get('verified')
            if flag is not None and type(flag) is not bool:
                raise ValueError('Shodan: verified должен быть boolean')
            vulns.append({'id': cve.upper(), 'verified_by_shodan': flag})
        result.append({'ip': address, 'port': port, 'transport': transport,
                       'observed_at': observed, 'timestamp_utc_assumed': assumed,
                       'product': _text(raw.get('product')), 'reported_version': _text(raw.get('version')),
                       'hostnames': hostnames, 'domains': domains, 'http_host': http_host,
                       'reported_org': _text(raw.get('org', parent.get('org'))),
                       'asn': _text(raw.get('asn', parent.get('asn'))),
                       'cpe': sorted(set(_strings(raw.get('cpe')) + _strings(raw.get('cpe23')))),
                       'vulnerabilities': sorted(vulns, key=lambda v: v['id']), 'is_demo': bool(demo)})
    return result


def is_observation(pub):
    return pub.source_id == SOURCE and pub.metadata.get('collection_method') == METHOD


def empty_extraction():
    return {'event_type': 'technical_observation', 'signals': [], 'assertions': [],
            'products': [], 'domains': [], 'cves': [], 'bdu_ids': [], 'entity_mentions': []}


def import_export(store, payload, *, demo=False, imported_at=None, origin='file'):
    observations = normalize_export(payload, demo)
    at = date_iso(imported_at or utcnow())
    publications = []
    for o in observations:
        # Identity includes the observed snapshot, never the import time.
        serialized = json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        external = digest(serialized)
        pub = Publication(SOURCE, 'https://www.shodan.io/host/' + o['ip'],
                          'Shodan: ' + o['ip'] + ':' + str(o['port']) + ' · ' + (o['product'] or 'продукт неизвестен'),
                          serialized, published_at=None, collected_at=at, external_id=external,
                          is_demo=o['is_demo'], metadata={'collection_method': METHOD,
                          'content_scope': 'synthetic_service_observation' if o['is_demo'] else 'third_party_service_observation',
                          'ingestion_method': origin, 'observation': o})
        publications.append(pub)
    counts = Counter()
    with store.connect() as db:
        for pub in publications:
            previous = db.execute('SELECT data FROM publications WHERE id=?', (pub.id,)).fetchone()
            if previous:
                review = json.loads(previous['data']).get('metadata', {}).get('association_review')
                if review:
                    pub.metadata['association_review'] = review
            counts[store.save_publication(pub, empty_extraction(), connection=db)] += 1
    return {'status': 'ok', 'observations': len(publications), 'counts': dict(counts),
            'ids': sorted({p.id for p in publications}), 'scores_changed_by_import': False}


def _candidates(observation, companies):
    # org/ASN/IP are deliberately not attribution rules. A hostname is only a lead.
    hosts = {_domain(h) for h in observation['hostnames']}
    hosts.add(observation.get('http_host'))
    result = []
    for c in companies:
        if bool(c.get('is_demo', False)) != observation['is_demo']:
            continue
        matches = sorted({h for h in hosts if h and any(
            (d := _domain(domain)) and (h == d or h.endswith('.' + d)) for domain in c.get('domains', []))})
        if matches:
            result.append({'id': c['id'], 'name': c['name'], 'matching_hostnames': matches})
    return result


def observations(store, *, now=None, include_demo=False, as_of=None):
    at = datetime.fromisoformat(date_iso(now or utcnow()))
    companies = store.companies()
    discovered = {}
    with store.connect() as db:
        for row in db.execute('SELECT d.publication_id,t.company_id,t.domain FROM shodan_discoveries d '
                              'JOIN shodan_targets t ON t.id=d.target_id'):
            discovered.setdefault(row['publication_id'], []).append({'company_id': row['company_id'], 'domain': row['domain']})
    result = []
    for demo in (False, True) if include_demo else (False,):
        for row in store.publications(demo, as_of=as_of):
            data = json.loads(row['data'])
            if row['source_id'] != SOURCE or data.get('metadata', {}).get('collection_method') != METHOD:
                continue
            o = data['metadata']['observation']
            observed = datetime.fromisoformat(o['observed_at']) if o['observed_at'] else None
            age = (at - observed).total_seconds() / 86400 if observed else None
            review = data['metadata'].get('association_review')
            candidates = _candidates(o, companies)
            result.append(dict(o, id=row['id'], source_url=row['url'], content_hash=row['content_hash'],
                               imported_at=row['collected_at'], last_seen_at=row['last_seen_at'],
                               age_days=None if age is None else round(age, 2),
                               freshness='unknown' if age is None else 'future' if age < 0 else 'stale' if age > 30 else 'recent',
                               association_review=review, company_candidates=candidates,
                               discovered_for=discovered.get(row['id'], []),
                               interpretation='Наблюдение стороннего источника. Версия по баннеру и CVE не устанавливают нынешнюю уязвимость компании.'))
    return sorted(result, key=lambda o: (o['observed_at'] or '', o['id']), reverse=True)


def review_association(store, identifier, company_id, status, reviewer, note, evidence_url):
    if not isinstance(identifier, str) or not isinstance(company_id, str):
        raise ValueError('Shodan: нужны идентификаторы наблюдения и компании')
    if status not in ('confirmed', 'refuted', 'needs_review'):
        raise ValueError('Shodan: неверный статус связи')
    if not isinstance(reviewer, str) or not reviewer.strip() or not isinstance(note, str) or not note.strip():
        raise ValueError('Shodan: нужны проверяющий и объяснение связи')
    url = urlsplit(evidence_url) if isinstance(evidence_url, str) else None
    if not url or url.scheme not in ('https', 'http') or not url.hostname or url.username or url.password:
        raise ValueError('Shodan: нужна публичная ссылка, обосновывающая принадлежность сервиса')
    if any(k.lower() in {'key', 'api_key', 'token', 'access_token', 'password'} for k, _ in parse_qsl(url.query)):
        raise ValueError('Shodan: ссылка на основание не должна содержать ключи или токены')
    with store.connect() as db:
        row = db.execute('SELECT data FROM publications WHERE id=? AND source_id=?', (identifier, SOURCE)).fetchone()
        company = db.execute('SELECT data FROM companies WHERE id=?', (company_id,)).fetchone()
        if not row or not company:
            raise ValueError('Shodan: наблюдение или компания не найдены')
        before = json.loads(row['data'])
        if bool(json.loads(company['data']).get('is_demo', False)) != before['is_demo']:
            raise ValueError('Shodan: демонстрационные наблюдения нельзя привязать к реальной компании')
        after = json.loads(row['data'])
        after['metadata']['association_review'] = {'company_id': company_id, 'status': status,
            'reviewer': redact(reviewer.strip())[:200], 'note': redact(note.strip())[:2000],
            'evidence_url': redact(evidence_url)[:2000], 'reviewed_at': utcnow()}
        from .storage import dumps
        db.execute('UPDATE publications SET data=? WHERE id=?', (dumps(after), identifier))
        db.execute('INSERT INTO publication_metadata_updates(publication_id,recorded_at,data) VALUES(?,?,?)',
                   (identifier, utcnow(), dumps({'before': before, 'after': after})))
    return {'status': 'ok', 'id': identifier, 'association_review': after['metadata']['association_review'],
            'scores_changed_by_review': False}


def review_available(review, as_of=None):
    if not review or review.get('status') != 'confirmed':
        return False
    return not as_of or datetime.fromisoformat(date_iso(review['reviewed_at'])) <= datetime.fromisoformat(date_iso(as_of))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_host(store, address, *, api_key=None, opener=None, now=None):
    """One explicit GET to the existing host database, with persistent request limits."""
    try:
        ip = ipaddress.ip_address(address)
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise ValueError()
    except ValueError:
        raise ValueError('Shodan API: нужен один публичный IP-адрес, без URL, сети или диапазона') from None
    def consume(payload, imported_at):
        rows = normalize_export(payload)
        if any(o['ip'] != str(ip) for o in rows):
            raise ValueError('host_mismatch')
        return import_export(store, payload, imported_at=imported_at, origin='api')
    return _api_request(store, '/shodan/host/' + str(ip), {}, 'shodan_host_' + digest(str(ip))[:16],
                        consume, api_key=api_key, opener=opener, now=now)


def _api_request(store, endpoint, params, source_id, consume, *, api_key=None, opener=None,
                 now=None, interval=3600, search=False):
    secret = api_key if api_key is not None else os.getenv('SHODAN_API_KEY', '')
    if not isinstance(secret, str) or not re.fullmatch(r'[A-Za-z0-9]{16,128}', secret):
        raise ValueError('Задайте SHODAN_API_KEY локально. Импорт JSON работает без ключа.')
    at = datetime.fromisoformat(date_iso(now or utcnow()))
    from .storage import dumps
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        for sid in ('shodan_api', source_id):
            last = db.execute('SELECT details FROM source_runs WHERE source_id=? ORDER BY id DESC LIMIT 1', (sid,)).fetchone()
            if last:
                until = json.loads(last['details']).get('next_allowed_at')
                if until and at < datetime.fromisoformat(until):
                    return {'status': 'cooldown', 'next_allowed_at': until, 'message': 'Интервал Shodan ещё не истёк'}
        if search:
            used = db.execute("SELECT attempted_at FROM source_runs WHERE source_id LIKE 'shodan_search_%' "
                              "AND status='requested' AND attempted_at>? ORDER BY attempted_at",
                              ((at - timedelta(days=1)).isoformat(),)).fetchall()
            if len(used) >= 10:
                until = (datetime.fromisoformat(used[0]['attempted_at']) + timedelta(days=1)).isoformat()
                return {'status': 'budget_exhausted', 'next_allowed_at': until,
                        'message': 'Достигнут лимит: 10 поисковых запросов за 24 часа'}
        for sid, seconds in (('shodan_api', 60), (source_id, interval)):
            db.execute('INSERT INTO source_runs(source_id,attempted_at,status,details) VALUES(?,?,?,?)',
                       (sid, at.isoformat(), 'requested', dumps({'next_allowed_at': (at + timedelta(seconds=seconds)).isoformat()})))
    request = Request('https://api.shodan.io' + endpoint + '?' + urlencode(dict(params, key=secret)),
                      headers={'Accept': 'application/json', 'User-Agent': 'CTI-Passive-Observations/1.0'})
    client = opener or build_opener(NoRedirect())
    try:
        with client.open(request, timeout=20) as response:
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('response_too_large')
        payload = decode_export(raw)
        payload = json.loads(json.dumps(payload).replace(secret, '[REDACTED]'))
        result = consume(payload, at.isoformat())
    except HTTPError as exc:
        code = {401: 'unauthorized', 403: 'forbidden', 404: 'not_found', 429: 'rate_limited'}.get(exc.code, 'http_error')
        retry = 3600
        if exc.code == 429:
            header = exc.headers.get('Retry-After', '') if exc.headers else ''
            if header.isdigit():
                retry = max(60, min(int(header), 86400))
            elif header:
                from email.utils import parsedate_to_datetime
                try:
                    retry = max(60, min(int((parsedate_to_datetime(header) - at).total_seconds()), 86400))
                except (ValueError, TypeError, OverflowError):
                    pass
        exc.close()
        result = {'status': 'error', 'error_code': code, 'http_status': exc.code,
                  'message': 'Shodan API отклонил чтение существующей записи'}
        if exc.code in (401, 403, 429):
            until = (at + timedelta(seconds=retry)).isoformat()
            store.source_run('shodan_api', code, {'next_allowed_at': until, 'error_code': code}, at.isoformat())
            result['next_allowed_at'] = until
    except (URLError, TimeoutError, ConnectionError, OSError):
        result = {'status': 'error', 'error_code': 'network_error', 'message': 'Не удалось прочитать данные Shodan'}
    except (ValueError, TypeError, KeyError) as exc:
        code = 'response_too_large' if str(exc) == 'response_too_large' else 'invalid_response'
        result = {'status': 'error', 'error_code': code, 'message': 'Shodan вернул непригодные данные'}
    seconds = interval if result['status'] == 'ok' else 3600 if result.get('http_status') in (401, 403) else 300
    result.setdefault('next_allowed_at', (at + timedelta(seconds=seconds)).isoformat())
    store.source_run(source_id, result['status'], result, at.isoformat())
    return result


def export_report(store, folder, include_demo=False):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    rows = observations(store, include_demo=include_demo)
    data = {'kind': 'third_party_service_observations', 'observations': rows, 'changes_company_indices': False}
    (folder / 'shodan.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    esc = lambda x: html.escape(str(x if x is not None else 'неизвестно'))
    cards = []
    for o in rows:
        cards.append('<article><h2>' + ('Вымышленный пример · ' if o['is_demo'] else '') + esc(o['ip']) + ':' + str(o['port']) + '</h2><p>' + esc(o['product']) + ' · версия по баннеру: ' + esc(o['reported_version']) + '</p><p>Наблюдение: ' + esc(o['observed_at']) + '; импорт: ' + esc(o['imported_at']) + '</p><p>' + esc(o['interpretation']) + '</p><pre>' + esc(json.dumps(o, ensure_ascii=False, indent=2)) + '</pre></article>')
    (folder / 'shodan.html').write_text('<!doctype html><meta charset="utf-8"><title>Shodan: технические наблюдения</title><style>body{font:16px/1.6 system-ui;max-width:1000px;margin:30px auto;padding:20px}article{border-top:1px solid #ccd;padding:15px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Технические наблюдения Shodan</h1><p>Данные стороннего источника. Принадлежность сервиса и применимость уязвимостей проверяются отдельно. Индексы компаний не изменяются.</p>' + ''.join(cards))
    return {'output': str(folder / 'shodan.html'), 'observations': len(rows)}
