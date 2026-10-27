"""Bounded RSS/Atom collection. Never follows article links or queries targets."""
from collections import Counter
from datetime import datetime, timedelta
import math
import socket
import ssl
import time
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
import xml.etree.ElementTree as ET
from .models import Publication, date_iso, utcnow
from .extraction import extract
from .russian_sources import parse_listing, json_links, parse_nckci_json

MAX_BYTES = 2_000_000
USER_AGENT = 'CTI-Intern-Research/1.0'


class CollectionError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def validate_sources(sources):
    if not isinstance(sources, list):
        raise ValueError('Конфигурация источников должна быть списком')
    ids = set()
    for source in sources:
        if not isinstance(source, dict) or not re.fullmatch(r'[a-z0-9_-]{1,80}', source.get('id', '')):
            raise ValueError('Некорректный source_id в конфигурации')
        if source['id'] in ids:
            raise ValueError('Повтор source_id: ' + source['id'])
        ids.add(source['id'])
        if source.get('kind', 'rss') not in ('rss', 'securelist_listing', 'nckci_listing', 'nckci_json',
                                           'vendor_advisories', 'vendor_case', 'cisa_kev',
                                           'bounty_listing', 'bounty_program', 'publisher_news', 'vendor_notice'):
            raise ValueError('Неизвестный адаптер: ' + source['id'])
        hosts = source.get('allowed_hosts', [])
        if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) for h in hosts):
            raise ValueError('Нужен список allowed_hosts: ' + source['id'])
        validate_feed_url(source.get('url', ''), hosts)
        for key, lower, upper in [('polling_minutes', 1, 10080), ('retry_minutes', 1, 10080),
                                   ('max_items', 1, 500), ('max_json_documents', 0, 3),
                                   ('max_date_documents', 0, 20), ('max_article_documents', 0, 5), ('freshness_days', 1, 3650)]:
            if key in source and (type(source[key]) not in (float, int) or not lower <= source[key] <= upper):
                raise ValueError('Некорректный ' + key + ': ' + source['id'])
        for key in ('max_items', 'max_json_documents', 'max_date_documents', 'max_article_documents', 'freshness_days'):
            if key in source and type(source[key]) is not int:
                raise ValueError(key + ' должен быть целым')
        for key in ({'bounty_listing': ('program_path', 'platform'), 'bounty_program': ('platform',),
                     'publisher_news': ('article_path',), 'vendor_notice': ('product_id', 'product_name')}
                    .get(source.get('kind'), ())):
            if not isinstance(source.get(key), str) or not source[key].strip():
                raise ValueError('Нужен ' + key + ': ' + source['id'])
            if key.endswith('_path'):
                try:
                    re.compile(source[key])
                except re.error as exc:
                    raise ValueError('Некорректный шаблон пути: ' + source['id']) from exc
    return sources


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def plain(text):
    p = TextOnly()
    p.feed(text or '')
    return ' '.join(' '.join(p.parts).split())


def child_text(node, names):
    for child in node:
        if child.tag.rsplit('}', 1)[-1] in names:
            return ''.join(child.itertext()).strip()
    return ''


def parse_feed(payload, source_id, is_demo=False, collected_at=None):
    if len(payload) > MAX_BYTES or re.search(rb'<!\s*(DOCTYPE|ENTITY)', payload.replace(b'\x00', b''), re.I):
        raise ValueError('Недопустимый XML: размер или DTD/ENTITY')
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValueError('Некорректный RSS/Atom XML') from exc
    nodes = [n for n in root.iter() if n.tag.rsplit('}', 1)[-1] in ('item', 'entry')]
    if root.tag.rsplit('}', 1)[-1] not in ('rss', 'feed', 'RDF'):
        raise ValueError('Ответ не является RSS/Atom')
    publications, errors = [], []
    for node in nodes[:500]:
        try:
            url = child_text(node, {'link'})
            if not url:
                url = next((c.get('href') for c in node if c.tag.rsplit('}', 1)[-1] == 'link'
                            and c.get('rel', 'alternate') == 'alternate' and c.get('href')), '')
            title = plain(child_text(node, {'title'}))
            content = plain(child_text(node, {'description', 'summary', 'content', 'encoded'})) or title
            raw_date = child_text(node, {'pubDate', 'published', 'date'})
            try:
                published_at = date_iso(raw_date)
            except (ValueError, TypeError, OverflowError):
                published_at = None
                errors.append('invalid_date')
            publications.append(Publication(
                source_id=source_id, url=url, title=title, text=content,
                published_at=published_at, collected_at=collected_at or utcnow(),
                author=child_text(node, {'creator', 'author'}) or None, is_demo=is_demo,
                external_id=child_text(node, {'guid', 'id'}) or None))
        except (ValueError, TypeError):
            errors.append('invalid_item')
    if nodes and not publications:
        raise ValueError('Все элементы feed отклонены')
    return publications, errors


class LimitedRedirect(HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_feed_url(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_feed_url(url, hosts):
    p = urlsplit(url)
    if p.scheme != 'https' or p.hostname not in hosts or p.username or p.password or p.port not in (None, 443):
        raise ValueError('Feed должен быть HTTPS на разрешённом хосте')


def fetch(url, hosts, headers=None):
    validate_feed_url(url, hosts)
    req = Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/rss+xml, application/atom+xml, application/json, text/html, text/xml',
                                **(headers or {})})
    opener = build_opener(LimitedRedirect(hosts))
    with opener.open(req, timeout=12) as response:
        data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError('Ответ источника превышает 2 МБ')
        return data, dict(response.headers)


class RobotsPolicy:
    """User-agent selection, longest rule, * and $ support for our public sources."""
    def __init__(self, text):
        groups, agents, rules, delay = [], [], [], 0
        has_directives = False
        for raw in text.splitlines():
            key, sep, value = raw.split('#', 1)[0].partition(':')
            if not sep:
                continue
            key, value = key.strip().lower(), value.strip()
            if key == 'user-agent':
                if has_directives:
                    groups.append((agents, rules, delay))
                    agents, rules, delay, has_directives = [], [], 0, False
                agents.append(value.lower())
            elif agents and key in ('allow', 'disallow', 'crawl-delay'):
                has_directives = True
                if key == 'crawl-delay':
                    try:
                        candidate = float(value)
                        if math.isfinite(candidate) and candidate >= 0:
                            delay = candidate
                    except ValueError:
                        pass
                elif value:
                    rules.append((key == 'allow', value))
        if agents:
            groups.append((agents, rules, delay))
        specific = [(max(len(a) for a in aa if a != '*' and a in USER_AGENT.lower()), rr, dd)
                    for aa, rr, dd in groups if any(a != '*' and a in USER_AGENT.lower() for a in aa)]
        chosen = [(rr, dd) for length, rr, dd in specific if length == max(x[0] for x in specific)] if specific else [
            (rr, dd) for aa, rr, dd in groups if '*' in aa]
        self.rules = [rule for rr, _ in chosen for rule in rr]
        self.delay = max((dd for _, dd in chosen), default=0)

    def allowed(self, url):
        p = urlsplit(url)
        path = p.path + ('?' + p.query if p.query else '')
        matches = []
        for allow, pattern in self.rules:
            anchored = pattern.endswith('$')
            value = pattern[:-1] if anchored else pattern
            expression = '^' + re.escape(value).replace(r'\*', '.*') + ('$' if anchored else '')
            if re.search(expression, path):
                matches.append((len(value.replace('*', '')), allow))
        return max(matches)[1] if matches else True


def robots_allowed(source):
    if time.monotonic() - source.get('_robots_fetched_at', time.monotonic()) > 86400:
        source.pop('_robots_policy', None)
    if '_robots_policy' not in source:
        host = urlsplit(source['url']).netloc
        try:
            data, _ = fetch('https://' + host + '/robots.txt', source['allowed_hosts'])
        except HTTPError as exc:
            if exc.code in (404, 410):
                # A missing robots file differs from a network failure (RFC 9309).
                data = b''
                source['_robots_status'] = 'not_published'
            else:
                exc.cti_stage = 'robots'
                raise
        source['_last_request_at'] = time.monotonic()
        source['_robots_fetched_at'] = time.monotonic()
        source['_robots_policy'] = RobotsPolicy(data.decode('utf-8-sig', errors='replace'))
    policy = source['_robots_policy']
    if policy.delay > 10:
        raise CollectionError('crawl_delay', 'Crawl-delay больше 10 секунд; нужен отдельный планировщик запросов')
    source['_request_delay'] = max(1, policy.delay)
    return policy.allowed(source['url'])


def checked_fetch(source, url):
    # Every follow-up uses the same robots policy and host allowlist as its listing.
    validate_feed_url(url, source['allowed_hosts'])
    check = dict(source, url=url)
    if not robots_allowed(check):
        raise CollectionError('robots_denied', 'Путь запрещён правилами robots.txt')
    source.update({k: v for k, v in check.items() if k.startswith('_')})
    if '_last_request_at' in source:
        wait = source.get('_request_delay', 1) - (time.monotonic() - source['_last_request_at'])
        if wait > 0:
            time.sleep(wait)
    try:
        return fetch(url, source['allowed_hosts'])
    finally:
        source['_last_request_at'] = time.monotonic()


def error_details(exc, stage):
    # Use categories only: exception strings may include credentials or upstream content.
    details = {'stage': getattr(exc, 'cti_stage', stage)}
    if isinstance(exc, CollectionError):
        details.update(error_code=exc.code, message=str(exc))
    elif isinstance(exc, HTTPError):
        details.update(error_code='http_' + str(exc.code), http_status=exc.code,
                       message='Источник вернул HTTP ' + str(exc.code))
        retry = exc.headers.get('Retry-After') if exc.headers else None
        if retry:
            try:
                seconds = int(retry)
            except ValueError:
                try:
                    seconds = math.ceil((datetime.fromisoformat(date_iso(retry)) -
                                         datetime.fromisoformat(utcnow())).total_seconds())
                except (ValueError, TypeError, OverflowError):
                    seconds = 0
            if seconds > 0:
                details['retry_after_seconds'] = seconds
    else:
        reason = exc.reason if isinstance(exc, URLError) else exc
        if isinstance(reason, socket.gaierror):
            code, msg = 'dns_error', 'Не удалось разрешить имя источника'
        elif isinstance(reason, (TimeoutError, socket.timeout)):
            code, msg = 'timeout', 'Источник не ответил за отведённое время'
        elif isinstance(reason, ssl.SSLError):
            code, msg = 'tls_error', 'Не удалось проверить защищённое соединение'
        elif isinstance(reason, PermissionError):
            code, msg = 'network_permission', 'Среда запрещает сетевое соединение'
        elif isinstance(reason, ConnectionRefusedError):
            code, msg = 'connection_refused', 'Источник отклонил соединение'
        elif isinstance(exc, ValueError):
            code, msg = 'invalid_format', 'Ответ не соответствует ожидаемому формату источника'
        else:
            code, msg = 'network_error', 'Сетевая ошибка при обращении к источнику'
        details.update(error_code=code, message=msg)
    return details


def next_attempt(previous, source):
    details = previous.get('details', {})
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except ValueError:
            details = {}
    if details.get('next_allowed_at'):
        return datetime.fromisoformat(details['next_allowed_at'])
    minutes = source.get('polling_minutes', 60) if previous['status'] == 'ok' else source.get('retry_minutes', 15)
    return datetime.fromisoformat(previous['attempted_at']) + timedelta(minutes=minutes)


def source_status(store, sources, as_of=None):
    from .freshness import audit
    validate_sources(sources)
    ages = {r['source_id']: r['freshness'] for r in audit(store, sources, as_of=as_of)}
    previous = {r['source_id']: r for r in store.source_status()}
    now = datetime.fromisoformat(as_of or utcnow())
    results = []
    for source in sources:
        row = previous.get(source['id'])
        details = row.get('details', {}) if row else {}
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except ValueError:
                details = {}
        at = next_attempt(row, source) if row else None
        results.append({'source_id': source['id'], 'kind': source.get('kind', 'rss'),
                        'url': source['url'], 'enabled': source.get('enabled', True),
                        'status': ('disabled' if not source.get('enabled', True) else row['status'] if row else 'never_checked'),
                        'last_status': row['status'] if row else None,
                        'disabled_reason': source.get('disabled_reason'),
                        'attempted_at': row['attempted_at'] if row else None,
                        'next_allowed_at': at.isoformat() if at else None,
                        'wait_seconds': max(0, math.ceil((at - now).total_seconds())) if at else 0,
                        'freshness': ages[source['id']],
                        'freshness_mode': source.get('freshness_mode', 'monitoring'),
                        'details': details})
    # Keep provenance of historical sources even if removed from the active config.
    for sid, row in previous.items():
        if not any(r['source_id'] == sid for r in results):
            results.append(dict(row, enabled=False, configured=False))
    return results


def parse_source(payload, source, headers=None, is_demo=False):
    kind = source.get('kind', 'rss')
    if kind in ('bounty_listing', 'publisher_news', 'bounty_program', 'vendor_notice'):
        from .public_sources import parse_listing as parse_public_listing, parse_article as parse_public_article
        parser = parse_public_listing if kind in ('bounty_listing', 'publisher_news') else parse_public_article
        return parser(payload, source, headers, is_demo)
    if kind == 'rss':
        return parse_feed(payload, source['id'], is_demo)
    if kind == 'cisa_kev':
        from .kev import parse_kev
        return parse_kev(payload, source, is_demo)
    if kind in ('securelist_listing', 'nckci_listing'):
        return parse_listing(payload, source, headers, is_demo=is_demo)
    if kind == 'nckci_json':
        return parse_nckci_json(payload, source, source['url'], is_demo=is_demo)
    if kind in ('vendor_advisories', 'vendor_case'):
        from .vendor_sources import parse_advisory_table, parse_case
        parser = parse_advisory_table if kind == 'vendor_advisories' else parse_case
        return parser(payload, source, headers, is_demo=is_demo)
    raise ValueError('Неизвестный адаптер')


def ingest(store, publications):
    counts = Counter()
    companies = store.companies()
    products = store.products()
    for pub in publications:
        from .shodan import is_observation, empty_extraction
        extraction = (empty_extraction() if is_observation(pub) else
                      extract(pub, companies, products, store.entities(pub.is_demo)))
        counts[store.save_publication(pub, extraction)] += 1
        for assertion in extraction.get('assertions', []):
            store.add_assertion(assertion)
    return dict(counts)


def import_jsonl(store, path, demo=False):
    items = []
    path = Path(path)
    if path.stat().st_size > 10_000_000:
        raise ValueError('Импорт не более 10 МБ за запуск')
    for index, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            # Do not silently turn demo rows into real observations.
            if bool(data.get('is_demo', False)) != demo:
                raise ValueError('Маркер is_demo не соответствует режиму импорта')
            items.append(Publication(**data))
        except (ValueError, TypeError) as exc:
            raise ValueError(f'Строка {index}: {exc}') from exc
    # Validate complete input before changing storage.
    return ingest(store, items)


def collect_source(store, source, runtime=None):
    validate_sources([source])
    source = dict(source)  # Runtime robots policy is never written to config/logs.
    host = urlsplit(source['url']).netloc
    if runtime is not None:
        source.update(runtime.get(host, {}))
    if not source.get('enabled', True):
        return {'source_id': source['id'], 'status': 'disabled'}
    previous = next((r for r in store.source_status() if r['source_id'] == source['id']), None)
    now = datetime.fromisoformat(utcnow())
    if previous:
        at = next_attempt(previous, source)
        if now < at:
            details = previous['details']
            if isinstance(details, str):
                details = json.loads(details)
            return {'source_id': source['id'], 'status': 'cooldown',
                    'previous_status': previous['status'], 'previous_error_code': details.get('error_code'),
                    'next_allowed_at': at.isoformat(), 'wait_seconds': math.ceil((at - now).total_seconds()),
                    'message': 'Интервал ещё не истёк; новый запрос не выполнялся'}
    stage = 'robots_or_download'
    try:
        payload, headers = checked_fetch(source, source['url'])
        if source.get('_capture_public_response'):
            capture = Path(source['_capture_public_response'])
            capture.mkdir(parents=True, exist_ok=True)
            (capture / (source['id'] + '.html')).write_bytes(payload)
        stage = 'parse'
        publications, errors = parse_source(payload, source, headers)
        warnings = []
        if source.get('kind') == 'publisher_news':
            from .public_sources import parse_article
            enriched = []
            for pub in publications[:source.get('max_article_documents', 0)]:
                try:
                    detail, detail_headers = checked_fetch(source, pub.url)
                    detail_source = dict(source, url=pub.url)
                    items, item_errors = parse_article(detail, detail_source, detail_headers)
                    enriched.extend(items)
                    errors.extend(item_errors)
                except (URLError, OSError, ValueError) as exc:
                    warnings.append(error_details(exc, 'public_article'))
            replacements = {p.url: p for p in enriched}
            publications = [replacements.get(p.url, p) for p in publications]
        if source.get('kind') == 'securelist_listing' and source.get('max_date_documents', 0):
            from .russian_sources import parse_article_date
            saved = {r['id']: json.loads(r['data']) for r in store.publications()}
            candidates = []
            for pub in publications:
                old = saved.get(pub.id, {})
                if not pub.published_at and not pub.metadata.get('publication_day'):
                    pub.published_at = old.get('published_at')
                    for key in ('publication_day', 'date_precision', 'date_source_url'):
                        if old.get('metadata', {}).get(key) is not None:
                            pub.metadata[key] = old['metadata'][key]
                    if not pub.published_at and not pub.metadata.get('publication_day'):
                        candidates.append(pub)
            for pub in candidates[:source['max_date_documents']]:
                try:
                    detail, detail_headers = checked_fetch(source, pub.url)
                    stamp, day = parse_article_date(detail, detail_headers)
                    if stamp or day:
                        pub.published_at = stamp
                        pub.metadata.update(publication_day=day, date_source_url=pub.url,
                                            date_precision='timestamp' if stamp else 'day')
                    else:
                        warnings.append({'stage': 'article_date', 'error_code': 'publication_date_not_found'})
                except (URLError, OSError, ValueError) as exc:
                    warnings.append(error_details(exc, 'article_date'))
        # NCKCI: newest limited JSON-labelled detail pages, then explicit JSON link.
        if source.get('kind') == 'nckci_listing':
            candidates = [p for p in publications if p.metadata.get('attachment_format') == 'json']
            for pub in candidates[:source.get('max_json_documents', 2)]:
                try:
                    detail, detail_headers = checked_fetch(source, pub.url)
                    links = json_links(detail, source, pub.url, detail_headers)
                    if not links:
                        raise CollectionError('json_link_not_found', 'В карточке не найдена явная ссылка .json')
                    for link in links:
                        data, _ = checked_fetch(source, link)
                        items, item_errors = parse_nckci_json(data, source, link)
                        publications.extend(items)
                        errors.extend(item_errors)
                except (URLError, OSError, ValueError) as exc:
                    warnings.append(error_details(exc, 'json_attachment'))
        from .freshness import summarize
        freshness = summarize([p.asdict() for p in publications], source.get('freshness_days', 30))
        if source.get('freshness_days') and source.get('freshness_mode') != 'reference_catalog':
            if freshness['status'] in ('stale', 'unknown', 'future_dates', 'empty'):
                warnings.append({'stage': 'freshness', 'error_code': 'data_' + freshness['status']})
            elif freshness['unknown']:
                warnings.append({'stage': 'freshness', 'error_code': 'missing_dates', 'count': freshness['unknown']})
        result = {'counts': ingest(store, publications), 'parse_warnings': dict(Counter(errors)),
                  'freshness': freshness,
                  'items': len(publications), 'warnings': warnings,
                  'next_allowed_at': (datetime.fromisoformat(utcnow()) +
                                      timedelta(minutes=source.get('polling_minutes', 60))).isoformat()}
        status = 'partial' if warnings or errors else 'ok'
        store.source_run(source['id'], status, result)
        return {'source_id': source['id'], 'status': status, **result}
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, ET.ParseError) as exc:
        result = error_details(exc, stage)
        seconds = max(source.get('retry_minutes', 15) * 60, result.get('retry_after_seconds', 0))
        result['next_allowed_at'] = (datetime.fromisoformat(utcnow()) + timedelta(seconds=seconds)).isoformat()
        store.source_run(source['id'], 'error', result)
        return {'source_id': source['id'], 'status': 'error', **result}
    finally:
        if runtime is not None:
            runtime[host] = {k:v for k,v in source.items() if k.startswith('_')}
