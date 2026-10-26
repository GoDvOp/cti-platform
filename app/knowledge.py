"""Evidence-backed assertions and conservative product/CVE applicability.

Extraction creates review candidates. Co-occurrence alone never asserts product
use. Only confirmed, fresh assertions participate in version applicability.
"""
from datetime import datetime, date
import json
import re
from .models import digest, normalized, utcnow, identifier_text

# Fixed endpoint types are also the only labels permitted in graph queries.
THREAT_KINDS = {
    'incident_affects': ('Incident', 'Company', 'AFFECTED_ORGANIZATION'),
    'incident_exploited': ('Incident', 'Vulnerability', 'EXPLOITED'),
    'incident_malware': ('Incident', 'Malware', 'INVOLVED_MALWARE'),
    'incident_product': ('Incident', 'Product', 'INVOLVED_PRODUCT'),
    'attributed_to': ('Incident', 'ThreatActor', 'ATTRIBUTED_TO'),
    'claimed_by': ('Incident', 'ThreatActor', 'CLAIMED_BY'),
    'actor_exploits': ('ThreatActor', 'Vulnerability', 'REPORTED_EXPLOITS'),
    'actor_uses_malware': ('ThreatActor', 'Malware', 'USES_MALWARE'),
    'actor_overlap': ('ThreatActor', 'ThreatActor', 'REPORTED_OVERLAP'),
    'actor_cooperates': ('ThreatActor', 'ThreatActor', 'COOPERATES_WITH'),
    'incident_part_of': ('Incident', 'Incident', 'PART_OF_CAMPAIGN'),
}
KINDS = {'uses_product', 'affects_product', 'part_of', 'subsidiary_of', 'supplies_to', 'partners_with'} | set(THREAT_KINDS)
VERSION_RE = re.compile(r'^\d+(?:\.\d+){1,4}$')
VULNERABILITY_RE = re.compile(r'\b(?:CVE-\d{4}-\d{4,}|BDU:\d{4}-\d{4,})\b', re.I)


def mentions(aliases, text):
    return any(re.search(r'(?<!\w)' + re.escape(normalized(a)) + r'(?!\w)', normalized(text))
               for a in aliases if a)


def scope_id(value, demo=False):
    return ('demo:' if demo else 'real:') + value


def claim_id(pub_id, kind, subject, obj):
    return digest('|'.join([pub_id, kind, subject, obj]))[:24]


def candidate(pub, kind, subject, obj, excerpt):
    return {'id': claim_id(pub.id, kind, subject, obj), 'publication_id': pub.id,
            'kind': kind, 'subject': subject, 'object': obj, 'excerpt': excerpt.strip()[:1000],
            'evidence_hash': pub.content_hash, 'status': 'needs_review',
            'attributes': {}, 'is_demo': pub.is_demo, 'extractor_version': 'relations-v1'}


def extract_relations(pub, companies, products):
    if pub.metadata.get('signal_scope') == 'research_program':
        return {'products': [], 'assertions': []}
    result, product_ids = {}, set()
    company_list = [c for c in companies if bool(c.get('is_demo', False)) == pub.is_demo
                    and c.get('monitor_target', True)]
    product_list = [p for p in products if bool(p.get('is_demo', False)) == pub.is_demo]
    fragments = re.split(r'[\n!?;]+|\.\s+', pub.title + '\n' + pub.text)
    for fragment in fragments:
        matching_products = [p for p in product_list if mentions([p['name'], *p.get('aliases', [])], fragment)]
        product_ids.update(p['id'] for p in matching_products)
        if len(fragment.strip()) > 1000:
            continue
        matching_companies = [c for c in company_list if mentions([c['name'], *c.get('aliases', [])], fragment)]
        # Denials and proposed deployments require context; do not turn them into use claims.
        if re.search(r'не\s+(использ|примен|затраг|принадлеж|входит)|отказал|планир|планируется|не подтвержд', fragment, re.I):
            continue
        for product in matching_products:
            if re.search(r'использ|внедри|разверну|развёрну|на базе|на платформе|uses|deployed', fragment, re.I):
                for company in matching_companies:
                    row = candidate(pub, 'uses_product', company['id'], product['id'], fragment)
                    result[row['id']] = row
            if re.search(r'уязвим|затронут|vulnerab|affected', fragment, re.I):
                # Multiple products/CVEs in one sentence are ambiguous; retain mentions only.
                cves = sorted(set(x.upper() for x in VULNERABILITY_RE.findall(identifier_text(fragment))))
                if len(matching_products) == 1 and len(cves) == 1:
                    row = candidate(pub, 'affects_product', cves[0], product['id'], fragment)
                    result[row['id']] = row
        if len(matching_companies) == 2:
            left, right = matching_companies
            # Replace longest aliases first, preserving the direction in the sentence.
            marked = normalized(fragment)
            tokens = {left['id']: '<0>', right['id']: '<1>'}
            aliases = [(a, c['id']) for c in (left, right) for a in [c['name'], *c.get('aliases', [])]]
            for alias, cid in sorted(aliases, key=lambda x: -len(x[0])):
                marked = re.sub(r'(?<!\w)' + re.escape(normalized(alias)) + r'(?!\w)',
                                lambda m: tokens[cid], marked)
            for a, b in [(left, right), (right, left)]:
                prefix, suffix = re.escape(tokens[a['id']]), re.escape(tokens[b['id']])
                for kind, verb in [('part_of', r'(?:входит в(?: состав)?|принадлежит)'),
                                   ('subsidiary_of', r'является дочерней компанией'),
                                   ('supplies_to', r'поставляет(?:\s+[^<>]{0,60})?'),
                                   ('partners_with', r'сотрудничает с')]:
                    if re.search(prefix + r'\s+(?:—\s*)?' + verb + r'\s+' + suffix, marked):
                        row = candidate(pub, kind, a['id'], b['id'], fragment)
                        result[row['id']] = row
    record = pub.metadata.get('vendor_record')
    if isinstance(record, dict):
        product = next((p for p in product_list if p['id'] == record.get('product_id')), None)
        identifier = record.get('identifier', '')
        if product and VULNERABILITY_RE.fullmatch(identifier) and identifier in identifier_text(pub.text).upper():
            row = candidate(pub, 'affects_product', identifier, product['id'], pub.text[:1000])
            row['attributes'] = record.get('attributes', {})
            result[row['id']] = row
            product_ids.add(product['id'])
    return {'products': sorted(product_ids), 'assertions': list(result.values())}


def validate_attributes(kind, attrs):
    if not isinstance(attrs, dict):
        raise ValueError('attributes должен быть объектом')
    if attrs.get('observed_day'):
        date.fromisoformat(attrs['observed_day'])
    if attrs.get('version') is not None and not VERSION_RE.fullmatch(str(attrs['version'])):
        raise ValueError('Поддерживается только точная числовая версия с точками')
    for name in ('affected_versions', 'fixed_versions'):
        if name in attrs and (not isinstance(attrs[name], list) or
                              not all(isinstance(v, str) and VERSION_RE.fullmatch(v) for v in attrs[name])):
            raise ValueError(name + ': нужен список точных числовых версий')
    if 'affected_ranges' in attrs:
        if not isinstance(attrs['affected_ranges'], list):
            raise ValueError('affected_ranges должен быть списком')
        for bound in attrs['affected_ranges']:
            if not isinstance(bound, dict) or not bound or set(bound) - {'gte', 'gt', 'lte', 'lt'}:
                raise ValueError('Диапазон версий: допустимы gte, gt, lte, lt')
            if not all(isinstance(v, str) and VERSION_RE.fullmatch(v) for v in bound.values()):
                raise ValueError('Границы версий должны быть точными числовыми версиями')
    allowed = {'observed_day', 'note', 'version', 'affected_versions', 'affected_ranges', 'fixed_versions',
               'affected_version_text', 'conditions', 'confidence', 'basis', 'attribution_scope',
               'network_exposure', 'network_exposure_note'}
    if 'network_exposure' in attrs:
        if kind != 'uses_product' or attrs['network_exposure'] not in ('unknown', 'closed_network', 'internet_reported'):
            raise ValueError('network_exposure относится к uses_product: unknown, closed_network, internet_reported')
        if not isinstance(attrs.get('network_exposure_note'), str) or not attrs['network_exposure_note'].strip():
            raise ValueError('Нужно текстовое основание network_exposure_note')
    if kind in THREAT_KINDS:
        if attrs.get('confidence') not in ('low', 'medium', 'high'):
            raise ValueError('Для связи инцидента/группировки нужна confidence: low, medium, high')
        if attrs.get('basis') not in ('victim_report', 'research_report', 'vendor_advisory',
                                      'government_advisory', 'legal_allegation', 'attacker_claim'):
            raise ValueError('Нужно явно указать basis связи инцидента/группировки')
        if kind == 'claimed_by' and attrs['basis'] != 'attacker_claim':
            raise ValueError('claimed_by сохраняет только заявление об ответственности')
        if kind == 'attributed_to' and attrs['basis'] == 'attacker_claim':
            raise ValueError('Заявление группировки не подтверждает атрибуцию; используйте claimed_by')
        if kind == 'actor_cooperates' and not attrs.get('note'):
            raise ValueError('Сотрудничество требует описания основания')
    if set(attrs) - allowed:
        raise ValueError('Неизвестные атрибуты связи')
    if kind != 'affects_product' and any(k in attrs for k in ('affected_versions', 'affected_ranges', 'fixed_versions')):
        raise ValueError('Диапазоны применимы только к связи affects_product')
    if kind != 'uses_product' and 'version' in attrs:
        raise ValueError('Установленная версия относится к uses_product')


def version_tuple(value):
    if not VERSION_RE.fullmatch(str(value)):
        raise ValueError('Неизвестный формат версии')
    parts = [int(p) for p in value.split('.')]
    return tuple(parts + [0] * (5 - len(parts)))


def version_match(version, attrs):
    if not version:
        return None
    v = version_tuple(version)
    # Fixed versions are never silently interpreted as affected ranges.
    exact = attrs.get('affected_versions', [])
    ranges = attrs.get('affected_ranges', [])
    if not exact and not ranges:
        return None
    if any(v == version_tuple(x) for x in exact):
        return True
    for bound in ranges:
        if all({'gte': v >= version_tuple(value), 'gt': v > version_tuple(value),
                'lte': v <= version_tuple(value), 'lt': v < version_tuple(value)}[key]
               for key, value in bound.items()):
            return True
    return False


def assertion_day(assertion):
    pub = assertion['publication']
    content = json.loads(pub['data'])
    return (assertion.get('attributes', {}).get('observed_day') or
            (pub['published_at'][:10] if pub['published_at'] else None) or
            content.get('metadata', {}).get('publication_day'))


def age_status(assertion, as_of=None, max_age_days=180):
    day = assertion_day(assertion)
    if not day:
        return 'date_unknown'
    at = date.fromisoformat((as_of or utcnow())[:10])
    age = (at - date.fromisoformat(day)).days
    return 'future' if age < 0 else 'historical' if age > max_age_days else 'recent'


def exposure_rows(store, demo=False, as_of=None):
    assertions = store.assertions(demo)
    uses = [a for a in assertions if a['kind'] == 'uses_product']
    affects = [a for a in assertions if a['kind'] == 'affects_product']
    rows = []
    for use in uses:
        for advisory in affects:
            if use['object'] != advisory['object']:
                continue
            if 'refuted' in (use['status'], advisory['status']):
                continue
            if age_status(advisory, as_of) == 'future' or age_status(use, as_of) == 'future':
                status = 'future_evidence'
            elif 'confirmed' != use['status'] or 'confirmed' != advisory['status']:
                status = 'needs_review'
            elif age_status(use, as_of) != 'recent':
                status = 'historical_use_only' if age_status(use, as_of) == 'historical' else 'use_date_unknown'
                if age_status(use, as_of) == 'future':
                    status = 'future_evidence'
            else:
                matches = version_match(use['attributes'].get('version'), advisory['attributes'])
                status = ('version_match_requires_configuration_check' if matches is True else
                          'version_outside_reported_range' if matches is False else
                          'version_unknown' if not use['attributes'].get('version') else 'affected_range_unknown')
            rows.append({'id': digest(use['id'] + advisory['id'])[:24], 'company_id': use['subject'],
                         'product_id': use['object'], 'cve': advisory['subject'], 'status': status,
                         'vulnerability_id': advisory['subject'],
                         'installed_version': use['attributes'].get('version'),
                         'use_assertion_id': use['id'], 'advisory_assertion_id': advisory['id'],
                         'use_source_url': use['publication']['url'],
                         'advisory_source_url': advisory['publication']['url'], 'is_demo': demo,
                         'interpretation': 'Требуется проверка применимости; факт уязвимости или компрометации не установлен'})
    # Several publications can describe the same advisory. Keep all evidence,
    # but show one result per use context, identifier and applicability state.
    merged = {}
    for row in rows:
        key = (row['use_assertion_id'], row['vulnerability_id'], row['status'], row['installed_version'])
        if key not in merged:
            merged[key] = dict(row, advisory_assertion_ids=[], advisory_source_urls=[])
        entry = merged[key]
        if row['advisory_assertion_id'] not in entry['advisory_assertion_ids']:
            entry['advisory_assertion_ids'].append(row['advisory_assertion_id'])
        if row['advisory_source_url'] not in entry['advisory_source_urls']:
            entry['advisory_source_urls'].append(row['advisory_source_url'])
    return list(merged.values())
