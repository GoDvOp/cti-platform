"""CISA KEV catalog records: inclusion date is not an incident/publication date."""
from datetime import date
import hashlib
import json
import re
from .models import Publication, date_iso


def parse_kev(payload, source, is_demo=False):
    if len(payload) > 2_000_000:
        raise ValueError('KEV больше 2 МБ')
    data = json.loads(payload.decode('utf-8-sig'))
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
        raise ValueError('Неизвестная схема CISA KEV')
    released = date_iso(data.get('dateReleased'))
    if not released or not data.get('catalogVersion') or data.get('count') != len(data['vulnerabilities']):
        raise ValueError('Неполный каталог CISA KEV')
    records, errors = [], []
    for item in data['vulnerabilities']:
        try:
            if not isinstance(item, dict) or not re.fullmatch(r'CVE-\d{4}-\d{4,19}', item.get('cveID', '')):
                raise ValueError('CVE')
            added = date.fromisoformat(item['dateAdded']).isoformat()
            required = ('vendorProject', 'product', 'vulnerabilityName', 'shortDescription', 'requiredAction')
            if not all(isinstance(item.get(k), str) and item[k].strip() for k in required):
                raise ValueError('Пустая запись KEV')
            records.append((added, item))
        except (ValueError, TypeError, KeyError):
            errors.append('invalid_kev_record')
    if not records:
        raise ValueError('Каталог KEV не содержит допустимых записей')
    # Catalog order is not guaranteed; an old CVE may have been added recently.
    records.sort(key=lambda pair: (pair[0], pair[1]['cveID']), reverse=True)
    pubs = []
    fingerprint = hashlib.sha256(payload).hexdigest()
    for added, item in records[:source.get('max_items', 100)]:
        cve = item['cveID']
        text = (f'{cve}: {item["vendorProject"]} / {item["product"]}. '
                f'{item["shortDescription"]}\nCISA KEV dateAdded: {added}. '
                f'Required action: {item["requiredAction"]}')
        pubs.append(Publication(source_id=source['id'], url=source['url'],
            title=cve + ' — ' + item['vulnerabilityName'], text=text,
            external_id=cve, is_demo=is_demo,
            metadata={'collection_method': 'cisa_kev_json', 'content_scope': 'catalog_record',
                      'source_role': 'vulnerability_context', 'date_precision': 'day',
                      'catalog_added_day': added, 'catalog_version': data['catalogVersion'],
                      'catalog_released_at': released, 'catalog_sha256': fingerprint,
                      'known_ransomware_campaign_use': item.get('knownRansomwareCampaignUse', 'Unknown'),
                      'notes': item.get('notes', ''),
                      'interpretation': 'Включение в KEV не доказывает атаку на компанию из нашей выборки.'}))
    return pubs, errors
