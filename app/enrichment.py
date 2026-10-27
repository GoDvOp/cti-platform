"""Local enrichment and reproducible graph demonstrations; no target probes."""
import json
from pathlib import Path
from .models import Publication, utcnow
from .collectors import ingest
from .knowledge import exposure_rows, claim_id


def reindex(store, demo=False):
    pubs = [Publication(**json.loads(p['data'])) for p in store.publications(demo)]
    result = ingest(store, pubs)
    return {'publications': len(pubs), 'counts': result,
            'assertions': len(store.assertions(demo)), 'exposures': len(exposure_rows(store, demo))}


def import_assertions(store, path):
    records = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(records, list):
        raise ValueError('Ожидается список связей')
    return [store.add_assertion(row) for row in records]


def expand_knowledge(store, root):
    """Import the reviewed research library without overwriting analyst decisions."""
    data = json.loads((root / 'examples/research_library.json').read_text(encoding='utf-8'))
    company_ids = {c['id'] for c in store.companies()}
    product_ids = {p['id'] for p in store.products()}
    catalogue_companies = json.loads((root / 'config/companies.json').read_text(encoding='utf-8'))
    catalogue_products = json.loads((root / 'config/products.json').read_text(encoding='utf-8'))
    store.load_companies([c for c in catalogue_companies if c['id'] not in company_ids])
    store.load_products([p for p in catalogue_products if p['id'] not in product_ids])
    pubs = {}
    for record in data['publications']:
        row = dict(record)
        key = row.pop('key')
        pubs[key] = Publication(**row)
    counts = ingest(store, list(pubs.values()))
    previous = {a['id']: a for a in store.assertions()}
    reviewed, preserved = 0, 0
    for record in data['claims']:
        row = dict(record)
        key = row.pop('publication_key')
        note = row.pop('review_note')
        row['publication_id'] = pubs[key].id
        identifier = claim_id(row['publication_id'], row['kind'], row['subject'], row['object'])
        old = previous.get(identifier)
        if old and old['status'] in ('confirmed', 'refuted') and old['evidence_hash'] == pubs[key].content_hash:
            preserved += 1
            continue
        identifier = store.add_assertion(row)
        if (old and old['status'] in ('confirmed', 'refuted') and
                old['evidence_hash'] == pubs[key].content_hash and old['attributes'] == row.get('attributes', {})
                and old['excerpt'] == row['excerpt']):
            preserved += 1
            continue
        store.review_assertion(identifier, 'confirmed', 'project_source_review', note)
        reviewed += 1
    return {'counts': counts, 'library_publications': len(pubs), 'library_claims': len(data['claims']),
            'reviewed': reviewed, 'existing_reviews_preserved': preserved,
            'companies': len(store.companies()), 'products': len(store.products()),
            'provenance': data['provenance']}


def seed_knowledge(store, root):
    """Three verified public source summaries. No invented installed versions."""
    data = json.loads((root / 'examples/knowledge_seed.json').read_text(encoding='utf-8'))
    pubs = [Publication(**row) for row in data['publications']]
    result = ingest(store, pubs)
    by_url = {p.url: p for p in pubs}
    ids = []
    previous = {a['id']: a for a in store.assertions()}
    for claim in data['claims']:
        row = dict(claim)
        url = row.pop('publication_url')
        note = row.pop('review_note')
        row['publication_id'] = by_url[url].id
        identifier = claim_id(row['publication_id'], row['kind'], row['subject'], row['object'])
        old = previous.get(identifier)
        if old and old['status'] in ('confirmed', 'refuted') and old['evidence_hash'] == by_url[url].content_hash:
            ids.append(identifier)
            continue
        identifier = store.add_assertion(row)
        store.review_assertion(identifier, 'confirmed', 'project_source_review', note)
        ids.append(identifier)
    return {'counts': result, 'reviewed_assertions': ids,
            'provenance': 'Краткие пересказы открытых первоисточников, проверенных веб-поиском; не результат RSS.',
            'exposures': exposure_rows(store)}


def demo_knowledge(store):
    if store.publications(False):
        raise ValueError('Для демонстрации используйте отдельную БД')
    store.load_products([{'id': 'demo-server', 'name': 'Учебный Сервер', 'vendor': 'Учебный поставщик',
                          'aliases': [], 'is_demo': True}])
    now = utcnow()
    docs = [
        ('use-alpha', 'Учебное внедрение Альфы', 'Учебная Альфа использует Учебный Сервер версии 1.2.3.'),
        ('use-beta', 'Учебное внедрение Беты', 'Учебная Бета использует Учебный Сервер, версия не указана.'),
        ('advisory', 'Учебное уведомление об уязвимости',
         'Уязвимость CVE-2099-20001 затрагивает Учебный Сервер версии 1.2.3. Исправление: 1.2.4.'),
        ('supplier', 'Учебная связь организаций', 'Учебная Бета поставляет услуги Учебная Альфа.'),
    ]
    pubs = [Publication('demo_knowledge', 'https://knowledge.example/' + slug, title, text,
                        published_at=now, is_demo=True) for slug, title, text in docs]
    counts = ingest(store, pubs)
    attributes = {'uses_product': {'observed_day': now[:10]},
                  'affects_product': {'affected_versions': ['1.2.3'], 'fixed_versions': ['1.2.4']},
                  'supplies_to': {'observed_day': now[:10]}}
    for assertion in store.assertions(True):
        if assertion['publication']['source_id'] != 'demo_knowledge':
            continue
        row = {k: assertion[k] for k in ('kind', 'subject', 'object', 'publication_id', 'excerpt')}
        row['attributes'] = dict(attributes.get(row['kind'], {}))
        if row['kind'] == 'uses_product' and row['subject'] == 'demo-alpha':
            row['attributes']['version'] = '1.2.3'
        identifier = store.add_assertion(row)
        store.review_assertion(identifier, 'confirmed', 'учебная проверка', 'Вымышленный пример для проверки графа',
                               confidence='medium', basis='research_report')
    return {'warning': 'Все данные вымышлены', 'counts': counts, 'exposures': exposure_rows(store, True)}
