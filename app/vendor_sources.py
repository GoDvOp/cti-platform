"""Bounded public vendor pages; no querying customer infrastructure."""
from datetime import datetime
import re
from .models import Publication, utcnow
from .russian_sources import Document, decode_html, listing_dates

IDENTIFIER = re.compile(r'\b(?:CVE-\d{4}-\d{4,}|BDU:\d{4}-\d{4,})\b', re.I)
PRODUCTS = {'TrueConf Server': 'trueconf-server', 'TrueConf Client': 'trueconf-client'}


def parse_advisory_table(payload, source, headers=None, is_demo=False):
    document = Document(decode_html(payload, headers))
    result = {}
    for row in document.root.walk():
        if row.tag != 'tr':
            continue
        cells = [n.text() for n in row.children if hasattr(n, 'tag') and n.tag in ('td', 'th')]
        identifier_index = next((i for i, text in enumerate(cells) if IDENTIFIER.search(text)), None)
        if identifier_index is None:
            continue
        rest = cells[identifier_index:]
        if len(rest) < 3:
            continue
        identifier = IDENTIFIER.search(rest[0])[0].upper()
        name, versions = rest[1].strip(), rest[2].strip()
        # Product identity comes from the row, never a footer or neighbouring row.
        product_id = PRODUCTS.get(name)
        if not product_id or not versions:
            continue
        text = f'{identifier}: {name}; затронутые версии по таблице: {versions}.'
        attrs = {'affected_version_text': versions}
        if re.fullmatch(r'\d+(?:\.\d+){1,4}', versions):
            attrs['affected_versions'] = [versions]
        # Do not expand x branches, platform conditions or vague "before" values.
        result[identifier] = Publication(source_id=source['id'], url=source['url'],
            title=identifier + ' — ' + name, text=text, is_demo=is_demo,
            external_id='vendor-table:' + identifier,
            metadata={'collection_method':'vendor_table','content_scope':'advisory_table_row',
                      'date_precision':'unknown','independence_group':source.get('independence_group','trueconf'),
                      'vendor_record':{'identifier':identifier,'product_id':product_id,'attributes':attrs}})
    if not result:
        raise ValueError('В таблице не найдены строки с CVE/BDU, продуктом и версией')
    return list(result.values())[:source.get('max_items', 100)], []


def parse_case(payload, source, headers=None, is_demo=False):
    document = Document(decode_html(payload, headers))
    nodes = list(document.root.walk())
    heading = next((n for n in nodes if n.tag == 'h1' and len(n.text()) >= 12), None)
    if heading is None:
        raise ValueError('В кейсе внедрения не найден заголовок')
    root = heading.parent
    while root and root.tag not in ('article', 'main', 'body', 'document'):
        root = root.parent
    root = root or document.root
    parts, started = [], False
    for node in root.walk():
        if node is heading:
            started = True
            continue
        if not started or node.tag not in ('p', 'h2', 'h3', 'h4', 'li'):
            continue
        text = node.text()
        if re.match(r'(?:Попробуйте|Разверните собственный|Предыдущая статья|Следующая статья|Комментарии|Try out)', text, re.I):
            break
        if text and text not in parts:
            parts.append(text)
    text = '\n'.join(parts)
    if len(text) < 50:
        raise ValueError('Кейс не содержит достаточного текста проекта')
    stamp, day = listing_dates(root)
    match = re.search(r'Дата публикации\s*:\s*(\d{2}\.\d{2}\.\d{4})', root.text())
    if match and not stamp:
        day = datetime.strptime(match[1], '%d.%m.%Y').date().isoformat()
    return [Publication(source_id=source['id'], url=source['url'], title=heading.text(), text=text,
                        published_at=stamp, is_demo=is_demo, external_id=source['url'],
                        metadata={'collection_method':'vendor_case','content_scope':'public_case_text',
                                  'publication_day':day,'date_precision':'timestamp' if stamp else 'day' if day else 'unknown',
                                  'independence_group':source.get('independence_group','trueconf')})], []
