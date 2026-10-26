"""Public publisher news and bug bounty context; no assets, accounts or hidden APIs."""
from datetime import datetime
import json
import re
from urllib.parse import urlsplit
from .models import Publication, utcnow
from .russian_sources import Document, decode_html, same_source_url, item_context, listing_dates, parse_article_date


def structured_items(document):
    def walk(value, depth=0):
        if depth > 12:return
        if isinstance(value, dict):
            if value.get('url') and (value.get('headline') or value.get('name')):yield value
            for child in value.values():yield from walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value[:500]:yield from walk(child, depth + 1)
    for node in document.root.walk():
        if node.tag == 'script' and (node.attrs.get('type') == 'application/ld+json' or node.attrs.get('id') == '__NEXT_DATA__'):
            raw = ''.join(x for x in node.children if isinstance(x, str))
            try:yield from walk(json.loads(raw))
            except (ValueError, RecursionError):continue


def date_fields(node, payload=None, headers=None):
    stamp, day = parse_article_date(payload, headers) if payload else (None, None)
    if stamp or day:return stamp, day
    if not (stamp or day):
        text = node.text()
        match = re.search(r'(?:Date published|Дата публикации)\s*:?\s*(\d{2}\.\d{2}\.\d{4})', text, re.I)
        if match:
            try:day = datetime.strptime(match[1], '%d.%m.%Y').date().isoformat()
            except ValueError:pass
    if not (stamp or day):stamp, day=listing_dates(node)
    return stamp, day


def _metadata(source, stamp=None, day=None):
    return {'collection_method': source['kind'], 'discovery_url': source['url'],
            'source_role': source.get('role'), 'independence_group': source.get('independence_group', 'unknown'),
            'publication_day': day, 'date_precision': 'timestamp' if stamp else 'day' if day else 'unknown'}


def parse_listing(payload, source, headers=None, is_demo=False):
    document = Document(decode_html(payload, headers))
    program = source['kind'] == 'bounty_listing'
    expression = source['program_path'] if program else source['article_path']
    items = {}
    for anchor in document.root.walk():
        if anchor.tag != 'a' or not anchor.attrs.get('href'):continue
        try:url = same_source_url(anchor.attrs['href'], source)
        except ValueError:continue
        if not re.fullmatch(expression, urlsplit(url).path):continue
        context = item_context(anchor)
        headings = [n.text() for n in anchor.walk() if n.tag in ('h1', 'h2', 'h3', 'h4') and n.text()]
        if program:
            names = [n.text() for n in anchor.walk() if n.attrs.get('data-testid') == 'programName' and n.text()]
            if names:
                headings = names
        title = (headings[0] if headings else anchor.attrs.get('aria-label') or anchor.text()).strip()
        title = re.sub(r'^(?:Читать|Read)(?:\s+(?:more|далее))?\s*[–—:-]\s*', '', title, flags=re.I)
        if len(title) < 3 or title.lower() in ('read more', 'подробнее'):continue
        title = title[:350]
        stamp, day = date_fields(context) if not program else (None, None)
        metadata = _metadata(source, stamp, day)
        if program:
            metadata.update(content_scope='public_program_card', signal_scope='research_program',
                bug_bounty_program={'platform': source['platform'], 'url': url, 'name': title,
                                   'company_name': next((name for ref,name in source.get('program_company_map',{}).items() if ref.rstrip('/')==url.rstrip('/')),source.get('company_name'))})
            text = title
        else:
            paragraphs = [n.text() for n in context.walk() if n.tag == 'p' and n.text()]
            text = ' '.join(paragraphs)[:1800] or title
            metadata['content_scope'] = 'title_and_listing_summary' if paragraphs else 'title_only'
        pub = Publication(source['id'], url, title, text, published_at=stamp, is_demo=is_demo, external_id=url, metadata=metadata)
        if url not in items or (len(pub.text) > len(items[url].text) and not re.match(r'^(?:Читать|Read)\b', pub.title, re.I)):
            items[url] = pub
    for row in structured_items(document):
        try:url = same_source_url(row['url'], source)
        except (ValueError, TypeError):continue
        if url in items or not re.fullmatch(expression, urlsplit(url).path):continue
        title = str(row.get('headline') or row.get('name'))[:350]
        stamp=None
        meta = _metadata(source)
        if program:
            meta.update(signal_scope='research_program', content_scope='public_program_card',
                        bug_bounty_program={'platform': source['platform'], 'url': url, 'name': title,
                                            'company_name': next((name for ref,name in source.get('program_company_map',{}).items() if ref.rstrip('/')==url.rstrip('/')),source.get('company_name'))})
        else:
            raw = row.get('datePublished')
            if raw:
                from .models import date_iso
                try:stamp = date_iso(raw)
                except (ValueError, TypeError):stamp = None
                if stamp:meta.update(publication_day=stamp[:10], date_precision='timestamp')
                elif isinstance(raw,str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}',raw):
                    try:
                        datetime.strptime(raw,'%Y-%m-%d')
                        meta.update(publication_day=raw,date_precision='day')
                    except ValueError:pass
        items[url] = Publication(source['id'], url, title, str(row.get('description') or title)[:1800],
            published_at=stamp,
            is_demo=is_demo, external_id=url, metadata=meta)
    if not items:
        raise ValueError('В открытом HTML/JSON-LD нет карточек. Возможна JavaScript-страница или изменение вёрстки; закрытые API не используются.')
    return list(items.values())[:source.get('max_items', 25)], []


def parse_article(payload, source, headers=None, is_demo=False):
    document = Document(decode_html(payload, headers))
    heading = next((n for n in document.root.walk() if n.tag=='h1' and n.text()), None)
    if heading is None and source['kind']=='bounty_program':
        company=source.get('company_name','').casefold()
        heading=next((n for n in document.root.walk() if n.tag in ('h2','h3') and company and company in n.text().casefold()),None)
    if heading is None:raise ValueError('В публичной статье нет заголовка h1; возможно, требуется JavaScript')
    container = heading.parent
    while container.parent and container.tag not in ('article', 'main', 'body'):container=container.parent
    parts, started = [], False
    for node in container.walk():
        if node is heading:started=True;continue
        if not started or node.tag not in ('p','h2','h3','h4','li'):continue
        text=node.text()
        if source['kind']=='bounty_program' and node.tag.startswith('h') and re.search(r'scope|область|правила|rules|вознаграж|rewards',text,re.I):break
        if re.match(r'(Try out|Попробуйте|Previous article|Предыдущая статья|Related|Читайте также)', text, re.I):break
        if text and text not in parts:parts.append(text)
    text='\n'.join(parts)[:24000]
    if len(text)<30 and source['kind']!='bounty_program':raise ValueError('Публичная статья не содержит достаточного текста')
    stamp, day = date_fields(container, payload, headers)
    meta=_metadata(source,stamp,day);meta['content_scope']='public_article_text'
    if source['kind']=='bounty_program':
        company=source.get('company_name')
        if company and company.casefold() not in (heading.text()+' '+text).casefold():
            raise ValueError('На странице программы не подтверждено название организации')
        meta.update(signal_scope='research_program',content_scope='public_program_description',
            bug_bounty_program={'platform':source['platform'],'url':source['url'],'name':heading.text(),
                               'company_name':source.get('company_name')})
        # Retain only a short intro, never collect target scopes or researcher accounts.
        text='\n'.join(parts[:2])[:1800] or heading.text()
        stamp=None;meta.update(publication_day=None,date_precision='unknown')
    if source['kind']=='vendor_notice':
        name=source['product_name']
        affected=re.search(r'all versions up to and including\s+(\d+(?:\.\d+)+)',text,re.I)
        fixed=re.search(r'(?:upgrading|upgrade) to\s+'+re.escape(name)+r'\s+(\d+(?:\.\d+)+)',text,re.I)
        if name.casefold() not in (heading.text()+' '+text).casefold() or not affected or not fixed:
            raise ValueError('Уведомление не содержит явных продукта, границы затронутых версий и исправления')
        meta['security_notice']={'product_id':source['product_id'],'product_name':name,
            'affected_ranges':[{'lte':affected[1]}],'fixed_versions':[fixed[1]],
            'extraction_status':'parsed_vendor_statement','date_meaning':'publication',
            'conditions':'Требуется проверить ветку продукта, установленную версию, конфигурацию и обновление по исходному бюллетеню.'}
    return [Publication(source['id'],source['url'],heading.text(),text,published_at=stamp,is_demo=is_demo,
                        external_id=source['url'],metadata=meta)], []
