"""Source-specific parsers of public Russian listings and vulnerability JSON.

No site-wide crawl: a listing is fetched once; NCKCI may follow only a bounded
number of its own advisory pages and explicitly linked JSON attachments.
"""
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
import json
import re
from urllib.parse import urljoin, urlsplit
from .models import Publication, canonical_url, date_iso, utcnow

CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}


@dataclass(eq=False)
class Node:
    tag: str
    attrs: dict = field(default_factory=dict)
    children: list = field(default_factory=list)
    parent: object = None

    def text(self):
        if self.tag in ('script', 'style', 'noscript', 'svg'):
            return ''
        return ' '.join(' '.join(c.text() if isinstance(c, Node) else c for c in self.children).split())

    def walk(self):
        yield self
        for child in self.children:
            if isinstance(child, Node):
                yield from child.walk()


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.root = Node('document')
        self.stack = [self.root]
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        if len(self.stack) > 128:
            raise ValueError('Слишком глубокая вложенность HTML')
        node = Node(tag, dict(attrs), parent=self.stack[-1])
        self.stack[-1].children.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                self.stack = self.stack[:i]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def decode_html(payload, headers=None):
    if len(payload) > 2_000_000:
        raise ValueError('HTML больше 2 МБ')
    content_type = next((v for k, v in (headers or {}).items() if k.lower() == 'content-type'), '')
    declaration = content_type + ' ' + payload[:2048].decode('ascii', errors='ignore')
    match = re.search(r'charset\s*=\s*[\"\']?([a-zA-Z0-9_-]+)', declaration, re.I)
    charset = match[1] if match else 'utf-8'
    if charset.lower() not in ('utf-8', 'utf8', 'windows-1251', 'cp1251', 'utf-8-sig'):
        raise ValueError('Неподдерживаемая кодировка HTML')
    return payload.decode(charset, errors='replace')


def same_source_url(href, source, base=None):
    url = canonical_url(urljoin(base or source['url'], href))
    p = urlsplit(url)
    if p.scheme != 'https' or p.hostname not in source['allowed_hosts'] or p.port not in (None, 443):
        raise ValueError('Ссылка за пределами разрешённого источника')
    return url


def item_context(anchor):
    """Use a short nearest card; never absorb a whole listing or adjacent articles."""
    node = anchor.parent
    for _ in range(5):
        if node is None or node.tag in ('body', 'html', 'document', 'main', 'section'):
            break
        text = node.text()
        headings = sum(n.tag in ('h1', 'h2', 'h3', 'h4') for n in node.walk())
        if (node.tag in ('article', 'li') or re.search(r'(?:^|[ _-])(item|card|entry|post)(?:$|[ _-])',
                                                    node.attrs.get('class', ''))):
            if len(text) <= 2500 and headings <= 1:
                return node
        node = node.parent
    return anchor.parent if anchor.parent is not None else anchor


def listing_dates(node):
    timestamp, day = None, None
    for child in node.walk():
        if child.tag == 'time' and child.attrs.get('datetime'):
            raw = child.attrs['datetime']
            try:
                timestamp = date_iso(raw)
            except (ValueError, TypeError):
                if re.fullmatch(r'\d{4}-\d{2}-\d{2}', raw):
                    day = raw
            break
    if day is None and timestamp is None:
        match = re.search(r'\b(\d{2})\.(\d{2})\.(\d{4})\b', node.text())
        if match:
            try:
                day = datetime.strptime(match[0], '%d.%m.%Y').date().isoformat()
            except ValueError:
                pass
        if day is None:
            months = {'янв': 1, 'фев': 2, 'мар': 3, 'апр': 4, 'мая': 5, 'май': 5, 'июн': 6,
                      'июл': 7, 'авг': 8, 'сен': 9, 'окт': 10, 'ноя': 11, 'дек': 12}
            match = re.search(r'\b(\d{1,2})\s+([а-яА-Я]+)\.?\s+(\d{4})\b', node.text())
            if match and match[2][:3].lower() in months:
                try:
                    day = datetime(int(match[3]), months[match[2][:3].lower()], int(match[1])).date().isoformat()
                except ValueError:
                    pass
    return timestamp, day


def parse_article_date(payload, headers=None):
    """Read only explicit publication metadata; never use modified/copyright dates."""
    document = Document(decode_html(payload, headers))
    for node in document.root.walk():
        if node.tag != 'meta':
            continue
        label = node.attrs.get('property', node.attrs.get('name', node.attrs.get('itemprop', '')))
        if label not in ('article:published_time', 'datePublished'):
            continue
        raw = node.attrs.get('content', '')
        try:
            stamp = date_iso(raw)
            if stamp:
                return stamp, None
        except (ValueError, TypeError, OverflowError):
            if re.fullmatch(r'\d{4}-\d{2}-\d{2}', raw):
                try:
                    return None, datetime.strptime(raw, '%Y-%m-%d').date().isoformat()
                except ValueError:
                    pass
    return None, None


def parse_listing(payload, source, headers=None, collected_at=None, is_demo=False):
    document = Document(decode_html(payload, headers))
    kind = source['kind']
    entries = {}
    for anchor in document.root.walk():
        if anchor.tag != 'a' or not anchor.attrs.get('href'):
            continue
        try:
            url = same_source_url(anchor.attrs['href'], source)
        except ValueError:
            continue
        path = urlsplit(url).path
        title = anchor.text()
        if kind == 'securelist_listing':
            if not re.fullmatch(r'(?:/[a-zA-Z0-9_-]+)+/\d+/?', path) or len(title) < 12:
                continue
            if not any(n.tag.startswith('h') and n.tag in ('h1', 'h2', 'h3', 'h4')
                       for n in (anchor.parent, *list(anchor.walk())) if n):
                continue
        elif kind == 'nckci_listing':
            if not re.fullmatch(r'/materialy/uyazvimosti/\d+/?', path) or not re.search(r'уязвимост', title, re.I):
                continue
        else:
            raise ValueError('Неизвестный HTML-адаптер')
        context = item_context(anchor)
        paragraphs = [n.text() for n in context.walk() if n.tag == 'p' and n.text()]
        summary = ' '.join(paragraphs)[:1800]
        stamp, day = listing_dates(context)
        meta = {'collection_method': 'public_listing', 'discovery_url': source['url'],
                'source_role': source.get('role'), 'publication_day': day,
                'date_precision': 'timestamp' if stamp else 'day' if day else 'unknown',
                'content_scope': 'title_and_listing_summary' if summary else 'title_only'}
        if kind == 'nckci_listing':
            advisory = re.search(r'VULN\.\d{4}-\d{2}-\d{2}\.\d+', title, re.I)
            meta.update(advisory_id=advisory[0].upper() if advisory else None,
                        attachment_format='json' if re.search(r'\bJSON\b', title, re.I) else 'pdf')
        pub = Publication(source_id=source['id'], url=url, title=title, text=summary or title,
                          published_at=stamp, collected_at=collected_at or utcnow(),
                          is_demo=is_demo, external_id=url, metadata=meta)
        previous = entries.get(url)
        if previous is None or len(pub.text) > len(previous.text):
            entries[url] = pub
    if not entries:
        raise ValueError('В HTML не найдены ожидаемые карточки; возможно, изменилась вёрстка')
    return list(entries.values())[:source.get('max_items', 30)], []


def json_links(payload, source, page_url, headers=None):
    result = []
    for anchor in Document(decode_html(payload, headers)).root.walk():
        if anchor.tag != 'a' or not anchor.attrs.get('href'):
            continue
        try:
            url = same_source_url(anchor.attrs['href'], source, page_url)
        except ValueError:
            continue
        # Download only explicit .json resources; no guessing endpoints or file formats.
        if urlsplit(url).path.lower().endswith('.json') and url not in result:
            result.append(url)
    return result[:1]


def parse_nckci_json(payload, source, url, collected_at=None, is_demo=False):
    if len(payload) > 2_000_000:
        raise ValueError('JSON больше 2 МБ')
    data = json.loads(payload.decode('utf-8-sig'))
    # Do not assume NCKCI has a CVSS schema identical to NVD. Preserve the record
    # labels and extract only literal identifiers; unknown fields stay in evidence.
    serialized = json.dumps(data, ensure_ascii=False)
    cves = sorted(set(x.upper() for x in CVE_RE.findall(serialized)))
    bdu = sorted(set(re.findall(r'BDU:\d{4}-\d{4,}', serialized, re.I)))
    if not isinstance(data, (dict, list)) or not (cves or bdu):
        raise ValueError('JSON не содержит распознаваемых CVE/BDU; схема требует проверки')
    identifiers = cves + bdu
    # The exact raw resource remains referenced by URL. Do not claim product use,
    # severity or exploitation merely from key names in an unfamiliar schema.
    text = 'Идентификаторы из JSON: ' + ', '.join(identifiers) + '\n' + serialized
    return [Publication(source_id=source['id'], url=url,
                        title='Уведомление НКЦКИ об уязвимостях: ' + ', '.join(identifiers[:5]),
                        text=text, collected_at=collected_at or utcnow(), is_demo=is_demo,
                        external_id=url, metadata={'collection_method': 'published_json',
                            'source_role': 'vulnerability_context', 'content_scope': 'advisory_json',
                            'discovery_url': source['url'], 'date_precision': 'unknown',
                            'cves': cves, 'bdu_ids': bdu})], []
