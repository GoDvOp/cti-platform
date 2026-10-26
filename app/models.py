"""Validated publication contract, normalization and redaction."""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

UTC = timezone.utc


def utcnow():
    return datetime.now(UTC).isoformat(timespec='seconds')


def date_iso(value):
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        except ValueError:
            result = parsedate_to_datetime(str(value))
    if result.tzinfo is None:
        raise ValueError('Дата должна содержать часовой пояс')
    return result.astimezone(UTC).isoformat(timespec='seconds')


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def normalized(value):
    return ' '.join(value.casefold().replace('ё', 'е').split())


def identifier_text(value):
    """Normalize typographic hyphens for identifier lookup, never for evidence hashing."""
    return value.translate(str.maketrans({c: '-' for c in '‐‑‒–−﹣－'}))


def canonical_url(url):
    p = urlsplit(url.strip())
    if p.scheme not in ('https', 'http') or not p.hostname or p.username or p.password:
        raise ValueError('Требуется HTTP(S)-ссылка без учётных данных')
    host = p.hostname.encode('idna').decode('ascii').lower()
    if p.port and not (p.scheme == 'https' and p.port == 443 or p.scheme == 'http' and p.port == 80):
        host += ':' + str(p.port)
    query = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if not k.lower().startswith('utm_') and k.lower() not in ('fbclid', 'gclid')]
    return urlunsplit((p.scheme.lower(), host, p.path or '/', urlencode(sorted(query)), ''))


def redact(value):
    value = re.sub(r'(?i)\b(password|passwd|пароль|token|api[_-]?key)\s*[:=]\s*\S+',
                   r'\1=[REDACTED]', value)
    value = re.sub(r'\b\d{7,12}:[A-Za-z0-9_-]{25,}\b', '[REDACTED_TOKEN]', value)
    return re.sub(r'(?i)[\w.+-]+@([a-z0-9.-]+\.[a-z]{2,})', r'[email]@\1', value)


@dataclass
class Publication:
    source_id: str
    url: str
    title: str
    text: str
    published_at: str | None = None
    author: str | None = None
    collected_at: str = field(default_factory=utcnow)
    is_demo: bool = False
    external_id: str | None = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if type(self.is_demo) is not bool:
            raise ValueError('is_demo должен быть true или false')
        if not isinstance(self.metadata, dict):
            raise ValueError('metadata должен быть объектом')
        if not re.fullmatch(r'[a-z0-9_-]{1,80}', self.source_id):
            raise ValueError('Некорректный source_id')
        self.url = canonical_url(self.url)
        self.title = redact(self.title.strip())[:1000]
        self.text = redact(self.text.strip())[:30000]
        self.author = redact(self.author)[:200] if self.author else None
        if not self.title or not self.text:
            raise ValueError('Пустая публикация')
        self.published_at = date_iso(self.published_at)
        self.collected_at = date_iso(self.collected_at)
        if not self.collected_at:
            raise ValueError('collected_at обязателен')

    @property
    def id(self):
        scope = 'demo' if self.is_demo else 'real'
        return digest(scope + '\n' + self.source_id + '\n' + (self.external_id or self.url))[:24]

    @property
    def content_hash(self):
        return digest(normalized(self.title + '\n' + self.text))

    def asdict(self):
        return asdict(self)
