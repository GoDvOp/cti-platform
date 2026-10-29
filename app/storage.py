"""SQLite source of truth, immutable review audit and publication versions."""
from contextlib import contextmanager, nullcontext
import json
from pathlib import Path
import sqlite3
from .models import utcnow, redact

SCHEMA = '''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS companies(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS publications(
 id TEXT PRIMARY KEY, source_id TEXT NOT NULL, url TEXT NOT NULL,
 content_hash TEXT NOT NULL, published_at TEXT, collected_at TEXT NOT NULL,
 last_seen_at TEXT NOT NULL, is_demo INTEGER NOT NULL, data TEXT NOT NULL,
 extraction TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS pub_hash ON publications(content_hash);
CREATE TABLE IF NOT EXISTS publication_versions(
 publication_id TEXT NOT NULL REFERENCES publications(id), content_hash TEXT NOT NULL,
 data TEXT NOT NULL, recorded_at TEXT NOT NULL, PRIMARY KEY(publication_id,content_hash));
CREATE TABLE IF NOT EXISTS publication_metadata_updates(
 id INTEGER PRIMARY KEY, publication_id TEXT NOT NULL REFERENCES publications(id),
 recorded_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS signals(
 id TEXT PRIMARY KEY, publication_id TEXT NOT NULL REFERENCES publications(id),
 company_id TEXT NOT NULL REFERENCES companies(id), data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reviews(
 id INTEGER PRIMARY KEY, signal_id TEXT NOT NULL REFERENCES signals(id),
 reviewed_at TEXT NOT NULL, reviewer TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS factors(
 company_id TEXT NOT NULL REFERENCES companies(id), factor TEXT NOT NULL,
 assessed_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(company_id,factor));
CREATE TABLE IF NOT EXISTS factor_history(
 id INTEGER PRIMARY KEY, company_id TEXT NOT NULL, factor TEXT NOT NULL,
 assessed_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS source_runs(
 id INTEGER PRIMARY KEY, source_id TEXT NOT NULL, attempted_at TEXT NOT NULL,
 status TEXT NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shodan_targets(
 id TEXT PRIMARY KEY, company_id TEXT NOT NULL REFERENCES companies(id),
 domain TEXT NOT NULL, enabled INTEGER NOT NULL, created_at TEXT NOT NULL,
 UNIQUE(company_id,domain));
CREATE TABLE IF NOT EXISTS shodan_discoveries(
 target_id TEXT NOT NULL REFERENCES shodan_targets(id),
 publication_id TEXT NOT NULL REFERENCES publications(id),
 PRIMARY KEY(target_id,publication_id));
CREATE TABLE IF NOT EXISTS score_runs(
 id INTEGER PRIMARY KEY, calculated_at TEXT NOT NULL, model_version TEXT NOT NULL,
 data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS knowledge_entities(
 id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attack_snapshots(sha256 TEXT PRIMARY KEY,data TEXT NOT NULL,active INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS attack_one_active ON attack_snapshots(active) WHERE active=1;
CREATE TABLE IF NOT EXISTS attack_objects(
 snapshot_sha256 TEXT NOT NULL REFERENCES attack_snapshots(sha256),id TEXT NOT NULL,data TEXT NOT NULL,
 PRIMARY KEY(snapshot_sha256,id));
CREATE TABLE IF NOT EXISTS attack_mappings(local_id TEXT NOT NULL,stix_id TEXT NOT NULL,data TEXT NOT NULL,
 PRIMARY KEY(local_id,stix_id));
CREATE TABLE IF NOT EXISTS attack_mapping_reviews(id INTEGER PRIMARY KEY,local_id TEXT NOT NULL,stix_id TEXT NOT NULL,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assertions(
 id TEXT PRIMARY KEY, publication_id TEXT NOT NULL REFERENCES publications(id), data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assertion_reviews(
 id INTEGER PRIMARY KEY, assertion_id TEXT NOT NULL REFERENCES assertions(id),
 reviewed_at TEXT NOT NULL, reviewer TEXT NOT NULL, data TEXT NOT NULL);
'''


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


class CTIStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def load_companies(self, companies):
        ids = set()
        for c in companies:
            if not c.get('id') or not c.get('name') or c['id'] in ids:
                raise ValueError('Компания: нужны уникальный id и name')
            ids.add(c['id'])
            if not isinstance(c.get('aliases', []), list) or not isinstance(c.get('domains', []), list):
                raise ValueError('aliases и domains должны быть списками')
        with self.connect() as db:
            for c in companies:
                db.execute('INSERT INTO companies VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                           (c['id'], dumps(c)))

    def companies(self):
        with self.connect() as db:
            return [json.loads(r['data']) for r in db.execute('SELECT data FROM companies ORDER BY id')]

    def save_publication(self, pub, extraction, connection=None):
        with (nullcontext(connection) if connection is not None else self.connect()) as db:
            old = db.execute('SELECT content_hash,data FROM publications WHERE id=?', (pub.id,)).fetchone()
            if old and old['content_hash'] == pub.content_hash:
                # Date enrichment must persist even when title/text are unchanged.
                # Keep the first collection time and never erase a known date on re-fetch.
                data = json.loads(old['data'])
                incoming = pub.asdict()
                incoming['collected_at'] = data['collected_at']
                incoming['published_at'] = incoming['published_at'] or data.get('published_at')
                incoming['metadata'] = {**data.get('metadata', {}),
                                        **{k: v for k, v in incoming['metadata'].items() if v is not None}}
                if 'date_precision' in incoming['metadata']:
                    if incoming['published_at']:
                        incoming['metadata']['date_precision'] = 'timestamp'
                    elif incoming['metadata'].get('publication_day'):
                        incoming['metadata']['date_precision'] = 'day'
                enriched = (data.get('published_at') != incoming['published_at'] or
                            data.get('metadata', {}) != incoming['metadata'])
                db.execute('UPDATE publications SET last_seen_at=?,extraction=?,published_at=?,data=? WHERE id=?',
                           (utcnow(), dumps(extraction), incoming['published_at'], dumps(incoming), pub.id))
                if enriched:
                    db.execute('INSERT INTO publication_metadata_updates(publication_id,recorded_at,data) VALUES(?,?,?)',
                               (pub.id, utcnow(), dumps({'before': data, 'after': incoming})))
                    return 'updated'
                return 'unchanged'
            state = 'updated' if old else 'inserted'
            if old:
                db.execute("UPDATE assertions SET data=json_set(data,'$.status','needs_review',"
                           "'$.superseded',json('true')) WHERE publication_id=?", (pub.id,))
                db.execute("UPDATE signals SET data=json_set(data,'$.entity_status','needs_review',"
                           "'$.verification_status','needs_review','$.superseded',json('true')) "
                           'WHERE publication_id=?', (pub.id,))
            db.execute('''INSERT INTO publications VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET content_hash=excluded.content_hash,
                published_at=excluded.published_at,last_seen_at=excluded.last_seen_at,
                data=excluded.data,extraction=excluded.extraction''',
                (pub.id, pub.source_id, pub.url, pub.content_hash, pub.published_at,
                 pub.collected_at, utcnow(), int(pub.is_demo), dumps(pub.asdict()), dumps(extraction)))
            db.execute('INSERT OR IGNORE INTO publication_versions VALUES(?,?,?,?)',
                       (pub.id, pub.content_hash, dumps(pub.asdict()), utcnow()))
            for signal in extraction['signals']:
                db.execute('INSERT INTO signals VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                           (signal['id'], pub.id, signal['company_id'], dumps(signal)))
            return state

    def publications(self, demo=False, as_of=None):
        query = 'SELECT * FROM publications WHERE is_demo=?'
        args = [int(demo)]
        if as_of:
            query += ' AND collected_at<=? AND (published_at IS NULL OR published_at<=?)'
            args.extend([as_of, as_of])
        with self.connect() as db:
            return [dict(r) for r in db.execute(query + ' ORDER BY collected_at DESC,id', args)]

    def signals(self, demo=False, as_of=None):
        pubs = {p['id']: p for p in self.publications(demo, as_of)}
        with self.connect() as db:
            rows = [json.loads(r['data']) for r in db.execute('SELECT data FROM signals ORDER BY id')]
        return [dict(r, publication=pubs[r['publication_id']]) for r in rows
                if r['publication_id'] in pubs and not r.get('superseded')]

    def review(self, signal_id, entity_status, verification_status, confidence, reviewer, note):
        if entity_status not in ('confirmed', 'rejected', 'needs_review'):
            raise ValueError('Некорректный статус сопоставления компании')
        if verification_status not in ('needs_review', 'unresolved', 'corroborated', 'confirmed', 'refuted'):
            raise ValueError('Некорректный статус проверки')
        if confidence not in ('low', 'medium', 'high') or not reviewer.strip() or not note.strip():
            raise ValueError('Нужны confidence, reviewer и обоснование')
        with self.connect() as db:
            row = db.execute('SELECT data FROM signals WHERE id=?', (signal_id,)).fetchone()
            if not row:
                raise ValueError('Сигнал не найден')
            data = json.loads(row['data'])
            data.update(entity_status=entity_status, verification_status=verification_status,
                        analyst_confidence=confidence, reviewer=redact(reviewer), review_note=redact(note), reviewed_at=utcnow())
            db.execute('UPDATE signals SET data=? WHERE id=?', (dumps(data), signal_id))
            db.execute('INSERT INTO reviews(signal_id,reviewed_at,reviewer,data) VALUES(?,?,?,?)',
                       (signal_id, data['reviewed_at'], reviewer, dumps(data)))

    def set_factor(self, company_id, factor, data):
        from .scoring import validate_factor
        validate_factor(factor, data)
        with self.connect() as db:
            if not db.execute('SELECT 1 FROM companies WHERE id=?', (company_id,)).fetchone():
                raise ValueError('Неизвестная компания')
            for evidence_id in data['evidence_ids']:
                evidence = db.execute('SELECT content_hash FROM publications WHERE id=?', (evidence_id,)).fetchone()
                if not evidence:
                    raise ValueError('Не найдено доказательство: ' + evidence_id)
                if evidence['content_hash'] != data['evidence_hashes'][evidence_id]:
                    raise ValueError('Не совпадает хеш проверенного доказательства: ' + evidence_id)
            now = utcnow()
            db.execute('INSERT INTO factors VALUES(?,?,?,?) ON CONFLICT(company_id,factor) DO UPDATE SET '
                       'assessed_at=excluded.assessed_at,data=excluded.data', (company_id, factor, now, dumps(data)))
            db.execute('INSERT INTO factor_history(company_id,factor,assessed_at,data) VALUES(?,?,?,?)',
                       (company_id, factor, now, dumps(data)))

    def factors(self, company_id):
        with self.connect() as db:
            return {r['factor']: dict(json.loads(r['data']), assessed_at=r['assessed_at'])
                    for r in db.execute('SELECT * FROM factors WHERE company_id=?', (company_id,))}

    def source_run(self, source_id, status, details, attempted_at=None):
        from .models import date_iso
        stamp = date_iso(attempted_at) if attempted_at else utcnow()
        with self.connect() as db:
            db.execute('INSERT INTO source_runs(source_id,attempted_at,status,details) VALUES(?,?,?,?)',
                       (source_id, stamp, status, dumps(details)))

    def source_status(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM source_runs WHERE id IN '
                    '(SELECT MAX(id) FROM source_runs GROUP BY source_id) ORDER BY source_id')]

    def save_scores(self, data, model_version):
        with self.connect() as db:
            db.execute('INSERT INTO score_runs(calculated_at,model_version,data) VALUES(?,?,?)',
                       (utcnow(), model_version, dumps(data)))

    def health(self):
        with self.connect() as db:
            return db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'

    def load_products(self, products):
        import re
        ids = set()
        for p in products:
            if not isinstance(p, dict) or not re.fullmatch(r'[a-z0-9_-]{1,80}', p.get('id', '')) or not p.get('name'):
                raise ValueError('Продукту нужны id и name')
            if p['id'] in ids or not isinstance(p.get('aliases', []), list):
                raise ValueError('Повтор ID продукта или неверные aliases')
            ids.add(p['id'])
        with self.connect() as db:
            for p in products:
                db.execute('INSERT INTO products VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                           (p['id'], dumps(p)))

    def products(self):
        with self.connect() as db:
            return [json.loads(r['data']) for r in db.execute('SELECT data FROM products ORDER BY id')]

    def load_entities(self, entities):
        import re
        from datetime import date
        if not isinstance(entities, list):
            raise ValueError('Ожидается список сущностей')
        seen = set()
        for entity in entities:
            if (not isinstance(entity, dict) or entity.get('entity_type') not in ('ThreatActor', 'Incident', 'Malware')
                    or not re.fullmatch(r'[a-z0-9_-]{1,100}', entity.get('id', ''))
                    or not isinstance(entity.get('name'), str) or not entity['name'].strip()
                    or entity['id'] in seen):
                raise ValueError('Нужны уникальные id, name и допустимый entity_type')
            if not isinstance(entity.get('aliases', []), list) or not all(
                    isinstance(a, str) and a.strip() for a in entity.get('aliases', [])):
                raise ValueError('aliases должен быть списком непустых строк')
            if type(entity.get('is_demo', False)) is not bool:
                raise ValueError('is_demo должен быть boolean')
            for key in ('start_day', 'end_day'):
                if entity.get(key):
                    date.fromisoformat(entity[key])
            if entity.get('start_day') and entity.get('end_day') and entity['start_day'] > entity['end_day']:
                raise ValueError('Конец инцидента раньше начала')
            seen.add(entity['id'])
        with self.connect() as db:
            for entity in entities:
                old = db.execute('SELECT data FROM knowledge_entities WHERE id=?', (entity['id'],)).fetchone()
                if old:
                    previous = json.loads(old['data'])
                    if (previous['entity_type'] != entity['entity_type'] or
                            previous.get('is_demo', False) != entity.get('is_demo', False)):
                        raise ValueError('Нельзя менять тип или real/demo существующей сущности')
                db.execute('INSERT INTO knowledge_entities VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                           (entity['id'], entity['entity_type'], dumps(entity)))

    def entities(self, demo=False):
        with self.connect() as db:
            rows = [json.loads(r['data']) for r in db.execute('SELECT data FROM knowledge_entities ORDER BY id')]
        return [r for r in rows if bool(r.get('is_demo', False)) == demo]

    def add_assertion(self, data):
        """Validate and insert a review candidate; this API cannot confirm it."""
        import re
        from .knowledge import KINDS, claim_id, validate_attributes, mentions
        from .models import normalized
        required = ('kind', 'subject', 'object', 'publication_id', 'excerpt')
        if not isinstance(data, dict) or not all(isinstance(data.get(k), str) and data[k].strip() for k in required):
            raise ValueError('Связи нужны kind, subject, object, publication_id и excerpt')
        kind = data['kind']
        if kind not in KINDS or data.get('status', 'needs_review') != 'needs_review':
            raise ValueError('Импорт создаёт только needs_review; подтверждение — отдельной проверкой')
        attrs = data.get('attributes', {})
        validate_attributes(kind, attrs)
        with self.connect() as db:
            pub = db.execute('SELECT * FROM publications WHERE id=?', (data['publication_id'],)).fetchone()
            if not pub:
                raise ValueError('Не найдена публикация-доказательство')
            content = json.loads(pub['data'])
            excerpt = redact(data['excerpt'].strip())[:1000]
            if normalized(excerpt) not in normalized(content['title'] + '\n' + content['text']):
                raise ValueError('Фрагмент не найден в сохранённой публикации')
            from .knowledge import THREAT_KINDS
            if kind in THREAT_KINDS:
                subject_type, object_type, _ = THREAT_KINDS[kind]
            else:
                subject_type = 'Vulnerability' if kind == 'affects_product' else 'Company'
                object_type = 'Product' if kind in ('uses_product', 'affects_product') else 'Company'
            def endpoint(label, identifier):
                if label == 'Vulnerability':
                    if not re.fullmatch(r'(?:CVE-\d{4}-\d{4,}|BDU:\d{4}-\d{4,})', identifier):
                        raise ValueError('Объект Vulnerability должен быть CVE или BDU')
                    extraction = json.loads(pub['extraction'])
                    if identifier not in extraction.get('cves', []) + extraction.get('bdu_ids', []):
                        raise ValueError('CVE/BDU не найдена в публикации')
                    from .models import identifier_text
                    if identifier not in identifier_text(excerpt).upper():
                        raise ValueError('CVE/BDU не найдена в доказательном фрагменте')
                    return None
                table = {'Company': 'companies', 'Product': 'products'}.get(label, 'knowledge_entities')
                row = db.execute('SELECT data FROM ' + table + ' WHERE id=?', (identifier,)).fetchone()
                if not row:
                    raise ValueError('Не найдена сущность ' + label)
                entity = json.loads(row['data'])
                if table == 'knowledge_entities' and entity['entity_type'] != label:
                    raise ValueError('Тип сущности не соответствует связи')
                return entity
            subject = endpoint(subject_type, data['subject'])
            obj = endpoint(object_type, data['object'])
            if subject_type == object_type and data['subject'] == data['object']:
                raise ValueError('Связь сущности с самой собой недопустима')
            if attrs.get('version') and not re.search(r'(?<![\d.])' + re.escape(attrs['version']) + r'(?!\d|\.\d)', excerpt):
                raise ValueError('Версия не найдена в доказательном фрагменте')
            for entity in (subject, obj):
                if entity:
                    if bool(entity.get('is_demo', False)) != bool(pub['is_demo']):
                        raise ValueError('Нельзя смешивать реальные и учебные сущности')
                    if not mentions([entity['name'], *entity.get('aliases', [])], excerpt):
                        raise ValueError('Сущность не найдена в доказательном фрагменте')
            identifier = claim_id(pub['id'], kind, data['subject'], data['object'])
            value = {k: data[k] for k in required}
            value.update(id=identifier, excerpt=excerpt, evidence_hash=pub['content_hash'],
                         attributes=attrs, status='needs_review', is_demo=bool(pub['is_demo']),
                         extractor_version=data.get('extractor_version', 'manual-candidate-v1'))
            old = db.execute('SELECT data FROM assertions WHERE id=?', (identifier,)).fetchone()
            if old:
                previous = json.loads(old['data'])
                if (data.get('extractor_version') == 'relations-v1' and
                        previous.get('evidence_hash') == pub['content_hash'] and not previous.get('superseded')):
                    return identifier
                if (previous.get('evidence_hash') == pub['content_hash'] and
                        previous.get('attributes', {}) == attrs and previous.get('excerpt') == excerpt and
                        not previous.get('superseded')):
                    return identifier
            db.execute('INSERT INTO assertions VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                       (identifier, pub['id'], dumps(value)))
            return identifier

    def assertions(self, demo=False):
        pubs = {p['id']: p for p in self.publications(demo)}
        with self.connect() as db:
            rows = [json.loads(r['data']) for r in db.execute('SELECT data FROM assertions ORDER BY id')]
        return [dict(r, publication=pubs[r['publication_id']]) for r in rows
                if r['publication_id'] in pubs and not r.get('superseded')
                and r.get('evidence_hash') == pubs[r['publication_id']]['content_hash']]

    def review_assertion(self, identifier, status, reviewer, note, *, confidence=None, basis=None):
        if status not in ('needs_review', 'confirmed', 'refuted') or not reviewer.strip() or not note.strip():
            raise ValueError('Нужны статус, проверяющий и обоснование')
        with self.connect() as db:
            row = db.execute('SELECT * FROM assertions WHERE id=?', (identifier,)).fetchone()
            if not row:
                raise ValueError('Связь не найдена')
            data = json.loads(row['data'])
            pub = db.execute('SELECT content_hash FROM publications WHERE id=?', (row['publication_id'],)).fetchone()
            if data.get('superseded') or data['evidence_hash'] != pub['content_hash']:
                raise ValueError('Источник изменился; сначала заново извлеките связь')
            from .review_policy import missing_metadata, CONFIDENCE, BASES
            attributes = dict(data.get('attributes', {}))
            if confidence is not None:
                if confidence not in CONFIDENCE:
                    raise ValueError('Нужна confidence: low, medium, high')
                attributes['confidence'] = confidence
            if basis is not None:
                if basis not in BASES:
                    raise ValueError('Нужно указать допустимый тип основания basis')
                attributes['basis'] = basis
            if status == 'confirmed' and missing_metadata(attributes):
                raise ValueError('Для подтверждения нужны явные confidence и basis; '
                                 'фрагмент доказательства сохраняется в связи')
            from .knowledge import validate_attributes
            validate_attributes(data['kind'], attributes)
            data['attributes'] = attributes
            data.update(status=status, reviewer=redact(reviewer), review_note=redact(note), reviewed_at=utcnow())
            db.execute('UPDATE assertions SET data=? WHERE id=?', (dumps(data), identifier))
            db.execute('INSERT INTO assertion_reviews(assertion_id,reviewed_at,reviewer,data) VALUES(?,?,?,?)',
                       (identifier, data['reviewed_at'], data['reviewer'], dumps(data)))
