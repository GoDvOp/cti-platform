"""CLI entry point. Run python -m app.main --help."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
from .config import ROOT, load_env
from .models import Publication, utcnow
from .storage import CTIStore
from .collectors import (ingest, import_jsonl, collect_source, parse_feed, parse_source,
                         validate_sources, source_status, validate_feed_url)
from .scoring import calculate
from .reporting import export_report


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def demo(store):
    if store.publications(False):
        raise ValueError('Используйте отдельную БД для демонстрации: --db data/demo.sqlite3')
    store.load_companies(read_json(ROOT / 'examples/companies_demo.json'))
    now = utcnow()
    docs = read_json(ROOT / 'examples/publications_demo.json')
    pubs = [Publication(**dict(d, published_at=now, collected_at=now, is_demo=True)) for d in docs]
    previous = {row['id']: row for row in store.publications(True)}
    for pub in pubs:
        old = previous.get(pub.id)
        if old and old['content_hash'] == pub.content_hash:
            # Re-running the same fictional demo is not a new observation.
            original = json.loads(old['data'])
            pub.published_at = original['published_at']
            pub.collected_at = original['collected_at']
    result = ingest(store, pubs)
    # Explicit fictional analyst reviews; never applied to real observations.
    for s in store.signals(True):
        if s['company_id'] == 'demo-alpha' and s['event_type'] == 'access_sale_claim':
            store.review(s['id'], 'confirmed', 'unresolved', 'medium', 'учебный аналитик',
                         'Учебное совпадение домена; подлинность доступа не установлена.')
    all_pubs = {p['url']: p for p in store.publications(True)}
    for factor, value, reason in [('I', 75, 'Учебное адресное объявление, домен совпадает'),
                                  ('S', 75, 'Условный отраслевой профиль из учебного отчёта'),
                                  ('H', 50, 'Учебное совпадение одного из двух признаков')]:
        if factor == 'I':
            sig = next(s for s in store.signals(True) if s['company_id'] == 'demo-alpha'
                       and s['event_type'] == 'access_sale_claim')
            evidence = sig['publication']
        elif factor == 'S':
            evidence = all_pubs['https://news.example/posts/9']
        else:
            evidence = all_pubs['https://news.example/posts/11']
        store.set_factor('demo-alpha', factor, {'score': value, 'reason': reason,
                         'reviewer': 'учебный аналитик', 'evidence_ids': [evidence['id']],
                         'evidence_hashes': {evidence['id']: evidence['content_hash']},
                         'observed_at': now, 'confidence': 'medium'})
    return {'warning': 'ВСЕ ДАННЫЕ ВЫМЫШЛЕНЫ; не использовать как результат сбора', **result}


def parser():
    p = argparse.ArgumentParser(description='CTI: пассивные источники, проверка сигналов и объяснимый индекс')
    p.add_argument('--db', type=Path, default=None, help='SQLite; по умолчанию data/cti.sqlite3')
    sub = p.add_subparsers(dest='command', required=True)
    q = sub.add_parser('init', help='Создать БД и загрузить исследуемый список компаний')
    q.add_argument('--companies', type=Path, default=ROOT / 'config/companies.json')
    q = sub.add_parser('status', help='Целостность БД, причины ошибок и время следующей проверки')
    q.add_argument('--sources', type=Path, default=ROOT / 'config/sources.json')
    q = sub.add_parser('freshness', help='Возраст сведений отдельно от даты загрузки и состояния сети')
    q.add_argument('--sources', type=Path, default=ROOT / 'config/sources.json')
    q.add_argument('--as-of', help='ISO8601 с часовым поясом для воспроизводимого аудита')
    q.add_argument('--demo', action='store_true')
    q = sub.add_parser('monitoring', help='Условные гипотезы по свежим бюллетеням и публичный контекст bug bounty')
    q.add_argument('--as-of')
    q.add_argument('--record-snapshot', action='store_true', help='Сохранить неизменяемые данные и очередь для будущей оценки; только текущая дата')
    q.add_argument('--output', type=Path, default=ROOT / 'data/processed/monitoring')
    q = sub.add_parser('graph-scores', help='Два объяснимых индекса по весам графа, без вероятностей атаки')
    q.add_argument('--explain', action='store_true', help='Показать все пути, веса и причины исключения')
    q.add_argument('--demo', action='store_true')
    q.add_argument('--as-of', help='Дата расчёта ISO8601 с часовым поясом; прошлые снимки не восстанавливаются')
    q.add_argument('--weights', type=Path, help='JSON с экспертными коэффициентами')
    q.add_argument('--company', help='ID компании либо часть названия')
    q.add_argument('--include-historical', action='store_true', help='Включить исторические кейсы вне рейтинга целей')
    q = sub.add_parser('graph-sensitivity', help='Проверить чувствительность индексов к коэффициентам на копии БД')
    q.add_argument('--company', action='append', help='ID компании; можно повторить. По умолчанию novabev, winelab, equifax')
    q.add_argument('--delta', type=float, default=.2, help='Относительное изменение, по умолчанию 0.2 (20%%)')
    q.add_argument('--as-of', help='ISO8601 с часовым поясом; исторические версии не восстанавливаются')
    q.add_argument('--weights', type=Path)
    q.add_argument('--demo', action='store_true')
    q.add_argument('--output', type=Path, default=ROOT / 'data/processed/sensitivity')
    q = sub.add_parser('evaluate', help='Пилотная проверка классификации на сохранённой размеченной выборке')
    q.add_argument('--corpus', type=Path, default=ROOT / 'evaluation/pilot_real.json')
    q.add_argument('--output', type=Path, default=ROOT / 'data/processed/evaluation')
    sub.add_parser('demo', help='Только вымышленные данные, автоматически отдельная БД')
    sub.add_parser('knowledge-demo', help='Полный учебный граф: компании, продукты, CVE, поставщик')
    sub.add_parser('knowledge-seed', help='Добавить проверенные открытые примеры технических и деловых связей')
    sub.add_parser('knowledge-expand', help='Добавить проверенную библиотеку внедрений и бюллетеней разработчика')
    sub.add_parser('threat-seed', help='Добавить исторические инциденты и атрибуцию с источниками')
    sub.add_parser('company-attack-seed', help='Добавить проверенный пример компаний, кампании и FIN7')
    q = sub.add_parser('attack-import', help='Импортировать полный Enterprise ATT&CK STIX 2.1 JSON')
    q.add_argument('file', type=Path)
    q = sub.add_parser('attack-update', help='Скачать и импортировать официальный Enterprise ATT&CK')
    q.add_argument('--version', help='Зафиксировать версию, например 20.0; по умолчанию последняя из индекса')
    sub.add_parser('attack-restore', help='Восстановить проверенный ATT&CK из включённого локального кеша')
    q = sub.add_parser('attack-search', help='Поиск по активному справочнику ATT&CK')
    q.add_argument('text')
    q.add_argument('--kind', choices=['ThreatActor','Malware','Tool','Technique','Tactic','AttackCampaign'])
    q.add_argument('--limit', type=int, default=20)
    sub.add_parser('attack-status', help='Версия, проекция, сопоставления и кандидаты ATT&CK')
    q = sub.add_parser('attack-map', help='Проверить сопоставление локальной сущности с ATT&CK')
    q.add_argument('local_id')
    q.add_argument('attack_id')
    q.add_argument('--status', choices=['confirmed','refuted','needs_review'], required=True)
    q.add_argument('--reviewer', required=True)
    q.add_argument('--note', required=True)
    q = sub.add_parser('entity-add', help='Загрузить каталог группировок, инцидентов и вредоносного ПО')
    q.add_argument('file', type=Path)
    for name in ('knowledge', 'reindex', 'exposure'):
        q = sub.add_parser(name, help={'knowledge':'Связи с доказательствами', 'reindex':'Переизвлечь связи из сохранённых публикаций',
                                      'exposure':'Техническая применимость CVE, отдельно от интереса атакующих'}[name])
        q.add_argument('--demo', action='store_true')
    q = sub.add_parser('relation-add', help='Импорт кандидатов в связи из JSON')
    q.add_argument('file', type=Path)
    q = sub.add_parser('relation-review', help='Подтвердить или опровергнуть конкретную связь')
    q.add_argument('id')
    q.add_argument('--status', required=True, choices=['needs_review', 'confirmed', 'refuted'])
    q.add_argument('--reviewer', required=True)
    q.add_argument('--note', required=True)
    q.add_argument('--confidence', choices=['low', 'medium', 'high'], help='Уверенность в конкретной связи')
    q.add_argument('--basis', choices=['victim_report', 'research_report', 'vendor_advisory',
                                     'government_advisory', 'legal_allegation', 'attacker_claim'],
                   help='Тип основания; обязателен при подтверждении, если не задан в связи')
    q = sub.add_parser('collect', help='Один проход разрешённых feeds')
    q.add_argument('--sources', type=Path, default=ROOT / 'config/sources.json')
    q.add_argument('--source-id', help='Проверить только один источник, сохраняя его интервал')
    q = sub.add_parser('worker', help='Периодический пассивный сбор; Ctrl+C — остановка')
    q.add_argument('--sources', type=Path, default=ROOT / 'config/sources.json')
    q.add_argument('--source-id', help='Опрос только одного источника')
    q.add_argument('--sync-graph', action='store_true', help='Обновлять отчёт и Neo4j при новых публикациях')
    q.add_argument('--output', type=Path, help='Каталог отчёта')
    q = sub.add_parser('refresh', help='Сбор → извлечение связей → отчёт → Neo4j')
    q.add_argument('--sources', type=Path, default=ROOT / 'config/sources.json')
    q.add_argument('--source-id')
    q.add_argument('--no-graph', action='store_true', help='Только сбор и отчёт без обращения к Neo4j')
    q.add_argument('--output', type=Path, help='Каталог отчёта')
    q = sub.add_parser('import-source', help='Разобрать сохранённую HTML/JSON-копию российского источника')
    q.add_argument('source_id')
    q.add_argument('file', type=Path)
    q.add_argument('--sources', type=Path, default=ROOT / 'config/sources.json')
    q.add_argument('--format', choices=['html', 'json', 'rss'])
    q.add_argument('--url', help='Исходная URL-ссылка сохранённого JSON на хосте источника')
    q.add_argument('--demo', action='store_true')
    q = sub.add_parser('import-jsonl', help='Импорт разрешённых сохранённых публикаций')
    q.add_argument('file', type=Path)
    q.add_argument('--demo', action='store_true')
    q = sub.add_parser('import-feed', help='Разобрать локальную сохранённую копию RSS/Atom')
    q.add_argument('file', type=Path)
    q.add_argument('--source-id', required=True)
    q.add_argument('--demo', action='store_true')
    for name in ('signals', 'targets'):
        q = sub.add_parser(name)
        q.add_argument('--demo', action='store_true')
        if name == 'targets':
            q.add_argument('--as-of', help='ISO8601 с часовым поясом; прошлые версии автоматически не восстанавливаются')
            q.add_argument('--half-life', type=float, default=90)
    q = sub.add_parser('review', help='Проверить одно сопоставление и заявление')
    q.add_argument('signal_id')
    q.add_argument('--entity', required=True, choices=['confirmed', 'rejected', 'needs_review'])
    q.add_argument('--status', required=True, choices=['needs_review', 'unresolved', 'corroborated', 'confirmed', 'refuted'])
    q.add_argument('--confidence', required=True, choices=['low', 'medium', 'high'])
    q.add_argument('--reviewer', required=True)
    q.add_argument('--note', required=True)
    q = sub.add_parser('factor', help='Внести обоснованную ручную оценку I/S/H из JSON')
    q.add_argument('company_id')
    q.add_argument('factor', choices=['I', 'S', 'H'])
    q.add_argument('file', type=Path)
    q = sub.add_parser('report', help='HTML для печати + JSON + CSV')
    q.add_argument('--as-of', help='Фиксированная дата расчёта ISO8601 с часовым поясом')
    q.add_argument('--output', type=Path)
    q.add_argument('--demo', action='store_true')
    q = sub.add_parser('graph-export', help='Параметризованные запросы для Neo4j')
    q.add_argument('--as-of', help='Фиксированная дата расчёта весов на текущем снимке')
    q.add_argument('--output', type=Path, default=ROOT / 'data/processed/neo4j.json')
    q.add_argument('--demo', action='store_true')
    q = sub.add_parser('graph-sync', help='Загрузить проекцию в локальную Neo4j')
    q.add_argument('--demo', action='store_true')
    q = sub.add_parser('graph-status', help='Проверить, какие узлы и связи реально загружены в Neo4j')
    q.add_argument('--demo', action='store_true')
    return p


def run(args):
    is_demo = args.command in ('demo', 'knowledge-demo') or getattr(args, 'demo', False)
    default_db = ROOT / 'data' / ('demo.sqlite3' if is_demo else 'cti.sqlite3')
    store = CTIStore(args.db or os.getenv('CTI_DB_PATH') or default_db)
    store.load_products(read_json(ROOT / 'config/products.json'))
    command = args.command
    if command == 'init':
        store.load_companies(read_json(args.companies))
        return {'database': str(store.path), 'companies': len(store.companies())}
    if command == 'status':
        return {'database': str(store.path), 'database_ok': store.health(),
                'publications': len(store.publications()), 'demo_publications': len(store.publications(True)),
                'sources': source_status(store, read_json(args.sources))}
    if command == 'freshness':
        from .freshness import audit
        sources = validate_sources(read_json(args.sources))
        return {'database': str(store.path), 'sources': audit(store, sources, args.demo, args.as_of)}
    if command == 'graph-scores':
        from .graph_scoring import calculate_graph
        result = calculate_graph(store, args.demo, args.as_of, args.weights, args.include_historical)
        if args.company:
            query = args.company.strip().casefold()
            result['companies'] = [r for r in result['companies'] if query == r['company_id'].casefold()
                                   or query in r['company'].casefold()]
            if not result['companies']:
                raise ValueError('Компания не найдена в выбранном охвате; для исторических кейсов добавьте --include-historical')
        if not args.explain:
            for row in result['companies']:
                row.pop('paths')
        return result
    if command == 'graph-sensitivity':
        from .sensitivity import analyze, export
        return export(analyze(store, args.company, args.delta, args.as_of, args.weights, args.demo), args.output)
    if command == 'evaluate':
        from .evaluation import evaluate, export
        return export(evaluate(args.corpus), args.output)
    if command == 'demo':
        return demo(store)
    if command == 'knowledge-demo':
        from .enrichment import demo_knowledge
        demo(store)
        return demo_knowledge(store)
    if command == 'knowledge-seed':
        from .enrichment import seed_knowledge
        if not store.companies():
            store.load_companies(read_json(ROOT / 'config/companies.json'))
        return seed_knowledge(store, ROOT)
    if command == 'company-attack-seed':
        from .threats import seed_threats
        return seed_threats(store, ROOT, 'company_attack_library.json')
    if command == 'attack-import':
        from .attack import import_bundle, MAX_BYTES
        with args.file.open('rb') as stream:
            payload = stream.read(MAX_BYTES + 1)
        return import_bundle(store, payload)
    if command == 'attack-update':
        from .attack import update
        return update(store, ROOT / 'data/attack/cache', args.version)
    if command == 'attack-restore':
        from .attack import restore_cached
        return restore_cached(store, ROOT / 'data/attack')
    if command == 'attack-search':
        from .attack import search
        return search(store,args.text,args.kind,args.limit)
    if command == 'attack-status':
        from .attack import status
        return status(store)
    if command == 'attack-map':
        from .attack import review_mapping
        return review_mapping(store,args.local_id,args.attack_id,args.status,args.reviewer,args.note)
    if command == 'entity-add':
        store.load_entities(read_json(args.file))
        return {'entities': len(store.entities())}
    if command == 'threat-seed':
        from .threats import seed_threats
        return seed_threats(store, ROOT)
    if command == 'knowledge-expand':
        from .enrichment import expand_knowledge
        return expand_knowledge(store, ROOT)
    if command == 'monitoring':
        from .research_context import build, export
        if args.record_snapshot and args.as_of:
            raise ValueError('Запись для будущей оценки допускает только текущую дату, без --as-of')
        if args.record_snapshot:
            from .research_context import record
            return record(store, args.output, ROOT / 'data/monitoring_history')
        return export(build(store, args.as_of), args.output)
    if command == 'reindex':
        from .enrichment import reindex
        return reindex(store, args.demo)
    if command == 'exposure':
        from .knowledge import exposure_rows
        return exposure_rows(store, args.demo)
    if command == 'knowledge':
        return store.assertions(args.demo)
    if command == 'relation-add':
        from .enrichment import import_assertions
        return {'assertion_ids': import_assertions(store, args.file)}
    if command == 'relation-review':
        store.review_assertion(args.id, args.status, args.reviewer, args.note,
                               confidence=args.confidence, basis=args.basis)
        return {'reviewed': args.id, 'status': args.status}
    if command in ('collect', 'worker', 'refresh'):
        if not store.companies():
            raise ValueError('Сначала init: нужен фиксированный список компаний')
        sources = validate_sources(read_json(args.sources))
        if args.source_id:
            sources = [s for s in sources if s['id'] == args.source_id]
            if not sources:
                raise ValueError('Неизвестный source-id: ' + args.source_id)
        if command == 'worker':
            from .automation import run_worker
            return run_worker(store, args.sources, args.output or ROOT / 'data/processed/real', sync=args.sync_graph, source_id=args.source_id)
        source_runtime = {}
        results = [collect_source(store, source, source_runtime) for source in sources]
        if command == 'collect':
            return results
        from .enrichment import reindex
        result = {'collection': results, 'knowledge': reindex(store),
                  'report': export_report(store, args.output or ROOT / 'data/processed/real')}
        if not args.no_graph:
            from .graph import sync_graph
            try:
                result['graph'] = sync_graph(store)
            except (ValueError, OSError) as exc:
                result['graph'] = {'status': 'error', 'error_type': type(exc).__name__,
                                   'message': 'Neo4j не обновлена; данные и отчёт сохранены локально'}
        return result
    if command == 'import-source':
        sources = validate_sources(read_json(args.sources))
        source = next((dict(s) for s in sources if s['id'] == args.source_id), None)
        if source is None:
            raise ValueError('Неизвестный source_id')
        if args.url:
            validate_feed_url(args.url, source['allowed_hosts'])
            source['url'] = args.url
        if args.format == 'json':
            if source.get('kind') not in ('nckci_listing', 'nckci_json'):
                raise ValueError('JSON-адаптер реализован для уведомлений НКЦКИ')
            if not args.url:
                raise ValueError('Для JSON укажите --url исходного опубликованного файла')
            source['kind'] = 'nckci_json'
        elif args.format == 'rss':
            source['kind'] = 'rss'
        with args.file.open('rb') as f:
            pubs, warnings = parse_source(f.read(2_000_001), source, is_demo=args.demo)
        for pub in pubs:
            pub.metadata['import_method'] = 'local_file'
        return {'counts': ingest(store, pubs), 'warnings': warnings, 'is_demo': args.demo}
    if command == 'import-jsonl':
        return import_jsonl(store, args.file, args.demo)
    if command == 'import-feed':
        with args.file.open('rb') as f:
            pubs, warnings = parse_feed(f.read(2_000_001), args.source_id, args.demo)
        return {'counts': ingest(store, pubs), 'warnings': warnings}
    if command == 'signals':
        return store.signals(args.demo)
    if command == 'targets':
        return calculate(store, args.demo, args.as_of, args.half_life)
    if command == 'review':
        store.review(args.signal_id, args.entity, args.status, args.confidence, args.reviewer, args.note)
        return {'reviewed': args.signal_id}
    if command == 'factor':
        store.set_factor(args.company_id, args.factor, read_json(args.file))
        return {'company': args.company_id, 'factor': args.factor}
    if command == 'report':
        return export_report(store, args.output or ROOT / 'data/processed' / ('demo' if args.demo else 'real'), args.demo, args.as_of)
    if command == 'graph-export':
        from .graph import export_graph
        return export_graph(store, args.output, args.demo, args.as_of)
    if command == 'graph-sync':
        from .graph import sync_graph
        return sync_graph(store, args.demo)
    if command == 'graph-status':
        from .graph import graph_status
        return graph_status(args.demo)


def main():
    load_env()
    args = parser().parse_args()
    try:
        result = run(args)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.command == 'collect' and any(r['status'] in ('error', 'partial') for r in result):
            return 2
        if args.command == 'refresh' and (any(r['status'] in ('error', 'partial') for r in result['collection'])
                                          or result.get('graph', {}).get('status') == 'error'):
            return 2
        return 0
    except KeyboardInterrupt:
        print('Остановлено пользователем.', file=sys.stderr)
        return 130
    except (ValueError, TypeError, OSError, sqlite3.Error, KeyError) as exc:
        # Network/DB exceptions can contain credentials: expose only an error category.
        if isinstance(exc, (ValueError, KeyError)):
            print('Ошибка: ' + str(exc), file=sys.stderr)
        else:
            print('Ошибка окружения или формата данных (' + type(exc).__name__ + ').', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
