"""One command to prepare, load and verify the graph; save safe diagnostics.

Run in a regular user terminal, not in the Neo4j Cypher editor.
--prepare-only validates local data without contacting Neo4j.
"""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.config import load_env
from app.storage import CTIStore
from app.enrichment import reindex, seed_knowledge
from app.graph import statements, sync_graph
from app.models import utcnow, redact


def main():
    parser = argparse.ArgumentParser(description='Подготовка, загрузка и проверка графа Neo4j')
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--update-attack', action='store_true', help='Обновить ATT&CK из официального репозитория перед загрузкой')
    args = parser.parse_args()
    load_env()
    log_path = ROOT / 'data/graph_check.txt'
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []

    def report(message):
        message = redact(str(message))
        lines.append(message)
        print(message, flush=True)
        log_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    report('Проверка графа: ' + utcnow())
    try:
        store = CTIStore(os.getenv('CTI_DB_PATH') or ROOT / 'data/cti.sqlite3')
        report('SQLite: ' + str(store.path.resolve()))
        store.load_products(json.loads((ROOT / 'config/products.json').read_text(encoding='utf-8')))
        if not store.companies():
            store.load_companies(json.loads((ROOT / 'config/companies.json').read_text(encoding='utf-8')))
        if not store.assertions():
            seed_knowledge(store, ROOT)
        if args.update_attack:
            from app.attack import update
            report('Обновление ATT&CK: ' + json.dumps(update(store, ROOT / 'data/attack/cache'),ensure_ascii=False))
        from app.attack import status as attack_status
        info = attack_status(store)
        report('ATT&CK: ' + json.dumps({'version':(info['dataset'] or {}).get('version'),
                                      'projected_counts':info['projected_counts'],
                                      'confirmed_mappings':info.get('confirmed_mappings',0)},ensure_ascii=False))
        report('Переизвлечение: ' + json.dumps(reindex(store), ensure_ascii=False))
        queries = statements(store)
        from app.company_graph import attack_contexts
        report('Связанные с компаниями пути к ATT&CK: ' + str(len(attack_contexts(store))))
        report('Общий вид: MATCH path=(a:CompanyGraph)-[r]->(b:CompanyGraph) RETURN path LIMIT 1000;')
        for key in ('MERGE (p:Product', 'MERGE (n:Incident', 'MERGE (n:ThreatActor',
                    'r:USED_PRODUCT ', 'r:AFFECTS ', 'r:SHARES_PRODUCT_CONTEXT '):
            count = sum(len(q.get('parameters', {}).get('rows', [])) for q in queries if key in q['statement'])
            report('Подготовлено ' + key + ': ' + str(count))
        if not any('MERGE (p:Product' in q['statement'] and q.get('parameters', {}).get('rows') for q in queries):
            raise ValueError('Локально не подготовлены продукты: нужен разбор публикаций и сведения об использовании ПО.')
        if args.prepare_only:
            report('Локальная подготовка готова. Сетевой импорт не выполнялся (--prepare-only).')
            return 0
        report('Загрузка в Neo4j из обычного терминала пользователя...')
        result = sync_graph(store)
        report(json.dumps(result, ensure_ascii=False, indent=2))
        report('ГОТОВО: импорт подтверждён. В браузере выберите базу neo4j на localhost:7687.')
        return 0
    except ValueError as exc:
        report('ОШИБКА: ' + str(exc))
        return 1
    except (OSError, KeyError, TypeError) as exc:
        report('ОШИБКА окружения или данных: ' + type(exc).__name__)
        return 1
    finally:
        print('Журнал: ' + str(log_path), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
