"""Full CLI smoke test in a fresh temporary DB; no network or personal files."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
env = dict(os.environ)
env.pop('CTI_DB_PATH', None)


def call(db, *args, expect=0):
    proc = subprocess.run([sys.executable, '-m', 'app.main', '--db', str(db), *map(str, args)],
                          cwd=root, env=env, text=True, capture_output=True, timeout=20)
    if proc.returncode != expect:
        raise RuntimeError(f'{args[0]}: код {proc.returncode}; {proc.stderr}')
    return json.loads(proc.stdout)


with tempfile.TemporaryDirectory(prefix='cti-smoke-') as tmp:
    folder = Path(tmp)
    db = folder / 'demo.sqlite3'
    assert call(db, 'demo')['inserted'] == 12
    assert call(db, 'demo')['unchanged'] == 12
    targets = call(db, 'targets', '--demo')
    assert abs(targets[0]['score'] - 70) < .05
    assert targets[1]['score'] is None
    result = call(db, 'report', '--demo', '--output', folder / 'report')
    assert result['publications'] == 12 and result['signals'] == 5
    for name in ['report.html', 'report.json', 'targets.csv']:
        assert (folder / 'report' / name).stat().st_size > 100
    call(db, 'graph-export', '--demo', '--output', folder / 'graph.json')
    call(db, 'import-feed', root / 'examples/feed_demo.xml', '--source-id', 'demo_rss', '--demo')
    assert len(call(db, 'signals', '--demo')) == 6
    call(db, 'import-source', 'securelist_research', root / 'tests/fixtures/securelist_listing_demo.html', '--demo')
    call(db, 'import-source', 'nckci_advisories', root / 'tests/fixtures/nckci_listing_demo.html', '--demo')
    call(db, 'import-source', 'nckci_advisories', root / 'tests/fixtures/nckci_json_demo.json',
         '--format', 'json', '--url', 'https://www.cert.gov.ru/upload/test-advisory.json', '--demo')
    call(db, 'graph-export', '--demo', '--output', folder / 'graph.json')
    graph = json.loads((folder / 'graph.json').read_text())
    assert any('MENTIONS_CVE' in q['statement'] and q.get('parameters', {}).get('rows') for q in graph['statements'])
    real = folder / 'real.sqlite3'
    expected_companies = len(json.loads((root / 'config/companies.json').read_text()))
    assert call(real, 'init')['companies'] == expected_companies
    assert call(real, 'import-jsonl', root / 'examples/open_source_seed.jsonl')['inserted'] == 3
    assert call(real, 'import-jsonl', root / 'examples/open_source_seed.jsonl')['unchanged'] == 3
    assert len(call(real, 'signals')) == 5
    assert all(r['score'] is None for r in call(real, 'targets'))
    assert call(real, 'status')['database_ok'] is True
    call(real, 'knowledge-seed')
    assert call(real, 'exposure')[0]['status'] == 'historical_use_only'
    assert len(call(real, 'knowledge')) >= 3
    before = len(call(real, 'knowledge'))
    call(real, 'reindex')
    assert len(call(real, 'knowledge')) == before
    call(real, 'knowledge-expand')
    assert call(real, 'threat-seed')['counts']['inserted'] == 11
    assert call(real, 'threat-seed')['counts']['unchanged'] == 11
    sensitivity = call(real, 'graph-sensitivity', '--output', folder / 'sensitivity')
    assert sensitivity['scenario_count'] == 45
    sensitivity_json = json.loads((folder / 'sensitivity/sensitivity.json').read_text())
    assert sensitivity_json['is_probability'] is False
    assert len(sensitivity_json['companies']) == 3
    assert call(real, 'status')['database_ok'] is True
    call(real, 'graph-export', '--output', folder / 'unified-graph.json')
    unified = json.loads((folder / 'unified-graph.json').read_text())
    for relation in ('ATTRIBUTED_TO', 'EXPLOITED', 'SHARES_PRODUCT_CONTEXT'):
        assert any('r:' + relation + ' ' in q['statement'] and q.get('parameters', {}).get('rows')
                   for q in unified['statements'])
    call(real, 'report', '--output', folder / 'real-report')
    data = json.loads((folder / 'real-report/report.json').read_text())
    assert len(data['knowledge_entities']) == 16
    call(db, 'knowledge-demo')
    weighted = call(db, 'graph-scores', '--demo')
    assert weighted['is_probability'] is False
    alpha = next(r for r in weighted['companies'] if r['company_id'] == 'demo-alpha')
    assert alpha['technical']['score'] is not None
    assert 'paths' not in alpha
    explained = call(db, 'graph-scores', '--demo', '--company', 'demo-alpha', '--explain')
    assert explained['companies'][0]['paths']
    assert explained['companies'][0]['technical']['score'] == alpha['technical']['score']
    states = {r['status'] for r in call(db, 'exposure', '--demo')}
    assert 'version_unknown' in states and 'version_match_requires_configuration_check' in states
    call(db, 'graph-export', '--demo', '--output', folder / 'full-graph.json')
    graph = json.loads((folder / 'full-graph.json').read_text())
    scored_nodes = [r for q in graph['statements'] for r in q.get('parameters', {}).get('rows', [])
                    if 'graph_score_model' in r.get('properties', {})]
    scored_alpha = next(r for r in scored_nodes if r['id'] == 'demo-alpha')
    assert scored_alpha['properties']['technical_exposure_index'] == alpha['technical']['score']
    assert any('r:USES_PRODUCT ' in q['statement'] for q in graph['statements'])
    assert any('r:AFFECTS ' in q['statement'] for q in graph['statements'])
    assert any('r:SUPPLIES_TO ' in q['statement'] for q in graph['statements'])
    assert call(real, 'company-attack-seed')['counts']['inserted'] == 1
    assert call(real, 'company-attack-seed')['counts']['unchanged'] == 1
    attack_fixture = root / 'tests/fixtures/attack_demo.json'
    assert call(real, 'attack-import', attack_fixture)['version'] == '1.0'
    assert call(real, 'attack-import', attack_fixture)['status'] == 'unchanged'
    entity_file = folder / 'entity.json'
    entity_file.write_text(json.dumps([{'id':'testgroup','entity_type':'ThreatActor','name':'Test Group'}]))
    call(real, 'entity-add', entity_file)
    assert call(real, 'attack-status')['confirmed_mappings'] == 0
    assert call(real, 'attack-search', 'T9991.001')[0]['name'] == 'Test Subtechnique'
    call(real, 'attack-map', 'testgroup', 'G9991', '--status', 'confirmed',
         '--reviewer', 'Smoke Analyst', '--note', 'Fictional fixture identity checked')
    assert call(real, 'attack-status')['confirmed_mappings'] == 1
    call(real, 'graph-export', '--output', folder / 'attack-graph.json')
    attack_graph = json.loads((folder / 'attack-graph.json').read_text())
    assert any('ATTACK_USES_TECHNIQUE' in q['statement'] for q in attack_graph['statements'])
    assert any('SET n:CompanyGraph' in q['statement'] for q in attack_graph['statements'])
    shodan_db = folder / 'shodan-demo.sqlite3'
    shodan = call(shodan_db, 'shodan-demo', '--output', folder / 'shodan')
    assert shodan['counts'] == {'inserted': 1}
    assert call(shodan_db, 'shodan-demo', '--output', folder / 'shodan')['counts'] == {'unchanged': 1}
    observed = call(shodan_db, 'shodan-list', '--demo')['observations']
    assert len(observed) == 1 and observed[0]['is_demo'] is True
    assert observed[0]['company_candidates'][0]['id'] == 'demo-alpha'
    assert observed[0]['association_review'] is None
    assert call(shodan_db, 'shodan-list')['observations'] == []
    assert (folder / 'shodan/shodan.html').is_file()
    print('CLI smoke: OK — сбор/импорт, повторы, единый граф, ATT&CK, версии, отчёт и отдельный пример Shodan.')
