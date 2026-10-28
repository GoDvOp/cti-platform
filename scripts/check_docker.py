"""Exercise a submission in isolated Docker resources; never touch the working stack."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
import tomllib
import uuid
import zipfile
from urllib.request import Request, urlopen
import re


def runtime_fingerprint(root):
    names = ['Dockerfile', 'docker-compose.yml', 'start-cti.sh', '.dockerignore', '.env.example', 'pyproject.toml',
             'data/review_snapshot.json.gz', 'data/submission_manifest.json']
    for folder in ('app', 'config', 'examples', 'scripts', 'evaluation', 'tests', 'docs/cases'):
        names.extend(p.relative_to(root).as_posix() for p in (root / folder).rglob('*')
                     if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
    rows = {}
    for name in sorted(names):
        data = (root / name).read_bytes()
        if name == 'config/submission.json':
            # Author and PDF name are editorial metadata, covered by the archive
            # manifest, and do not affect the runtime acceptance result.
            settings = json.loads(data)
            for key in ('author', 'report_filename'):
                settings.pop(key, None)
            data = json.dumps(settings, sort_keys=True, ensure_ascii=False).encode()
        rows[name] = hashlib.sha256(data).hexdigest()
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--temp-dir', type=Path, default=Path.home() / '.cache/cti-platform/docker-checks')
    args = parser.parse_args()
    args.temp_dir.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(args.temp_dir).free < 512 * 1024 ** 2:
        raise SystemExit('Для приёмки нужно минимум 512 MiB свободного места; задайте другой --temp-dir.')
    results = []
    receipt = {'execution': 'real_docker_clean_archive',
               'started_at': datetime.now(timezone.utc).isoformat(), 'checks': results}
    with tempfile.TemporaryDirectory(prefix='cti docker acceptance ', dir=args.temp_dir) as tmp:
        base = Path(tmp)
        with zipfile.ZipFile(args.archive) as archive:
            for member in archive.infolist():
                target = (base / member.filename).resolve()
                if not target.is_relative_to(base.resolve()):
                    raise ValueError('Archive member escapes extraction directory')
            archive.extractall(base)
            for member in archive.infolist():
                if not member.is_dir():
                    (base / member.filename).chmod(0o755 if (member.external_attr >> 16) & 0o111 else 0o644)
        root = base / 'cti-platform'
        receipt['project_version'] = tomllib.loads((root / 'pyproject.toml').read_text())['project']['version']
        receipt['runtime_input_sha256'] = runtime_fingerprint(root)
        project = 'cti-check-' + uuid.uuid4().hex[:10]
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(('CTI_', 'NEO4J_', 'COMPOSE_', 'SHODAN_'))}
        env.update(COMPOSE_PROJECT_NAME=project, CTI_IMAGE='cti-platform-check:' + project,
                   CTI_NEO4J_HTTP_PORT='0', CTI_NEO4J_BOLT_PORT='0', CTI_WORKBENCH_PORT='0')
        # Use an existing disabled source to avoid external traffic in acceptance.
        override = root / 'acceptance.override.json'
        override.write_text(json.dumps({'services': {'worker': {
            'command': ['worker', '--sync-graph', '--source-id', 'pt_standoff_news']}}}))
        env['COMPOSE_FILE'] = 'docker-compose.yml' + os.pathsep + override.name

        def run(*command, expected=0, timeout=480):
            done = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=timeout)
            if done.returncode != expected:
                # Do not dump resolved Compose configuration or credentials.
                raise RuntimeError(f'{command[0:3]} returned {done.returncode}: '
                                   + done.stderr[-2500:] + '\n' + done.stdout[-500:])
            return done.stdout

        def check(name, valid, **details):
            results.append({'name': name, 'status': 'passed' if valid else 'failed', **details})
            print(name + ': ' + results[-1]['status'], flush=True)
            if not valid:
                raise RuntimeError('Acceptance check failed: ' + name)

        def read(name):
            return json.loads((root / name).read_text())

        try:
            receipt['docker_engine'] = run('docker', 'version', '--format', '{{.Server.Version}}').strip()
            receipt['docker_compose'] = run('docker', 'compose', 'version', '--short').strip()
            check('archive_excludes_local_env_and_working_database',
                  not (root / '.env').exists() and not (root / 'data/cti.sqlite3').exists())
            run('sh', 'scripts/docker.sh', 'review')
            reviewed = read('data/review/review_result.json')
            first_scores = read('data/review/report/graph_scores.json')
            check('offline_review_real_container', reviewed['offline'] is True and reviewed['publications'] == 374
                  and reviewed['assertions'] == 99 and not (root / '.env').exists()
                  and not (root / 'data/cti.sqlite3').exists(), publications=reviewed['publications'])
            config = json.loads(run('docker', 'compose', '--profile', 'review', 'config', '--format', 'json'))
            check('offline_container_has_no_network_or_credentials',
                  config['services']['review']['network_mode'] == 'none'
                  and not config['services']['review'].get('environment')
                  and config['services']['review']['read_only'] is True)
            run('docker', 'compose', 'run', '--rm', '--no-deps', '-T', 'review')
            check('offline_repeat_is_reproducible', read('data/review/report/graph_scores.json') == first_scores)
            run(str(root / 'start-cti.sh'))
            rows = [json.loads(line) for line in run('docker', 'compose', 'ps', '--format', 'json').splitlines()]
            check('all_core_services_healthy',
                  {s['Service'] for s in rows} == {'neo4j', 'worker', 'workbench'}
                  and all(s['Health'] == 'healthy' for s in rows))
            panel_address = run('docker', 'compose', 'port', 'workbench', '8765').strip()
            panel_url = 'http://' + panel_address
            with urlopen(panel_url + '/api/dashboard', timeout=20) as response:
                panel = json.load(response)
            check('workbench_has_positive_case_and_docker_state', panel['runtime']['mode'] == 'docker'
                  and panel['companies'][0]['id'] == 'ispras' and panel['companies'][0]['priority'] == 0)
            resolved = json.loads(run('docker', 'compose', 'config', '--format', 'json'))
            check('workbench_receives_no_service_credentials',
                  set(resolved['services']['workbench'].get('environment', {})) == {'CTI_DB_PATH'})
            example = next(c for c in panel['companies'] if c['id'] == 'equifax')
            check('v3_example_and_quality_warnings_are_preserved', panel['model'] == 'weighted-graph-v3'
                  and example['historical_technical']['score'] == 90
                  and not example['historical_technical']['current_vulnerability_established']
                  and any(r['review_warnings'] for r in example['relations'])
                  and len(panel['sources']) == 9 and all(s['enabled'] for s in panel['sources']))
            with urlopen(panel_url, timeout=20) as response:
                page = response.read().decode()
            with urlopen(panel_url + '/api/shodan/example', timeout=20) as response:
                preview = json.load(response)
            with urlopen(panel_url + '/api/shodan', timeout=20) as response:
                observed = json.load(response)
            check('shodan_preview_requires_no_key_and_preserves_database',
                  preview['example_only'] is True and preview['observations'][0]['is_demo'] is True
                  and observed['observations'] == [] and 'Наблюдения Shodan' in page)
            token = re.search(r'name="cti-token" content="([^"]+)"', page).group(1)
            def panel_action(action):
                req = Request(panel_url + '/api/control', data=json.dumps({'action': action}).encode(),
                              headers={'Content-Type': 'application/json', 'X-CTI-Token': token})
                with urlopen(req, timeout=20) as response:
                    return json.load(response)
            def wait_phase(paused):
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    state = read('data/diagnostics/auto_update/status.json')
                    if (state.get('phase') == 'paused') == paused:
                        return True
                    time.sleep(.2)
                return False
            panel_action('pause')
            check('docker_worker_acknowledges_panel_pause', wait_phase(True))
            panel_action('resume')
            check('docker_worker_acknowledges_panel_resume', wait_phase(False))
            panel_action('refresh')
            check('docker_panel_refresh_request_is_accepted', True)
            audit = read('data/diagnostics/auto_update/audit.json')
            check('worker_graph_matches_sqlite', audit['status'] == 'passed' and len(audit['checks']) == 9,
                  counts=audit['counts'])
            logs = run('docker', 'compose', 'logs', '--no-log-prefix', 'worker')
            check('new_database_restored_from_public_snapshot', '"restored_public_snapshot": true' in logs)
            env_hash = hashlib.sha256((root / '.env').read_bytes()).hexdigest()
            check('generated_env_is_private', (root / '.env').stat().st_mode & 0o777 == 0o600)
            identity_hash = run('docker', 'compose', 'exec', '-T', 'neo4j',
                                'sha256sum', '/data/server_id').strip()
            run('docker', 'compose', 'stop', 'worker')
            with sqlite3.connect(root / 'data/cti.sqlite3') as db:
                db.execute('CREATE TABLE acceptance_marker (id TEXT PRIMARY KEY)')
                db.execute('INSERT INTO acceptance_marker VALUES (?)', ('preserve-after-recreate',))
                pubs = db.execute('SELECT count(*) FROM publications').fetchone()[0]
            run('docker', 'compose', 'down')
            run(str(root / 'start-cti.sh'))
            run('docker', 'compose', 'stop', 'worker')
            with sqlite3.connect(root / 'data/cti.sqlite3') as db:
                marker = db.execute('SELECT id FROM acceptance_marker').fetchone()[0]
                after_pubs = db.execute('SELECT count(*) FROM publications').fetchone()[0]
            check('data_and_password_survive_container_recreation',
                  marker == 'preserve-after-recreate' and pubs == after_pubs
                  and hashlib.sha256((root / '.env').read_bytes()).hexdigest() == env_hash)
            check('valid_neo4j_identity_survives_container_recreation',
                  run('docker', 'compose', 'exec', '-T', 'neo4j',
                      'sha256sum', '/data/server_id').strip() == identity_hash)
            def cypher(statement):
                return run('docker', 'compose', 'exec', '-T', 'neo4j', 'sh', '-c',
                           'exec cypher-shell -u neo4j -p "$CTI_GRAPH_PASSWORD" "$1"',
                           'acceptance', statement)
            cypher("CREATE (:CtiStartupAcceptance {id: 'preserve-graph-on-repair'})")
            for length in (0, 8):
                run('docker', 'compose', 'stop', 'worker', 'neo4j')
                run('docker', 'compose', 'run', '--rm', '--no-deps', '-T',
                    '--entrypoint', 'sh', 'neo4j', '-c',
                    'head -c "$1" /data/server_id > /data/cti-acceptance-truncated; '
                    'cat /data/cti-acceptance-truncated > /data/server_id',
                    'acceptance', str(length))
                run('docker', 'compose', 'up', '-d', '--no-build', '--wait',
                    '--wait-timeout', '180', 'neo4j')
                backups = run('docker', 'compose', 'exec', '-T', 'neo4j', 'sh', '-c',
                              'find /data -maxdepth 2 -path "/data/cti-server-id-backup.*/server_id" '
                              '-type f -exec cmp -s /data/cti-acceptance-truncated {} \\; -print')
                size = run('docker', 'compose', 'exec', '-T', 'neo4j',
                           'sh', '-c', 'wc -c < /data/server_id').strip()
                check(f'neo4j_recovers_{length}_byte_identity_without_losing_graph',
                      bool(backups.strip()) and size == '17'
                      and 'preserve-graph-on-repair' in cypher('MATCH (n:CtiStartupAcceptance) RETURN n.id'))
            cypher('MATCH (n:CtiStartupAcceptance) DETACH DELETE n')
            run(str(root / 'start-cti.sh'))
            recovery_config = json.loads(run('docker', 'compose', '--profile', 'tools',
                                             'config', '--format', 'json'))['services']['neo4j-recovery']
            check('password_recovery_has_no_network_or_published_ports',
                  recovery_config['network_mode'] == 'none' and not recovery_config.get('ports')
                  and recovery_config['hostname'] == 'localhost')
            cypher("MATCH (n:Company) WITH n LIMIT 1 SET n.cti_recovery_marker = 'preserve-auth-repair'")
            cypher("ALTER USER neo4j SET PASSWORD 'cti-acceptance-old-password' CHANGE NOT REQUIRED")
            run(str(root / 'start-cti.sh'), 'repair-neo4j')
            backups = list((root / 'data/diagnostics/neo4j-recovery').glob('recovery.*/neo4j-data.tar.gz'))
            check('password_recovery_preserves_graph_and_creates_backup',
                  len(backups) == 1 and backups[0].stat().st_size > 0
                  and 'preserve-auth-repair' in cypher('MATCH (n:Company) WHERE n.cti_recovery_marker IS NOT NULL RETURN n.cti_recovery_marker')
                  and hashlib.sha256((root / '.env').read_bytes()).hexdigest() == env_hash)
            run(str(root / 'start-cti.sh'), 'repair-neo4j')
            check('password_recovery_also_accepts_already_matching_password',
                  'preserve-auth-repair' in cypher('MATCH (n:Company) WHERE n.cti_recovery_marker IS NOT NULL RETURN n.cti_recovery_marker'))
            cypher('MATCH (n:Company) REMOVE n.cti_recovery_marker')
            run('docker', 'compose', 'run', '--rm', '--no-deps', '-T', 'cli',
                'python', 'scripts/audit_graph.py', '--sync', '--repeat')
            live = read('data/diagnostics/neo4j_audit/audit.json')
            check('live_graph_audit_after_recreation', live['status'] == 'passed'
                  and live['repeat']['graph_unchanged'] is True,
                  checks=len(live['checks']), repeat_unchanged=live['repeat']['graph_unchanged'])
            shodan = json.loads(run('docker', 'compose', 'run', '--rm', '--no-deps', '-T',
                '-e', 'CTI_DISPOSABLE_GRAPH_CHECK=1', 'cli', 'python', 'scripts/check_shodan_graph.py'))
            check('shodan_live_context_edge_indices_and_revocation', shodan['status'] == 'passed', **shodan)
            test_result = run('docker', 'compose', 'run', '--rm', '--no-deps', '-T', 'review',
                'python', '-c', 'import unittest,json,sys; '
                'r=unittest.TextTestRunner().run(unittest.defaultTestLoader.discover("tests")); '
                'print(json.dumps({"count":r.testsRun,"skipped":len(r.skipped)})); '
                'sys.exit(0 if r.wasSuccessful() else 1)')
            test_counts = json.loads(test_result.strip().splitlines()[-1])
            check('container_unit_tests', True, **test_counts)
            receipt['python_container'] = run('docker', 'compose', 'run', '--rm', '--no-deps', '-T',
                                              'review', 'python', '--version').strip()
            run('docker', 'compose', 'run', '--rm', '--no-deps', '-T', 'review', 'python', 'scripts/smoke.py')
            check('container_cli_smoke', True)
            run(str(root / 'start-cti.sh'), 'stop')
            try:
                with urlopen(panel_url + '/health', timeout=3):
                    stopped = False
            except OSError:
                stopped = True
            check('stop_removes_workbench_listener', stopped)
            receipt['status'] = 'passed'
        except Exception as exc:
            receipt['status'] = 'failed'
            receipt['error'] = str(exc)
            state = root / 'data/diagnostics/auto_update/status.json'
            if state.exists():
                receipt['worker_state_at_failure'] = json.loads(state.read_text())
            diagnostic = subprocess.run(['docker', 'compose', 'logs', '--tail', '15', 'worker'],
                                        cwd=root, env=env, capture_output=True, text=True)
            receipt['worker_log_at_failure'] = diagnostic.stdout[-4000:]
            raise
        finally:
            cleanup = subprocess.run(['docker', 'compose', 'down', '-v', '--remove-orphans'],
                                     cwd=root, env=env, capture_output=True, text=True)
            subprocess.run(['docker', 'image', 'rm', env['CTI_IMAGE']], capture_output=True, text=True)
            receipt['isolated_resource_cleanup'] = 'passed' if cleanup.returncode == 0 else 'failed'
            receipt['finished_at'] = datetime.now(timezone.utc).isoformat()
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
