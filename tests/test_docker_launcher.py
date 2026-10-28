"""Check launcher failure paths without touching Docker or user services."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FAKE = r'''
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['LAUNCH_LOG'], 'a') as log:
    log.write(json.dumps([name, args, os.getcwd()]) + '\n')
mode = os.environ.get('LAUNCH_MODE', '')
if name == 'systemctl':
    if 'is-active' in args:
        sys.exit(3 if mode in ('inactive', 'inactive-enabled') else 0)
    if 'show' in args:
        print('/another/project' if mode == 'other' else os.getcwd())
    if 'is-enabled' in args:
        print('disabled' if mode == 'inactive' else 'enabled')
        sys.exit(1 if mode == 'inactive' else 0)
elif args == ['info'] and mode == 'unavailable':
    sys.exit(1)
elif args[:2] == ['compose', 'build'] and mode == 'build-failed':
    sys.exit(1)
elif args[:2] == ['compose', 'up'] and mode in ('up-failed', 'stop-failed'):
    sys.exit(1)
elif args == ['compose', 'stop', 'worker'] and mode == 'stop-failed':
    sys.exit(1)
elif args[:2] == ['compose', 'run'] and 'neo4j-recovery' in args and mode == 'repair-failed':
    sys.exit(1)
elif args[:2] == ['compose', 'port']:
    print('127.0.0.1:18766')
'''


class DockerLauncherTests(unittest.TestCase):
    def run_launcher(self, mode='', *args, direct=False):
        # The offline review container deliberately mounts /tmp with noexec.
        # Keep executable fixtures in a disposable folder on its data mount.
        with tempfile.TemporaryDirectory(prefix='.cti launcher ', dir=ROOT / 'data') as tmp:
            base = Path(tmp)
            root = base / 'project with spaces'
            (root / 'scripts').mkdir(parents=True)
            shutil.copy2(ROOT / 'start-cti.sh', root)
            shutil.copy2(ROOT / 'scripts/docker.sh', root / 'scripts')
            shutil.copy2(ROOT / 'scripts/stop_local_panel.sh', root / 'scripts')
            (root / '.env').write_text('NEO4J_PASSWORD=local-test-only\n')
            (root / 'data').mkdir()
            (root / 'data/cti.sqlite3').write_bytes(b'existing database')
            commands = base / 'bin'
            commands.mkdir()
            for name in ('docker', 'systemctl'):
                path = commands / name
                path.write_text('#!' + sys.executable + '\n' + FAKE)
                path.chmod(0o755)
            log = base / 'calls.jsonl'
            env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'],
                       LAUNCH_LOG=str(log), LAUNCH_MODE=mode)
            command = ['sh', str(root / 'scripts/docker.sh')] if direct else [str(root / 'start-cti.sh')]
            done = subprocess.run([*command, *args], cwd=base,
                                  env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual((root / '.env').read_text(), 'NEO4J_PASSWORD=local-test-only\n')
            self.assertEqual((root / 'data/cti.sqlite3').read_bytes(), b'existing database')
            calls = [json.loads(row)[:2] for row in log.read_text().splitlines()] if log.exists() else []
            if log.exists():
                self.assertTrue(all(json.loads(row)[2] == str(root) for row in log.read_text().splitlines()))
            return done, calls

    def test_launch_switches_own_service_after_build_and_displays_actual_port(self):
        done, calls = self.run_launcher()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn('http://127.0.0.1:18766/', done.stdout)
        stop = ['systemctl', ['--user', 'stop', 'cti-platform-update.service']]
        self.assertLess(calls.index(['docker', ['compose', 'build', 'cli']]), calls.index(stop))
        self.assertEqual(calls[calls.index(stop) - 1][1][:2], ['compose', 'run'])
        disable = ['systemctl', ['--user', 'disable', 'cti-platform-update.service']]
        up = next(c for c in calls if c[0] == 'docker' and c[1][:2] == ['compose', 'up'])
        self.assertLess(calls.index(up), calls.index(disable))

    def test_direct_helper_also_switches_own_desktop_service(self):
        done, calls = self.run_launcher('', 'up', direct=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(['systemctl', ['--user', 'stop', 'cti-platform-update.service']], calls)
        self.assertIn(['systemctl', ['--user', 'disable', 'cti-platform-update.service']], calls)

    def test_inactive_but_enabled_service_cannot_restart_after_login(self):
        done, calls = self.run_launcher('inactive-enabled')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(['systemctl', ['--user', 'disable', 'cti-platform-update.service']], calls)
        self.assertFalse(any(name == 'systemctl' and 'stop' in args for name, args in calls))

    def test_preflight_and_build_failure_leave_desktop_running(self):
        for mode in ('unavailable', 'build-failed'):
            with self.subTest(mode=mode):
                done, calls = self.run_launcher(mode)
                self.assertNotEqual(done.returncode, 0)
                self.assertFalse(any(name == 'systemctl' and 'stop' in args for name, args in calls))

    def test_failed_start_stops_container_before_restoring_service(self):
        done, calls = self.run_launcher('up-failed')
        self.assertNotEqual(done.returncode, 0)
        self.assertLess(calls.index(['docker', ['compose', 'stop', 'worker']]),
                        calls.index(['systemctl', ['--user', 'start', 'cti-platform-update.service']]))
        self.assertFalse(any(name == 'systemctl' and 'disable' in args for name, args in calls))

    def test_failed_container_stop_does_not_start_second_collector(self):
        done, calls = self.run_launcher('stop-failed')
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(any(name == 'systemctl' and 'start' in args for name, args in calls))

    def test_unrelated_and_inactive_services_are_untouched(self):
        for mode in ('other', 'inactive'):
            with self.subTest(mode=mode):
                done, calls = self.run_launcher(mode)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertFalse(any(name == 'systemctl' and 'stop' in args for name, args in calls))

    def test_management_commands_are_forwarded_without_service_switch(self):
        for command, expected in [('stop', ['compose', 'stop']), ('status', ['compose', 'ps', '--all']),
                                  ('logs', ['compose', 'logs', '--tail', '100', 'worker'])]:
            with self.subTest(command=command):
                args = [command, 'worker'] if command == 'logs' else [command]
                done, calls = self.run_launcher('', *args)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn(['docker', expected], calls)
                self.assertFalse(any(name == 'systemctl' for name, _ in calls))

    def test_repair_stops_stack_before_recovery_and_restarts_normal_stack(self):
        done, calls = self.run_launcher('', 'repair-neo4j')
        self.assertEqual(done.returncode, 0, done.stderr)
        stop = ['docker', ['compose', 'stop', '-t', '60', 'workbench', 'worker', 'neo4j']]
        recovery = next(c for c in calls if 'neo4j-recovery' in c[1])
        normal = next(c for c in calls if c[1][:2] == ['compose', 'up'])
        self.assertLess(calls.index(stop), calls.index(recovery))
        self.assertLess(calls.index(recovery), calls.index(normal))
        self.assertIn('workbench', normal[1])
        self.assertIn('--wait', normal[1])

    def test_failed_repair_restores_authenticated_service_without_starting_worker(self):
        done, calls = self.run_launcher('repair-failed', 'repair-neo4j')
        self.assertEqual(done.returncode, 1)
        ups = [c[1] for c in calls if c[1][:2] == ['compose', 'up']]
        self.assertEqual(ups, [['compose', 'up', '-d', '--no-build', 'neo4j']])
