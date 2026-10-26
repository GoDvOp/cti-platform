from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.desktop import install, service_text, desktop_text, control, ensure_neo4j, unit_directory, UNIT


class DesktopTests(unittest.TestCase):
    def test_install_user_startup_and_launchers_in_paths_with_spaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            desktop = home / 'Рабочий стол'
            paths = install(root=home / 'Проекты с пробелами/cti', home=home, desktop=desktop)
            link = Path(paths['autostart_link'])
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve(), Path(paths['unit']))
            self.assertIn('worker" "--sync-graph', Path(paths['unit']).read_text())
            self.assertIn('Terminal=false', Path(paths['desktop']).read_text())
            install(root=home / 'Проекты с пробелами/cti', home=home, desktop=desktop)
            self.assertTrue(link.is_symlink())

    def test_commands_use_user_service_and_no_shell_or_elevation(self):
        with patch('app.desktop._run', return_value={'ok': True, 'output': ''}) as run, \
                patch('app.desktop.install'):
            control('start')
            self.assertEqual(run.call_args_list[0].args[0], ['systemctl', '--user', 'daemon-reload'])
            self.assertEqual(run.call_args_list[1].args[0], ['systemctl', '--user', 'restart', UNIT])
            control('stop')
            self.assertEqual(run.call_args.args[0], ['systemctl', '--user', 'disable', '--now', UNIT])

    def test_control_does_not_report_start_when_session_bus_unavailable(self):
        with patch('app.desktop._run', return_value={'ok': False, 'output': 'Operation not permitted'}) as run, \
                patch('app.desktop.install'):
            self.assertFalse(control('start')['ok'])
            self.assertEqual(run.call_count, 1)

    def test_refresh_wakes_active_worker_without_restarting_collection(self):
        with patch('app.desktop.service_status', return_value={'active': True}), \
                patch('app.desktop._run', return_value={'ok': True}) as run:
            control('refresh')
            self.assertEqual(run.call_args.args[0],
                ['systemctl', '--user', 'kill', '--kill-whom=main', '--signal=USR1', UNIT])

    def test_neo4j_start_does_not_download_images(self):
        with patch('app.desktop.shutil.which', return_value='/usr/bin/docker'), \
                patch('app.desktop._run', return_value={'ok': True}) as run:
            ensure_neo4j()
            args = run.call_args.args[0]
            self.assertIn('--no-build', args)
            self.assertEqual(args[args.index('--pull') + 1], 'never')

    def test_launch_specs_quote_path_and_reject_newlines(self):
        for render in (service_text, desktop_text):
            value = render(Path('/tmp/Каталог с пробелами/%data'))
            self.assertIn('%%data', value)
            self.assertNotIn('sudo', value)
            with self.assertRaises(ValueError):
                render(Path('/tmp/bad\npath'))

    def test_working_directory_is_literal_absolute_path_not_an_exec_argument(self):
        root = Path('/home/example/Проекты с пробелами/$data/100%')
        value = service_text(root)
        directory = next(line for line in value.splitlines() if line.startswith('WorkingDirectory='))
        self.assertEqual(directory, 'WorkingDirectory=/home/example/Проекты с пробелами/$data/100%%')
        self.assertTrue(directory.split('=', 1)[1].startswith('/'))
        self.assertNotIn('WorkingDirectory="', value)
        self.assertIn('ExecStart="/home/example/Проекты с пробелами/$$data/100%%/.venv/bin/python"', value)
        with self.assertRaises(ValueError):
            unit_directory('relative/path')
