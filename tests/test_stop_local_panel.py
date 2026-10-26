"""The Docker switch must stop only desktop panels from the same project."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(Path('/proc/self/cwd').exists(), 'Linux desktop process inspection')
class StopLocalPanelTests(unittest.TestCase):
    def test_stops_own_panel_and_preserves_other_projects_and_processes(self):
        with tempfile.TemporaryDirectory(prefix='cti panels ') as tmp:
            roots = [Path(tmp) / name for name in ('own project', 'other project')]
            children = []
            try:
                for root in roots:
                    (root / 'app').mkdir(parents=True)
                    (root / 'app/__init__.py').write_text('')
                    (root / 'app/workbench.py').write_text('import time; time.sleep(60)\n')
                    children.append(subprocess.Popen([sys.executable, '-m', 'app.workbench'], cwd=root))
                children.append(subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], cwd=roots[0]))
                (roots[0] / 'scripts').mkdir()
                script = roots[0] / 'scripts/stop_local_panel.sh'
                shutil.copy2(ROOT / 'scripts/stop_local_panel.sh', script)
                done = subprocess.run(['sh', str(script)], capture_output=True, text=True, timeout=10)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(children[0].wait(timeout=5), -15)
                self.assertIsNone(children[1].poll())
                self.assertIsNone(children[2].poll())
                again = subprocess.run(['sh', str(script)], capture_output=True, text=True, timeout=10)
                self.assertEqual(again.returncode, 0, again.stderr)
            finally:
                for child in children:
                    if child.poll() is None:
                        child.terminate()
                    child.wait(timeout=5)
