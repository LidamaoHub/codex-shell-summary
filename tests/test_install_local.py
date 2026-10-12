import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import install_local

class InstallTests(unittest.TestCase):
    def test_preview_never_generates_source_or_registers_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'home'
            with patch.object(sys, 'argv', ['install', '--workspace', tmp, '--codex-home', str(home)]), \
                 patch('install_local.build') as build, patch('install_local.subprocess.run') as run, \
                 contextlib.redirect_stdout(io.StringIO()):
                install_local.main()
            build.assert_not_called(); run.assert_not_called()
            self.assertFalse(home.exists())

    def test_apply_uses_selected_home_and_stops_on_registration_failure(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'home'
            with patch.object(sys, 'argv', ['install', '--workspace', tmp, '--codex-home', str(home), '--apply']), \
                 patch('install_local.build') as build, \
                 patch('install_local.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'codex')) as run, \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(subprocess.CalledProcessError): install_local.main()
            build.assert_called_once()
            self.assertEqual(build.call_args.kwargs['allowed_cwd'], Path(tmp).resolve())
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.kwargs['env']['CODEX_HOME'], str(home.resolve()))

    def test_rejects_missing_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                install_local.plan(Path(tmp), Path(tmp)/'missing')
