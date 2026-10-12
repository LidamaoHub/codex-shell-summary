import json
from pathlib import Path
import sys
import subprocess
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_backend import analyze, AnalysisError, event_diagnostics

class NativeDiagnosticsTests(unittest.TestCase):
    def test_diagnostics_do_not_copy_text_ids_paths_or_arbitrary_categories(self):
        secret = 'synthetic-private-payload'
        events = [
            {'type': 'thread.started', 'thread_id': secret},
            {'type': 'turn.started'},
            {'type': 'error', 'message': 'Reconnecting 1/5 '+secret},
            {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': secret}},
            {'type': secret},
        ]
        stdout = '\n'.join(map(json.dumps, events)).encode()
        result = event_diagnostics(stdout, secret.encode())
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result['event_counts']['agent_message'], 1)
        self.assertEqual(result['event_counts']['turn.completed'], 0)
        self.assertEqual(result['reconnect_events'], 1)

    def test_timeout_kills_parser_and_reports_only_state(self):
        proc = Mock(pid=987654)
        proc.communicate.side_effect = [subprocess.TimeoutExpired('codex', 1),
            (b'{"type":"turn.started"}\n', b'synthetic-private-stderr')]
        states = []
        with patch('native_backend.subprocess.Popen', return_value=proc), patch('os.killpg') as kill:
            with self.assertRaises(AnalysisError) as raised:
                analyze({'output_fragment': 'synthetic-private-input'}, timeout=1, register=states.append)
        self.assertEqual(str(raised.exception), 'analysis_timeout')
        self.assertEqual(raised.exception.diagnostics['event_counts']['turn.started'], 1)
        self.assertNotIn('private', json.dumps(raised.exception.diagnostics))
        kill.assert_called_once()
        self.assertEqual(states, [proc, None])
