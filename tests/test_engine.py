import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import Engine
from native_backend import AnalysisError

def fake(payload, **kwargs):
    return {'analysis': {'contains_sensitive_information': False, 'body': '命令状态已解析', 'attention': ''}, 'usage': None}

class EngineTests(unittest.TestCase):
    def test_parser_failure_state_diagnostics_preserved_without_log(self):
        diagnostics = {'event_counts': {'turn.started': 1, 'turn.completed': 0}}
        def fail(payload, **kwargs):
            raise AnalysisError('analysis_timeout', diagnostics)
        self.engine.analyzer = fail
        result = self.engine.execute({'cmd': "printf 'synthetic ordinary output'", 'login': False})
        self.assertEqual(result['analysis_diagnostics'], diagnostics)
        self.assertEqual(result['summary_error'], 'analysis_timeout')
        self.assertFalse(result['log_saved'])
        self.assertFalse(result['raw_output_in_memory'])

    def setUp(self):
        self.previous = os.environ.get('SHELL_SUMMARY_EXECUTION_PROFILE')
        os.environ['SHELL_SUMMARY_EXECUTION_PROFILE'] = 'unrestricted-local'
        self.logs = tempfile.TemporaryDirectory()
        self.log_env = patch.dict(os.environ, {'SHELL_SUMMARY_LOG_DIR': self.logs.name})
        self.log_env.start()
        self.engine = Engine(fake)
    def tearDown(self):
        self.engine.close()
        self.log_env.stop(); self.logs.cleanup()
        if self.previous is None: os.environ.pop('SHELL_SUMMARY_EXECUTION_PROFILE', None)
        else: os.environ['SHELL_SUMMARY_EXECUTION_PROFILE'] = self.previous

    def test_summary_failure_returns_original_and_discards_without_reexecution(self):
        with tempfile.TemporaryDirectory() as tmp:
            counter = Path(tmp) / 'counter'
            def failure(*args, **kwargs): raise AnalysisError('synthetic_quota_failure')
            self.engine.analyzer = failure
            result = self.engine.execute({'cmd': 'printf x >> counter; printf PRIVATE_OUTPUT', 'workdir': tmp, 'login': False})
            self.assertEqual(counter.read_text(), 'x')
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['summary_status'], 'failed')
            self.assertFalse(result['raw_output_retained'])
            self.assertEqual(result['raw_output']['stdout'], 'PRIVATE_OUTPUT')
            self.assertFalse(result['log_saved'])
            self.assertIn('解析', result['notice'])
            self.assertEqual(result['sensitivity_status'], 'unknown')
            def forbidden(*args, **kw): self.fail('failed output must have been discarded')
            self.engine.analyzer = forbidden
            again = self.engine.reinterpret({'execution_id': result['execution_id'], 'question': 'explain again'})
            self.assertTrue(again['rerun_required'])
            self.assertEqual(again['reason'], 'analysis_failed_output_discarded')
            self.assertFalse(again['command_reexecuted'])
            self.assertEqual(counter.read_text(), 'x')
            self.assertFalse(list(Path(self.logs.name).iterdir()))
            self.assertFalse(self.engine.runs)
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ['counter'])

    def sensitive(self, payload, **kw):
        return {'analysis': {'contains_sensitive_information': True, 'body': '', 'attention': ''}, 'usage': None}

    def test_sensitive_returns_original_and_cannot_be_reinterpreted(self):
        self.engine.analyzer = self.sensitive
        result = self.engine.execute({'cmd': 'printf SYNTHETIC_SECRET', 'login': False})
        self.assertEqual(result['raw_output']['stdout'], 'SYNTHETIC_SECRET')
        self.assertTrue(result['raw_return_complete'])
        self.assertNotIn('analysis', result)
        self.assertFalse(list(Path(self.logs.name).iterdir()))
        self.assertEqual(self.engine.records[result['execution_id']], 'sensitive_output_discarded')
        def forbidden(*args, **kw): self.fail('discarded data must not be analyzed')
        self.engine.analyzer = forbidden
        again = self.engine.reinterpret({'execution_id': result['execution_id'], 'question': 'again'})
        self.assertEqual(again['reason'], 'sensitive_output_discarded')
        self.assertTrue(again['rerun_required'])
        self.assertFalse(again['command_reexecuted'])

    def test_reinterpret_new_sensitive_detection_purges_original(self):
        result = self.engine.execute({'cmd': 'printf SYNTHETIC_SECRET', 'login': False})
        self.engine.analyzer = self.sensitive
        again = self.engine.reinterpret({'execution_id': result['execution_id'], 'question': 'check again'})
        self.assertEqual(again['raw_output']['stdout'], 'SYNTHETIC_SECRET')
        self.assertFalse(again['raw_output_retained'])
        self.assertFalse(self.engine.store.path(result['execution_id']).exists())

    def test_sensitive_later_chunk_purges_previous_chunks(self):
        result = self.engine.execute({'cmd': 'printf FIRST; sleep 0.7; printf SECRET; sleep 0.7; printf LAST', 'login': False, 'yield_time_ms': 250})
        self.engine.analyzer = self.sensitive
        second = self.engine.poll({'session_id': result['session_id'], 'yield_time_ms': 600})
        self.assertEqual(second['raw_output']['stdout'], 'FIRSTSECRET')
        run = self.engine.runs[result['session_id']]
        self.assertFalse(any(run.retained_streams.values()))
        def forbidden(*args, **kw): self.fail('known sensitive run must bypass subsequent analysis')
        self.engine.analyzer = forbidden
        last = self.engine.poll({'session_id': result['session_id'], 'yield_time_ms': 1000})
        self.assertEqual(last['raw_output']['stdout'], 'LAST')
        self.assertFalse(list(Path(self.logs.name).iterdir()))

    def test_sensitive_budget_marks_truncation_without_retention(self):
        self.engine.analyzer = self.sensitive
        result = self.engine.execute({'cmd': 'printf SYNTHETIC_SECRET', 'login': False, 'max_output_tokens': 1})
        self.assertEqual(result['raw_output']['stdout'], 'SYNT')
        self.assertTrue(result['raw_return_truncated'])
        self.assertFalse(result['raw_output_retained'])

    def test_more_than_eight_commands_persist_and_reinterpret_after_restart(self):
        results = []
        with patch.dict(os.environ, {'SHELL_SUMMARY_RETAINED_RUNS': '1'}):
            for i in range(12):
                result = self.engine.execute({'cmd': 'printf ORIGINAL_%d' % i, 'login': False})
                self.assertTrue(result['log_saved'])
                self.assertFalse(result['raw_output_in_memory'])
                results.append(result)
        first = results[0]
        self.assertEqual(self.engine.store.load(first['execution_id'])['output']['stdout'], 'ORIGINAL_0')
        self.assertEqual(len(list(Path(self.logs.name).glob('*.log'))), 12)
        self.assertFalse(self.engine.records)
        self.engine.close()
        seen = []
        def capture(payload, **kw): seen.append(payload); return fake(payload, **kw)
        self.engine = Engine(capture)
        again = self.engine.reinterpret({'execution_id': first['execution_id'], 'question': 'again'})
        self.assertEqual(again['summary_status'], 'completed')
        self.assertFalse(again['command_reexecuted'])
        self.assertIn('ORIGINAL_0', seen[0]['output_fragment'])
        self.assertEqual(seen[0]['question'], 'again')
        self.assertNotIn('segment_analyses', seen[0])

    def test_normal_log_permissions_and_finished_memory_release(self):
        runs = []
        def capture(payload, **kw):
            runs.extend(self.engine.runs.values())
            return fake(payload, **kw)
        self.engine.analyzer = capture
        result = self.engine.execute({'cmd': 'printf OUT; printf ERR >&2', 'login': False})
        path = Path(result['log_file'])
        self.assertEqual(path.name, result['execution_id'] + '.log')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        doc = self.engine.store.load(result['execution_id'])
        self.assertEqual(doc['output'], {'stdout': 'OUT', 'stderr': 'ERR'})
        self.assertNotIn('analysis', doc)
        self.assertFalse(any(runs[0].retained_streams.values()))
        self.assertEqual(runs[0].cmd, '')

    def test_reinterpret_failure_returns_original_and_removes_log(self):
        first = self.engine.execute({'cmd': 'printf ORIGINAL', 'login': False})
        def fail(*args, **kw): raise AnalysisError('synthetic_failure')
        self.engine.analyzer = fail
        result = self.engine.reinterpret({'execution_id': first['execution_id'], 'question': 'again'})
        self.assertEqual(result['raw_output']['stdout'], 'ORIGINAL')
        self.assertFalse(result['log_saved'])
        self.assertFalse(Path(first['log_file']).exists())
        self.assertIn('解析', result['notice'])

    def test_storage_failure_returns_original_without_partial_file(self):
        with patch('log_store.os.replace', side_effect=OSError('synthetic_disk_failure')):
            result = self.engine.execute({'cmd': 'printf ORIGINAL', 'login': False})
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['raw_output']['stdout'], 'ORIGINAL')
        self.assertFalse(result['log_saved'])
        self.assertEqual(result['storage_error'], 'log_write_failed')
        self.assertFalse(list(Path(self.logs.name).iterdir()))

    def test_failed_later_chunk_returns_collected_original_and_never_saves(self):
        first = self.engine.execute({'cmd': 'printf FIRST; sleep 0.7; printf SECOND', 'login': False, 'yield_time_ms': 250})
        self.assertFalse(list(Path(self.logs.name).iterdir()))
        def fail(*args, **kw): raise AnalysisError('synthetic_failure')
        self.engine.analyzer = fail
        last = self.engine.poll({'session_id': first['session_id'], 'yield_time_ms': 1000})
        self.assertEqual(last['raw_output']['stdout'], 'FIRSTSECOND')
        self.assertFalse(last['log_saved'])
        self.assertFalse(self.engine.runs)
        self.assertFalse(list(Path(self.logs.name).iterdir()))

    def test_invalid_id_and_symlink_are_not_read(self):
        result = self.engine.reinterpret({'execution_id': '../outside', 'question': 'again'})
        self.assertEqual(result['reason'], 'log_unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / 'outside'; outside.write_text('PRIVATE')
            self.engine.store.path('a'*32).symlink_to(outside)
            result = self.engine.reinterpret({'execution_id': 'a'*32, 'question': 'again'})
            self.assertEqual(result['reason'], 'log_unavailable')

    def test_binary_failure_returns_exact_bytes_encoded_and_not_stored(self):
        import base64
        result = self.engine.execute({'cmd': "printf '\\377\\000'", 'login': False})
        self.assertEqual(result['raw_output_encoding'], 'base64')
        self.assertEqual(base64.b64decode(result['raw_output']['stdout']), b'\xff\x00')
        self.assertFalse(list(Path(self.logs.name).iterdir()))

    def test_unsupported_fallback_happens_before_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.engine.execute({'cmd': 'touch must-not-exist', 'workdir': tmp, 'tty': True})
            self.assertTrue(result['fallback_required'])
            self.assertFalse(result['command_executed'])
            self.assertFalse(list(Path(tmp).iterdir()))

    def test_polling_does_not_restart_and_analyses_have_no_history(self):
        seen = []
        def capture(payload, **kw): seen.append(payload); return fake(payload, **kw)
        self.engine.analyzer = capture
        result = self.engine.execute({'cmd': 'printf FIRST_MARKER; sleep 0.7; printf SECOND_MARKER', 'login': False, 'yield_time_ms': 250})
        self.assertEqual(result['execution_status'], 'running')
        result = self.engine.poll({'session_id': result['session_id'], 'yield_time_ms': 1000})
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(len(seen), 2)
        self.assertIn('FIRST_MARKER', seen[0]['output_fragment'])
        self.assertNotIn('FIRST_MARKER', seen[1]['output_fragment'])
        self.assertIn('SECOND_MARKER', seen[1]['output_fragment'])

    def test_real_exit_code_not_parser_code(self):
        result = self.engine.execute({'cmd': 'printf "synthetic error" >&2; exit 7', 'login': False})
        self.assertEqual(result['exit_code'], 7)
        self.assertTrue(result['raw_return_complete'])
        self.assertEqual(result['raw_output']['stderr'], 'synthetic error')

    def test_timeout_and_process_group_cleanup(self):
        self.engine.total_timeout = 1
        result = self.engine.execute({'cmd': 'sleep 10', 'login': False})
        self.assertEqual(result['execution_status'], 'timed_out')
        self.assertEqual(result['signal'], 9)
        self.assertFalse(self.engine.runs)

    def test_small_return_budget_does_not_truncate_raw_analysis_input(self):
        seen = []
        def capture(payload, **kw): seen.append(payload); return fake(payload, **kw)
        self.engine.analyzer = capture
        result = self.engine.execute({'cmd': 'printf FULL_INPUT_MARKER', 'login': False, 'max_output_tokens': 1})
        self.assertIn('FULL_INPUT_MARKER', seen[0]['output_fragment'])
        self.assertEqual(result['summary_error'], 'return_budget_exceeded')
        self.assertNotIn('analysis', result)

    def test_segmentation_full_input_and_merge(self):
        self.engine.segment_bytes = 12000
        seen = []
        def capture(payload, **kw): seen.append(payload); return fake(payload, **kw)
        self.engine.analyzer = capture
        result = self.engine.execute({'cmd': "python3 -c 'print(\"X\" * 25000)'", 'login': False})
        self.assertEqual(result['analysis_coverage'], 'segmented_full_current_chunk')
        fragments = [p['output_fragment'] for p in seen if 'output_fragment' in p]
        self.assertEqual(''.join(fragments).count('X'), 25000)
        self.assertTrue(any('segment_analyses' in p for p in seen))

    def test_default_segment_budget_avoids_unnecessary_batch_merges(self):
        seen = []
        def capture(payload, **kw): seen.append(payload); return fake(payload, **kw)
        self.engine.analyzer = capture
        result = self.engine.execute({'cmd': "python3 -c 'print(\"X\" * 41000)'", 'login': False})
        self.assertEqual(result['analysis_calls'], 1)
        self.assertEqual(seen[0]['output_fragment'].count('X'), 41000)
        self.assertTrue(result['log_saved'])

    def test_default_workdir_uses_host_cwd_without_required_argument(self):
        seen = []
        def capture(payload, **kw): seen.append(payload); return fake(payload, **kw)
        self.engine.analyzer = capture
        result = self.engine.execute({'cmd': 'pwd', 'login': False})
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(seen[0]['workdir'], os.getcwd())
        self.assertEqual(result['workdir'], os.getcwd())

    def test_cancel_one_run_does_not_cancel_other_run(self):
        first = self.engine.execute({'cmd': 'sleep 3', 'login': False, 'yield_time_ms': 250})
        second = self.engine.execute({'cmd': 'sleep 3', 'login': False, 'yield_time_ms': 250})
        other = self.engine.runs[second['session_id']].proc
        result = self.engine.poll({'session_id': first['session_id'], 'chars': '\x03'})
        self.assertEqual(result['execution_status'], 'cancelled')
        self.assertIsNone(other.poll())
        self.engine.poll({'session_id': second['session_id'], 'chars': '\x03'})

    def test_analysis_call_limit_is_explicit_not_silent_partial_summary(self):
        self.engine.segment_bytes = 12000
        self.engine.max_analysis_calls = 1
        result = self.engine.execute({'cmd': "python3 -c 'print(\"X\" * 25000)'", 'login': False})
        self.assertEqual(result['summary_status'], 'failed')
        self.assertEqual(result['summary_error'], 'analysis_call_limit')
        self.assertEqual(result['analysis_coverage'], 'none')
        self.assertEqual(result['exit_code'], 0)

    def test_pilot_workspace_scope_falls_back_before_execution(self):
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as outside:
            with patch.dict(os.environ, {'SHELL_SUMMARY_ALLOWED_CWD': allowed}):
                result=self.engine.execute({'cmd':'touch must-not-exist','workdir':outside,'login':False})
            self.assertEqual(result['reason'],'outside_pilot_workspace')
            self.assertFalse(result['command_executed'])
            self.assertFalse(list(Path(outside).iterdir()))

if __name__ == '__main__': unittest.main()
