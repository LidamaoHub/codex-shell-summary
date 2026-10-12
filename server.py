"""Local stdio MCP: assessed ordinary output is persisted; failures/secrets are discarded."""
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid
from native_backend import analyze, AnalysisError
from log_store import LogStore

VERSION = '0.3.0'

EXEC_SCHEMA = {'type': 'object', 'additionalProperties': False, 'required': ['cmd'], 'properties': {
    'cmd': {'type': 'string'}, 'workdir': {'type': 'string'}, 'shell': {'type': 'string'},
    'login': {'type': 'boolean'}, 'tty': {'type': 'boolean'},
    'yield_time_ms': {'type': 'integer'}, 'max_output_tokens': {'type': 'integer'},
    'sandbox_permissions': {'type': 'string', 'enum': ['use_default', 'require_escalated']},
    'justification': {'type': 'string'}, 'prefix_rule': {'type': 'array', 'items': {'type': 'string'}},
}}
STDIN_SCHEMA = {'type': 'object', 'additionalProperties': False, 'required': ['session_id'], 'properties': {
    'session_id': {'type': 'integer'}, 'chars': {'type': 'string'},
    'yield_time_ms': {'type': 'integer'}, 'max_output_tokens': {'type': 'integer'},
}}
REINTERPRET_SCHEMA = {'type': 'object', 'additionalProperties': False, 'required': ['execution_id', 'question'],
    'properties': {'execution_id': {'type': 'string'}, 'question': {'type': 'string'}, 'model': {'type': 'string'}}}
TOOLS = [
    {'name': 'exec_command', 'description': '本机 Shell 摘要隔离，沿用原生入参。普通输出按编号保存日志；敏感或解析失败时返回原文并清除、不保存。解析失败须提醒用户，不重跑命令。未执行且不支持时回退原生。', 'inputSchema': EXEC_SCHEMA},
    {'name': 'write_stdin', 'description': '沿用原生参数，继续等待本插件运行中的非 TTY 命令；支持空输入轮询和 Ctrl-C。不要将本插件会话编号传给原生 Shell。', 'inputSchema': STDIN_SCHEMA},
    {'name': 'reinterpret', 'description': '读取执行编号对应的日志文件进行全新独立解释，不重跑命令。敏感或解析失败时返回原文并删除日志；不存在的日志要求重新调用。普通日志服务重启后仍可读取。', 'inputSchema': REINTERPRET_SCHEMA},
]

def kill_group(proc, sig=signal.SIGTERM):
    if proc is not None:
        try: os.killpg(proc.pid, sig)
        except ProcessLookupError: pass

class Run:
    def __init__(self, args, proc, sid):
        self.id = uuid.uuid4().hex; self.sid = sid; self.proc = proc
        self.cmd = args['cmd']; self.cwd = str(Path(args.get('workdir', os.getcwd())).resolve())
        self.started = time.monotonic(); self.streams = {'stdout': bytearray(), 'stderr': bytearray()}
        self.total = 0; self.complete = True; self.reason = None
        self.lock = threading.Lock(); self.call_lock = threading.Lock(); self.finished = threading.Event()
        self.parser = None; self.default_budget = args.get('max_output_tokens', 10000)
        self.retained_streams = {'stdout': bytearray(), 'stderr': bytearray()}
        self.sensitive = False; self.discard_reason = None

class Engine:
    def __init__(self, analyzer=analyze):
        self.analyzer = analyzer; self.runs = {}; self.records = {}; self.lock = threading.Lock(); self.next_sid = 1
        self.context = threading.local()
        self.closing = threading.Event()
        self.active_parsers = {}
        self.reinterpret_lock = threading.Lock()
        self.store = LogStore(os.environ.get('SHELL_SUMMARY_LOG_DIR', str(Path.home() / 'Library/Logs/CodexShell')))
        self.model = os.environ.get('SHELL_SUMMARY_MODEL', 'gpt-5.6-luna')
        self.max_bytes = int(os.environ.get('SHELL_SUMMARY_MEMORY_BYTES', 8388608))
        self.total_timeout = int(os.environ.get('SHELL_SUMMARY_COMMAND_SECONDS', 120))
        self.max_analysis_calls = int(os.environ.get('SHELL_SUMMARY_ANALYSIS_CALLS', 32))
        self.segment_bytes = int(os.environ.get('SHELL_SUMMARY_SEGMENT_BYTES', 60000))
        if self.segment_bytes <= 0: raise ValueError('invalid_segment_bytes')

    def fallback(self, reason):
        return {'execution_status': 'not_started', 'command_executed': False,
                'fallback_required': True, 'fallback_tool': 'native.exec_command', 'reason': reason}

    def execute(self, args):
        if self.closing.is_set(): return self.fallback('service_closing')
        # This opt-in is for the verified unrestricted local profile only. No sandbox imitation.
        if os.environ.get('SHELL_SUMMARY_EXECUTION_PROFILE') != 'unrestricted-local':
            return self.fallback('execution_profile_not_confirmed')
        allowed_cwd = os.environ.get('SHELL_SUMMARY_ALLOWED_CWD')
        if allowed_cwd:
            requested = Path(args.get('workdir', os.getcwd())).resolve()
            root = Path(allowed_cwd).resolve()
            if requested != root and root not in requested.parents:
                return self.fallback('outside_pilot_workspace')
        if args.get('tty'):
            return self.fallback('tty_not_supported')
        if args.get('sandbox_permissions', 'use_default') != 'use_default' or 'prefix_rule' in args or 'justification' in args:
            return self.fallback('native_approval_required')
        try: tokens = shlex.split(args['cmd'])
        except ValueError: return self.fallback('complex_shell_syntax_requires_native')
        if any(t in ['sudo', 'ssh', 'sftp', 'vim', 'vi', 'nano', 'less', 'more', 'top', 'htop', 'tmux', 'screen', 'read'] for t in tokens):
            return self.fallback('known_interactive_command')
        if re.search(r'\b(npm|pnpm|yarn|bun)\s+(run\s+)?(dev|start)\b|\btail\s+.*(?:-f|--follow)|\bhttp\.server\b', args['cmd']):
            return self.fallback('known_persistent_command')
        shell = args.get('shell', os.environ.get('SHELL', '/bin/zsh'))
        cwd = args.get('workdir', os.getcwd())
        if not Path(shell).is_file() or not os.access(shell, os.X_OK) or not Path(cwd).is_dir():
            return self.fallback('shell_or_workdir_unavailable')
        with self.lock:
            if len(self.runs) >= 2: return self.fallback('concurrency_limit')
            sid = self.next_sid; self.next_sid += 1
            argv = [shell] + (['-l'] if args.get('login', True) else []) + ['-c', args['cmd']]
            proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            run = Run(args, proc, sid); self.runs[sid] = run
            if hasattr(self.context, 'request'): self.context.request['run'] = run
        readers = []
        for stream in ['stdout', 'stderr']:
            t = threading.Thread(target=self._read, args=(run, stream), daemon=True); t.start(); readers.append(t)
        threading.Thread(target=self._wait, args=(run, readers), daemon=True).start()
        return self._snapshot(run, args.get('yield_time_ms', 10000), run.default_budget)

    def _read(self, run, stream):
        pipe = getattr(run.proc, stream)
        while True:
            chunk = pipe.read1(65536)
            if not chunk: break
            with run.lock:
                used = run.total
                remaining = max(0, self.max_bytes - used)
                run.streams[stream].extend(chunk[:remaining]); run.total += len(chunk)
                if len(chunk) > remaining:
                    run.complete = False; run.reason = 'memory_limit'
                    kill_group(run.proc, signal.SIGKILL)
        pipe.close()

    def _wait(self, run, readers):
        try: run.proc.wait(timeout=self.total_timeout)
        except subprocess.TimeoutExpired:
            run.reason = 'execution_timeout'; kill_group(run.proc, signal.SIGKILL); run.proc.wait()
        for t in readers: t.join(timeout=2)
        if any(t.is_alive() for t in readers):
            run.complete = False; run.reason = 'background_descendants'; kill_group(run.proc, signal.SIGKILL)
            for t in readers: t.join(timeout=2)
        run.finished.set()

    def poll(self, args):
        run = self.runs.get(args['session_id'])
        if run is None: return {'execution_status': 'unknown_session', 'command_executed': False}
        if hasattr(self.context, 'request'): self.context.request['run'] = run
        chars = args.get('chars', '')
        if chars not in ['', '\x03']:
            # The command has already started: never recommend fallback/re-execution here.
            return {'execution_id': run.id, 'execution_status': 'running',
                    'input_status': 'unsupported', 'fallback_required': False,
                    'reason': 'non_tty_input_not_supported', 'command_executed': True}
        if chars == '\x03': run.reason = 'cancelled'; kill_group(run.proc, signal.SIGKILL)
        return self._snapshot(run, args.get('yield_time_ms', 250 if chars else 5000), args.get('max_output_tokens', run.default_budget), poll=True)

    def _remember_discard(self, execution_id, reason):
        # Content-free recent status only. Its size never blocks command execution.
        with self.lock:
            self.records[execution_id] = reason
            while len(self.records) > 256:
                self.records.pop(next(iter(self.records)))

    def _bypass(self, run, raw, result, budget, done):
        with run.lock:
            original = {k: bytes(run.retained_streams[k]) + raw[k] for k in raw}
            for value in run.retained_streams.values(): value.clear()
        run.cmd = ''
        self._return_original(original, result, budget, sensitive=run.sensitive,
                              entire=done and run.complete and run.total == sum(map(len, original.values())))
        if not run.sensitive:
            result['summary_error'] = run.discard_reason
            result['notice'] = '解析出问题，以下为原始输出；未保存日志。请告知用户，不要自动重跑命令。'

    def _snapshot(self, run, wait_ms, budget, poll=False):
        with run.call_lock:
            effective = max(250, min(wait_ms, 300000 if poll else 30000))
            run.finished.wait(effective / 1000)
            done = run.finished.is_set()
            with run.lock:
                raw = {k: bytes(v) for k, v in run.streams.items()}
                for v in run.streams.values(): v.clear()
            code = run.proc.returncode if done else None
            status = 'running' if not done else ('cancelled' if run.reason == 'cancelled' else
                     'timed_out' if run.reason == 'execution_timeout' else 'terminated' if code is not None and code < 0 else 'completed')
            result = {'execution_id': run.id, 'execution_status': status, 'exit_code': code if code is None or code >= 0 else None,
                      'workdir': run.cwd, 'signal': -code if code is not None and code < 0 else None,
                      'duration_ms': round((time.monotonic() - run.started) * 1000),
                      'command_executed': True, 'fallback_required': False, 'output_complete': done and run.complete,
                      'raw_output_retained': False, 'raw_return_complete': False, 'log_saved': False,
                      'analysis_coverage': 'partial' if not done or not run.complete else 'full_current_chunk',
                      'coverage_scope': 'output_since_last_plugin_call', 'reason': run.reason}
            if not done: result['session_id'] = run.sid
            try:
                if run.discard_reason:
                    self._bypass(run, raw, result, budget, done)
                else:
                    if run.reason == 'cancelled': raise AnalysisError('request_cancelled')
                    text = {k: v.decode('utf-8', errors='strict') for k, v in raw.items()}
                    if any('\x00' in v for v in text.values()): raise UnicodeError()
                    self._summarize(run, text, result, budget)
                    if result.get('contains_sensitive_information'):
                        run.sensitive = True; run.discard_reason = 'sensitive_output_discarded'
                    elif result.get('summary_status') != 'completed':
                        run.discard_reason = result.get('summary_error', 'analysis_failed')
                    if run.discard_reason:
                        self._bypass(run, raw, result, budget, done)
                    elif done and code is not None and code > 0 and run.total == sum(map(len, raw.values())) <= 2048:
                        remaining = budget * 4 - len(json.dumps(result['analysis'], ensure_ascii=False).encode())
                        if len(json.dumps(text, ensure_ascii=False).encode()) <= remaining:
                            result['raw_output'] = text; result['raw_return_complete'] = True
            except Exception as exc:
                if isinstance(exc, AnalysisError) and exc.diagnostics:
                    result['analysis_diagnostics'] = exc.diagnostics
                run.discard_reason = ('binary_or_non_utf8_output' if isinstance(exc, UnicodeError) else
                                      str(exc) if isinstance(exc, AnalysisError) else 'analysis_failed')
                result['analysis_coverage'] = 'none'
                self._bypass(run, raw, result, budget, done)
            finally:
                with run.lock:
                    if not run.discard_reason:
                        for stream, value in raw.items(): run.retained_streams[stream].extend(value)
                    else:
                        for value in run.retained_streams.values(): value.clear()
                raw.clear()
                if done:
                    metadata = {k: result[k] for k in ['execution_status', 'exit_code', 'signal', 'duration_ms', 'workdir', 'output_complete']}
                    if not run.discard_reason:
                        with run.lock:
                            original = {k: bytes(v) for k, v in run.retained_streams.items()}
                        text = {}
                        try:
                            text = {k: v.decode('utf-8') for k, v in original.items()}
                            path = self.store.save(run.id, run.cmd, run.cwd, metadata, text)
                            result.update(log_saved=True, log_file=str(path))
                        except Exception:
                            run.discard_reason = 'log_write_failed'
                            self._return_original(original, result, budget, entire=run.complete)
                            result.update(summary_error='log_write_failed', storage_error='log_write_failed',
                                          notice='日志保存失败，以下为原始输出；请告知用户，不要自动重跑命令。')
                        finally:
                            original.clear(); text.clear()
                            with run.lock:
                                for value in run.retained_streams.values(): value.clear()
                    if run.discard_reason:
                        self._remember_discard(run.id, 'sensitive_output_discarded' if run.sensitive else 'analysis_failed_output_discarded')
                    self.runs.pop(run.sid, None)
                    run.cmd = ''; run.cwd = ''
                result['raw_output_retained'] = result['log_saved'] or (not done and not run.discard_reason)
                result['raw_output_in_memory'] = not done and not run.discard_reason
                result['storage_status'] = 'saved' if result['log_saved'] else 'discarded' if run.discard_reason else 'pending_assessment'
                result['sensitivity_status'] = 'detected' if run.sensitive else 'unknown' if run.discard_reason else 'not_detected'
                result['can_reinterpret'] = result['log_saved']
            return result

    def _summarize(self, run, text, result, budget, question=None, model=None):
        # Conservative bound: UTF-8 bytes upper-bound ordinary tokenizer token count.
        limit = self.segment_bytes
        source = json.dumps(text, ensure_ascii=False)
        chunks = []; current = ''; size = 0
        for char in source:
            n = len(char.encode())
            if size + n > limit: chunks.append(current); current = ''; size = 0
            current += char; size += n
        chunks.append(current)
        if 2 * len(chunks) - 1 > self.max_analysis_calls:
            raise AnalysisError('analysis_call_limit')
        outputs = []; usages = []
        chosen_model = model or self.model
        def register(proc):
            run.parser = proc
            with self.lock:
                if proc is None: self.active_parsers.pop(id(run), None)
                else: self.active_parsers[id(run)] = proc
            state = getattr(self.context, 'request', {})
            state['parser'] = proc
            if state.get('cancelled') or self.closing.is_set(): kill_group(proc, signal.SIGKILL)
        for i, chunk in enumerate(chunks):
            payload = {'cmd': run.cmd, 'workdir': run.cwd, 'execution_status': result['execution_status'],
                       'exit_code': result['exit_code'], 'signal': result['signal'],
                       'analysis_coverage': result['analysis_coverage'], 'output_fragment': chunk,
                       'fragment_index': i + 1, 'fragment_count': len(chunks),
                       'return_budget_tokens': budget, 'output_complete': result['output_complete'],
                       'instruction': 'Keep the answer within budget; preserve exact content needed to work.'}
            if question is not None: payload['question'] = question
            response = self.analyzer(payload, model=chosen_model, register=register)
            outputs.append(response['analysis']); usages.append(response.get('usage'))
            if response['analysis'].get('contains_sensitive_information') is True:
                result.update(contains_sensitive_information=True, model_used=chosen_model,
                              usage=usages, analysis_calls=len(usages))
                result['analysis_coverage'] = 'partial' if len(chunks) > 1 else result['analysis_coverage']
                return
        if len(outputs) > 1:
            # Group bounded summaries recursively. Each merge is a new independent request.
            while len(outputs) > 1:
                merged = []
                for i in range(0, len(outputs), 2):
                    group = outputs[i:i + 2]
                    if len(group) == 1: merged.extend(group); continue
                    payload = {'cmd': run.cmd, 'workdir': run.cwd, 'execution_status': result['execution_status'],
                               'exit_code': result['exit_code'], 'signal': result['signal'],
                               'output_complete': result['output_complete'], 'analysis_coverage': result['analysis_coverage'],
                               'segment_analyses': group,
                               'instruction': 'Merge conclusions and attention items. For queries, preserve every supplied filename/match/code line in order; never replace distinct rows by ranges, counts or examples. Deduplicate only irrelevant execution noise. No evidence section.',
                               'return_budget_tokens': budget}
                    if len(json.dumps(payload).encode()) > 60000: raise AnalysisError('merge_budget_exceeded')
                    if question is not None: payload['question'] = question
                    response = self.analyzer(payload, model=chosen_model, register=register)
                    merged.append(response['analysis']); usages.append(response.get('usage'))
                    if response['analysis'].get('contains_sensitive_information') is True:
                        result.update(contains_sensitive_information=True, model_used=chosen_model,
                                      usage=usages, analysis_calls=len(usages))
                        return
                outputs = merged
            result['analysis_coverage'] = 'segmented_full_current_chunk' if result['output_complete'] else 'segmented_partial'
        selected = {k:v for k,v in outputs[0].items() if k != 'contains_sensitive_information'}
        result.update(summary_status='completed', model_used=chosen_model, analysis=selected, usage=usages,
                      contains_sensitive_information=False,
                      analysis_calls=len(usages))
        # Match the native tool's observed approximate 4 UTF-8 bytes/token budget.
        # Never clip requested exact content or truncate analyzer input based on this budget.
        encoded = json.dumps(result['analysis'], ensure_ascii=False).encode()
        if len(encoded) > budget * 4:
            # Never silently clip requested content or claim the result is complete.
            result.pop('analysis'); result['summary_status'] = 'failed'
            result['summary_error'] = 'return_budget_exceeded'; result['rerun_required'] = False

    def _return_original(self, raw, result, budget, sensitive=False, entire=False):
        # Transport-only copy: no file and no retained in-process record.
        try:
            text = {k: v.decode('utf-8', errors='strict') for k, v in raw.items()}
            encoding = 'utf-8'
        except UnicodeError:
            text = {k: base64.b64encode(v).decode('ascii') for k, v in raw.items()}
            encoding = 'base64'
        sizes = {k: len(v.encode()) for k, v in text.items()}
        remaining = max(0, budget) * 4; returned = {}; truncated = False
        for index, stream in enumerate(['stdout', 'stderr']):
            available = remaining if index else max(0, remaining - min(sizes['stderr'], remaining // 2))
            data = text[stream].encode(); part = data[:available].decode('utf-8', errors='ignore')
            if encoding == 'base64': part = part[:len(part) // 4 * 4]
            returned[stream] = part; remaining -= len(part.encode())
            truncated |= len(part.encode()) != len(data)
        result.pop('analysis', None)
        if sensitive: result.pop('summary_error', None)
        result.update(summary_status='bypassed_sensitive' if sensitive else 'failed',
                      contains_sensitive_information=sensitive, raw_output=returned, raw_output_encoding=encoding,
                      raw_return_complete=entire and not truncated, raw_return_truncated=truncated,
                      raw_return_scope='all_available_output', raw_output_retained=False,
                      raw_output_in_memory=False, log_saved=False, can_reinterpret=False, rerun_required=True)

    def reinterpret(self, args):
        execution_id = args['execution_id']
        state = getattr(self.context, 'request', {})
        with self.reinterpret_lock:
            if any(r.id == execution_id for r in self.runs.values()):
                return {'execution_id': execution_id, 'summary_status': 'unavailable',
                        'reason': 'execution_still_running', 'rerun_required': False, 'command_reexecuted': False}
            if execution_id in self.records:
                return {'execution_id': execution_id, 'summary_status': 'unavailable',
                        'reason': self.records[execution_id], 'rerun_required': True, 'command_reexecuted': False}
            try:
                document = self.store.load(execution_id)
            except FileNotFoundError:
                return {'execution_id': execution_id, 'summary_status': 'unavailable',
                        'reason': 'log_not_found', 'rerun_required': True, 'command_reexecuted': False}
            except (ValueError, OSError, TypeError):
                return {'execution_id': execution_id, 'summary_status': 'unavailable',
                        'reason': 'log_unavailable', 'rerun_required': True, 'command_reexecuted': False}
            from types import SimpleNamespace
            record = SimpleNamespace(cmd=document['cmd'], cwd=document['workdir'], parser=None)
            state['record'] = record
            text = document['output']; raw = {k: v.encode('utf-8') for k, v in text.items()}
            result = dict(document['metadata'], execution_id=execution_id, interpretation_id=uuid.uuid4().hex,
                          command_reexecuted=False, analysis_coverage='full_logged_output' if document['metadata']['output_complete'] else 'partial',
                          raw_return_complete=False, rerun_required=False, log_saved=True,
                          log_file=str(self.store.path(execution_id)), raw_output_in_memory=False)
            discard = None; sensitive = False
            try:
                if state.get('cancelled'): raise AnalysisError('request_cancelled')
                self._summarize(record, text, result, 10000, question=args['question'], model=args.get('model'))
                sensitive = result.get('contains_sensitive_information') is True
                if sensitive: discard = 'sensitive_output_discarded'
                elif result.get('summary_status') != 'completed': discard = 'analysis_failed_output_discarded'
            except Exception as exc:
                discard = 'analysis_failed_output_discarded'
                if isinstance(exc, AnalysisError) and exc.diagnostics:
                    result['analysis_diagnostics'] = exc.diagnostics
                result.update(summary_error=str(exc) if isinstance(exc, AnalysisError) else 'analysis_failed', analysis_coverage='none')
            finally:
                if discard:
                    try:
                        self.store.discard(execution_id)
                        self._remember_discard(execution_id, discard)
                    except OSError:
                        result['storage_error'] = 'log_removal_failed'
                    self._return_original(raw, result, 10000, sensitive=sensitive, entire=document['metadata']['output_complete'])
                    result.pop('log_file', None)
                    if 'storage_error' in result:
                        result.update(log_saved=True, raw_output_retained=True)
                    if not sensitive:
                        result['notice'] = '解析出问题，以下为原始输出；已要求删除日志。请告知用户，不要自动重跑命令。'
                else:
                    result['raw_output_retained'] = True
                result['sensitivity_status'] = 'detected' if sensitive else 'unknown' if discard else 'not_detected'
                result['storage_status'] = 'removal_failed' if 'storage_error' in result else 'discarded' if discard else 'saved'
                result['can_reinterpret'] = not discard
                record.cmd = ''; record.cwd = ''; state.pop('record', None)
                text.clear(); raw.clear(); document.clear()
            return result

    def close(self):
        self.closing.set()
        for run in list(self.runs.values()):
            run.discard_reason = 'request_cancelled'
            kill_group(run.parser, signal.SIGKILL); kill_group(run.proc, signal.SIGKILL)
            for value in run.retained_streams.values(): value.clear()
            for value in run.streams.values(): value.clear()
            run.cmd = ''
        for parser in list(self.active_parsers.values()): kill_group(parser, signal.SIGKILL)
        self.runs.clear(); self.records.clear()

def validate(args, schema):
    if not isinstance(args, dict) or set(args) - set(schema['properties']) or set(schema['required']) - set(args):
        raise ValueError('invalid_arguments')
    types = {'string': str, 'integer': int, 'boolean': bool, 'array': list}
    for k, value in args.items():
        rule = schema['properties'][k]
        if not isinstance(value, types[rule['type']]) or (rule['type'] == 'integer' and isinstance(value, bool)):
            raise ValueError('invalid_arguments')
        if 'enum' in rule and value not in rule['enum']: raise ValueError('invalid_arguments')
        if rule['type'] == 'array' and not all(isinstance(v, str) for v in value): raise ValueError('invalid_arguments')
        if k in ['yield_time_ms', 'max_output_tokens'] and value < 0: raise ValueError('invalid_arguments')

def main():
    engine = Engine(); write_lock = threading.Lock(); jobs = {}
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    def send(message):
        with write_lock:
            sys.stdout.write(json.dumps(message, ensure_ascii=False) + '\n'); sys.stdout.flush()
    def call(message, state):
        engine.context.request = state
        params = message.get('params', {}); name = params.get('name'); args = params.get('arguments', {})
        try:
            tool = next(t for t in TOOLS if t['name'] == name); validate(args, tool['inputSchema'])
            data = {'exec_command': engine.execute, 'write_stdin': engine.poll, 'reinterpret': engine.reinterpret}[name](args)
            send({'jsonrpc': '2.0', 'id': message['id'], 'result': {
                'content': [{'type': 'text', 'text': json.dumps(data, ensure_ascii=False)}], 'structuredContent': data}})
        except Exception:
            send({'jsonrpc': '2.0', 'id': message['id'], 'result': {'isError': True,
                  'content': [{'type': 'text', 'text': 'invalid_arguments_or_internal_error'}]}})
        finally: jobs.pop(message['id'], None)
    def stop(signum, frame):
        engine.close()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    try:
        for line in sys.stdin:
            try: message = json.loads(line)
            except ValueError: continue
            method = message.get('method')
            if method == 'initialize':
                send({'jsonrpc': '2.0', 'id': message['id'], 'result': {
                    'protocolVersion': message.get('params', {}).get('protocolVersion', '2024-11-05'),
                    'capabilities': {'tools': {'listChanged': False}},
                    'serverInfo': {'name': 'shell-summary-isolation', 'version': VERSION}}})
            elif method == 'tools/list': send({'jsonrpc': '2.0', 'id': message['id'], 'result': {'tools': TOOLS}})
            elif method == 'tools/call':
                state = {}; jobs[message['id']] = state; state['future'] = pool.submit(call, message, state)
            elif method == 'ping': send({'jsonrpc': '2.0', 'id': message['id'], 'result': {}})
            elif method == 'notifications/cancelled':
                state = jobs.get(message.get('params', {}).get('requestId'), {})
                state['cancelled']=True;kill_group(state.get('parser'),signal.SIGKILL)
                run = state.get('run')
                if run is not None:
                    run.reason = 'cancelled'; kill_group(run.parser, signal.SIGKILL); kill_group(run.proc, signal.SIGKILL)
            elif 'id' in message: send({'jsonrpc': '2.0', 'id': message['id'], 'error': {'code': -32601, 'message': 'Method not found'}})
    finally:
        engine.close(); pool.shutdown(wait=True)

if __name__ == '__main__': main()
