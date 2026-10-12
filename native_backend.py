"""Fresh official Codex CLI request. No prompt, event or response files."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'properties': dict({k: {'type': 'string'} for k in ['body', 'attention']},
                       contains_sensitive_information={'type': 'boolean'}),
    'required': ['body', 'attention', 'contains_sensitive_information'],
}
INSTRUCTIONS = Path(__file__).with_name('shell-output-prompt.md').read_text(encoding='utf-8')

class AnalysisError(Exception):
    def __init__(self, reason, diagnostics=None):
        super().__init__(reason)
        self.diagnostics = diagnostics or {}

def event_diagnostics(stdout, stderr):
    """Only fixed categories and counters escape; never event text, IDs or paths."""
    counts = {k: 0 for k in ['thread.started', 'turn.started', 'turn.completed',
                             'turn.failed', 'error', 'agent_message', 'reasoning']}
    reconnects = 0
    for line in stdout.splitlines():
        try: event = json.loads(line)
        except ValueError: continue
        kind = event.get('type')
        if kind in counts: counts[kind] += 1
        item = event.get('item', {})
        if kind == 'item.completed' and item.get('type') in ['agent_message', 'reasoning']:
            counts[item['type']] += 1
        if 'Reconnecting' in str(event.get('message', '')): reconnects += 1
    return {'event_counts': counts, 'reconnect_events': reconnects,
            'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr)}

def analyze(payload, model='gpt-5.6-luna', timeout=90, register=lambda p: None):
    native_home = Path(os.environ.get('SHELL_SUMMARY_NATIVE_HOME', os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))))
    with tempfile.TemporaryDirectory(prefix='codex-shell-analyze-') as tmp:
        base = Path(tmp)
        home = base / 'home'; home.mkdir(mode=0o700)
        cwd = base / 'workspace'; cwd.mkdir(mode=0o700)
        # Native CLI authentication only; no credential extraction or private API calls.
        if (native_home / 'auth.json').is_file():
            (home / 'auth.json').symlink_to(native_home / 'auth.json')
        instructions = base / 'instructions.md'; instructions.write_text(INSTRUCTIONS)
        schema = base / 'schema.json'; schema.write_text(json.dumps(SCHEMA))
        disabled = [str(p) for root in [Path.home() / '.agents/skills', Path.home() / '.codex/skills']
                    if root.exists() for p in root.rglob('SKILL.md')]
        disabled += [str(home / 'skills/.system' / n / 'SKILL.md') for n in
                     ['imagegen', 'openai-docs', 'plugin-creator', 'skill-creator', 'skill-installer']]
        config = {
            'model': model, 'model_reasoning_effort': 'low',
            'model_instructions_file': str(instructions), 'project_doc_max_bytes': 0,
            'web_search': 'disabled', 'history.persistence': 'none',
            'memories.use_memories': False, 'memories.generate_memories': False,
            'analytics.enabled': False, 'feedback.enabled': False,
            'agents.enabled': False, 'tools.view_image': False,
        }
        for feature in ['shell_tool', 'unified_exec', 'shell_snapshot', 'apps', 'plugins',
                        'remote_plugin', 'memories', 'multi_agent', 'code_mode_host',
                        'code_mode', 'code_mode_only', 'computer_use', 'browser_use',
                        'image_generation', 'view_image', 'hooks']:
            config['features.' + feature] = False
        args = [os.environ.get('SHELL_SUMMARY_CODEX', shutil.which('codex') or 'codex')]
        for key, value in config.items():
            args += ['-c', key + '=' + json.dumps(value)]
        args += ['-c', 'skills.config=[' + ','.join('{path=' + json.dumps(p) + ',enabled=false}' for p in disabled) + ']']
        args += ['exec', '--ignore-user-config', '--ignore-rules', '--ephemeral',
                 '--skip-git-repo-check', '--sandbox', 'read-only', '--output-schema', str(schema), '--json', '-']
        env = dict(os.environ, CODEX_HOME=str(home))
        for key in ['OPENAI_API_KEY', 'CODEX_API_KEY', 'CODEX_THREAD_ID',
                    'CODEX_INTERNAL_ORIGINATOR_OVERRIDE', 'RUST_LOG', 'OTEL_EXPORTER_OTLP_ENDPOINT']:
            env.pop(key, None)
        proc = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        register(proc)
        try:
            stdout, stderr = proc.communicate(json.dumps(payload, ensure_ascii=False).encode(), timeout=timeout)
        except subprocess.TimeoutExpired:
            import signal
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            stdout, stderr = proc.communicate()
            raise AnalysisError('analysis_timeout', event_diagnostics(stdout, stderr))
        finally:
            register(None)
        if proc.returncode:
            raise AnalysisError('native_cli_failed')
        final = None; usage = None; notices = []
        for line in stdout.splitlines():
            try: event = json.loads(line)
            except ValueError: continue
            item = event.get('item', {})
            if event.get('type') == 'item.completed':
                kind = item.get('type')
                if kind == 'agent_message': final = item.get('text')
                elif kind == 'error': notices.append('native_runtime_notice')
                elif kind not in ['reasoning']:
                    raise AnalysisError('unexpected_tool_event')
            if event.get('type') == 'turn.completed': usage = event.get('usage')
        try:
            result = json.loads(final)
            if (set(result) != set(SCHEMA['required']) or
                type(result['contains_sensitive_information']) is not bool or
                not all(isinstance(result[k], str) for k in ['body', 'attention'])):
                raise ValueError()
        except (ValueError, TypeError):
            raise AnalysisError('invalid_analysis_format')
        # stdout/stderr are never returned or written. Only the selected final answer escapes.
        return {'analysis': result, 'usage': usage, 'model_used': model,
                'runtime_notices': sorted(set(notices))}
