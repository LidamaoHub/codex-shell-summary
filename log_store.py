"""Numbered local logs. Call save only after all captured data passed assessment."""
import json
import os
from pathlib import Path
import re
import tempfile


class LogStore:
    def __init__(self, root):
        self.root = Path(root).expanduser().resolve()

    def path(self, execution_id):
        if not isinstance(execution_id, str) or not re.fullmatch(r'[a-f0-9]{32}', execution_id):
            raise ValueError('invalid_execution_id')
        return self.root / (execution_id + '.log')

    def save(self, execution_id, cmd, cwd, metadata, text):
        target = self.path(execution_id)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        document = dict(format_version=1, execution_id=execution_id, cmd=cmd,
                        workdir=cwd, metadata=metadata, output=text)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.root,
                                             prefix='.write-', suffix='.tmp', delete=False) as file:
                temporary = Path(file.name)
                os.chmod(temporary, 0o600)
                json.dump(document, file, ensure_ascii=False)
                file.flush(); os.fsync(file.fileno())
            os.replace(temporary, target)
            return target
        finally:
            if temporary is not None:
                try: temporary.unlink()
                except FileNotFoundError: pass

    def load(self, execution_id):
        target = self.path(execution_id)
        # Refuse symlinks, including ones supplied by an invalid external ID.
        fd = os.open(target, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'r', encoding='utf-8') as file:
            document = json.load(file)
        if (not isinstance(document, dict) or document.get('format_version') != 1 or document.get('execution_id') != execution_id or
            not isinstance(document.get('cmd'), str) or not isinstance(document.get('workdir'), str) or
            not isinstance(document.get('metadata'), dict) or
            not isinstance(document.get('output'), dict) or
            set(document.get('output', {})) != {'stdout', 'stderr'} or
            not all(isinstance(v, str) for v in document['output'].values())):
            raise ValueError('invalid_log_format')
        required = {'execution_status', 'exit_code', 'signal', 'duration_ms', 'workdir', 'output_complete'}
        if set(document['metadata']) != required:
            raise ValueError('invalid_log_format')
        return document

    def discard(self, execution_id):
        try: self.path(execution_id).unlink()
        except FileNotFoundError: pass
