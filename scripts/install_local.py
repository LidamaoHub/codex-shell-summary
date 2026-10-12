"""Generate a machine-local source, then optionally install it with Codex CLI."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from build_local_plugin import build

def plan(home, workspace):
    source = home / 'plugin-sources/codex-shell-summary'
    codex = shutil.which('codex')
    if not codex:
        raise ValueError('Codex CLI was not found on PATH; install it before continuing.')
    if not workspace.is_dir():
        raise ValueError('Workspace must be an existing directory.')
    return {'marketplace_root': str(source), 'workspace': str(workspace),
            'codex_home': str(home), 'execution_profile': 'unrestricted-local',
            'model': 'gpt-5.6-luna', 'version': '0.3.0',
            'commands': [[codex, 'plugin', 'marketplace', 'add', str(source)],
                         [codex, 'plugin', 'add', 'shell-summary-isolation@shell-summary-local']]}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True,
                        help='Existing directory whose commands may execute, including descendants.')
    parser.add_argument('--codex-home', type=Path,
                        default=Path(os.environ.get('CODEX_HOME', str(Path.home()/'.codex'))))
    parser.add_argument('--apply', action='store_true',
                        help='Explicitly authorize generation, plugin registration and installation.')
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('This experimental release currently supports macOS only.')
    if sys.version_info < (3, 9):
        parser.error('Python 3.9 or newer is required.')
    home = args.codex_home.expanduser().resolve()
    workspace = args.workspace.expanduser().resolve()
    try: proposed = plan(home, workspace)
    except ValueError as exc: parser.error(str(exc))
    print(json.dumps(dict(proposed, applied=args.apply), ensure_ascii=False, indent=2))
    if not args.apply:
        print('Preview only. Review the paths and local execution profile, then add --apply.')
        return
    source = Path(proposed['marketplace_root'])
    build(source, home, execution=True, allowed_cwd=workspace)
    env = dict(os.environ, CODEX_HOME=str(home))
    for command in proposed['commands']:
        subprocess.run(command, env=env, check=True)
    print('Installed. Restart Codex and start a new session. No service needs manual startup.')

if __name__ == '__main__':
    main()
