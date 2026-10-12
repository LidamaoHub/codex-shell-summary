"""Render a machine-local Codex compatibility package; never installs or changes config."""
import argparse
import json
import os
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def build(output, codex_home, execution=False, allowed_cwd=None):
    marketplace_name = 'shell-summary-local'
    name = 'shell-summary-isolation'; version = '0.3.0'
    package = output / 'plugins' / name
    package.mkdir(parents=True, exist_ok=True)
    for file in ['server.py', 'native_backend.py', 'log_store.py', 'shell-output-prompt.md']:
        shutil.copyfile(ROOT / file, package / file)
    shutil.copytree(ROOT / 'skills', package / 'skills', dirs_exist_ok=True)
    manifest = {'name': name, 'version': version,
                'description': '本机 Shell 输出由独立 Codex 解析；普通日志按编号保存，敏感或解析失败不保存。',
                'skills': './skills/', 'mcpServers': './.mcp.json',
                'interface': {'displayName': 'Shell摘要隔离', 'shortDescription': '本机执行与独立 Codex 摘要'}}
    (package / '.codex-plugin').mkdir(exist_ok=True)
    (package / '.codex-plugin/plugin.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    # Variable-based MCP argv failed in the local 0.147.0 probes.
    # Render the verified installed cache path explicitly for this machine.
    installed = codex_home / 'plugins/cache' / marketplace_name / name / version
    env = {'SHELL_SUMMARY_MODEL': 'gpt-5.6-luna', 'SHELL_SUMMARY_NATIVE_HOME': str(codex_home),
           'SHELL_SUMMARY_CODEX': shutil.which('codex') or 'codex'}
    if execution: env['SHELL_SUMMARY_EXECUTION_PROFILE'] = 'unrestricted-local'
    if allowed_cwd: env['SHELL_SUMMARY_ALLOWED_CWD'] = str(allowed_cwd)
    mcp = {'mcpServers': {name: {'type': 'stdio', 'command': shutil.which('python3') or 'python3',
                               'args': [str(installed / 'server.py')], 'env': env}}}
    (package / '.mcp.json').write_text(json.dumps(mcp, ensure_ascii=False, indent=2))
    catalog = output / '.agents/plugins/marketplace.json'; catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text(json.dumps({'name': marketplace_name,
        'interface': {'displayName': 'Shell摘要隔离 · 本地'},
        'plugins': [{'name': name, 'source': {'source': 'local', 'path': './plugins/' + name},
                     'policy': {'installation': 'AVAILABLE', 'authentication': 'ON_INSTALL'}, 'category': 'Productivity'}]},
        ensure_ascii=False, indent=2))
    archive = output / 'shell-summary-isolation-0.3.0-local.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for file in sorted(package.rglob('*')):
            if file.is_file() and '__pycache__' not in file.parts:
                z.write(file, Path(name) / file.relative_to(package))
    return {'marketplace_root': str(output), 'plugin_root': str(package), 'archive': str(archive),
            'installed_entry': str(installed / 'server.py'), 'execution_enabled_in_candidate': execution,
            'global_config_modified': False}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=ROOT / 'local-package')
    parser.add_argument('--codex-home', type=Path, default=Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))))
    parser.add_argument('--enable-execution', action='store_true', help='Render an opt-in candidate; does not install it.')
    parser.add_argument('--allowed-cwd', type=Path, default=ROOT.parent, help='Pilot execution cwd scope; not a filesystem sandbox.')
    args = parser.parse_args()
    print(json.dumps(build(args.out.resolve(), args.codex_home.resolve(), args.enable_execution, args.allowed_cwd.resolve()), ensure_ascii=False, indent=2))
