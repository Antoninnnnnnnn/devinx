"""Read-only local diagnostics: no inference, credentials, log or prompt export."""
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import sys
import urllib.request

from runtime_support import CONFIG_FIELDS, build_id


def read_service(host, port):
    # A loopback readiness check must not travel through a shell's HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f'http://{host}:{port}/api/hello', timeout=3) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            return 'invalid_response', {}
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get('service') != 'devinx':
            return 'foreign', {}
        public = {key: data[key] for key in ('service', 'build', 'pid', 'port', 'inflight')
                  if key in data and isinstance(data[key], (str, int, float, type(None)))}
        config = data.get('configuration')
        if isinstance(config, dict):
            public['configuration'] = {key: value for key, value in config.items()
                                       if key in CONFIG_FIELDS and isinstance(
                                           value, (int, float, bool, type(None)))}
        return 'running', public
    except (OSError, ValueError):
        return 'unavailable', {}


def collect(mode, args, launcher):
    use_devin, use_orch, use_codex, _ = launcher.split_args(args)
    state, service = read_service(launcher.HOST, launcher.PORT)
    expected = build_id(launcher.HERE)
    problems = []
    if state == 'running' and service.get('build') != expected:
        problems.append('The service is running a different build.')
    requested = {}
    for name in CONFIG_FIELDS:
        if name not in os.environ:
            continue
        actual = service.get('configuration', {}).get(name, 'unknown')
        raw = os.environ[name]
        try:
            wanted = raw == '1' if name == 'DEVINX_COMPACT_STRICT' else float(raw)
            if name == 'DEVINX_RELAY_READ_TIMEOUT' and wanted == 0:
                wanted = None
        except ValueError:
            problems.append(f'{name} is invalid.')
            continue
        requested[name] = wanted
        if actual == 'unknown':
            problems.append(f'The running value of {name} is unavailable.')
        elif wanted != actual:
            problems.append(f'{name} differs from the running service; session flags do not reconfigure a daemon.')
    report = {'state': state, 'expected_build': expected, 'service': service,
              'requested_configuration': requested, 'warnings': problems}
    if mode != '--status':
        versions = {}
        for package in ('requests', 'protobuf'):
            try:
                versions[package] = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:
                versions[package] = None
        report['python'] = sys.version.split()[0]
        report['dependencies'] = versions
        report['clients_available'] = {name: shutil.which(name) is not None
                                       for name in ('claude', 'codex')}
        report['descriptor_files'] = len(list((Path(launcher.HERE) / 'descriptors').glob('*.fdp')))
    if mode == '--explain':
        report['launch'] = {
            'client': 'codex' if use_codex else 'claude',
            'proxy_enabled': use_devin,
            'orchestrator_enabled': use_orch,
            'agents': [name for name, _ in launcher.CODEX_ROLES] if use_codex and use_orch
                      else list(launcher.packaged_agents()) if use_devin and not use_codex else [],
            'permissions': 'No permission bypass is added by devinx.',
        }
    return report


def main(mode, args, launcher):
    args = list(args)
    as_json = '--json' in args
    if as_json:
        args.remove('--json')
    report = collect(mode, args, launcher)
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"devinx: {report['state']}; local build {report['expected_build']}")
        for key, value in report.items():
            if key not in ('state', 'expected_build', 'warnings'):
                print(f'{key}: {json.dumps(value, sort_keys=True)}')
        for warning in report['warnings']:
            print(f'warning: {warning}')
    return 0 if report['state'] == 'running' else 1
