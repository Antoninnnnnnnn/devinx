"""Read-only local diagnostics: no inference, credentials, log or prompt export."""
import http.client
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
    # Something is listening but does not speak HTTP at all (a non-HTTP
    # process squatting the port, a truncated response): this must be
    # reported as an ordinary diagnostic state, not a crash with a traceback.
    except (OSError, ValueError, http.client.HTTPException):
        return 'unavailable', {}


def parse_config_value(name, raw):
    """Parse one DEVINX_* runtime setting the way the service itself does.

    Shared so a value is judged the same way whether it is being validated
    before the service starts (launcher.py), or compared against what an
    already-running service reports (below, and --status/--explain). Raises
    ValueError on a value the service would also reject.
    """
    if name == 'DEVINX_COMPACT_STRICT':
        return raw == '1'
    value = float(raw)
    if name == 'DEVINX_RELAY_READ_TIMEOUT' and value == 0:
        return None
    return value


def configuration_mismatches(env, service_config):
    """Requested DEVINX_* settings that differ from a running service's own.

    Session flags never reconfigure a daemon that is already up - changing a
    variable in a new terminal silently does nothing unless this is said out
    loud. `service_config` is the 'configuration' object from /api/hello (or
    {} if unknown); an unparsable request is reported too, since the service
    will not have honoured it however it started.
    """
    warnings = []
    for name in CONFIG_FIELDS:
        if name not in env:
            continue
        actual = service_config.get(name, 'unknown') if service_config else 'unknown'
        try:
            wanted = parse_config_value(name, env[name])
        except ValueError:
            warnings.append(f'{name} is invalid.')
            continue
        if actual == 'unknown':
            warnings.append(f'The running value of {name} is unavailable.')
        elif wanted != actual:
            warnings.append(
                f'{name} differs from the running service; session flags do not reconfigure a daemon.')
    # The two switches that outlive the shell that set them. Reported as
    # booleans only; a service too old to report them says nothing here.
    for name in ('DEVINX_DUMP', 'DEVINX_ALLOW_BROWSER'):
        running = (service_config or {}).get(name)
        if not isinstance(running, bool):
            continue
        wanted = bool(env.get(name)) if name == 'DEVINX_DUMP' else env.get(name) == '1'
        if running and not wanted:
            warnings.append(
                f'{name} is active in the running service (inherited from the shell that started it); '
                'restart the service to turn it off.')
        elif wanted and not running:
            warnings.append(f'{name} is requested but the running service does not have it.')
    return warnings


def requested_configuration(env):
    """Parsed DEVINX_* settings the given environment is asking for.

    An entry that fails to parse is left out here; configuration_mismatches()
    reports that separately, so a bad value is never silently reported as
    some other, arbitrary parsed value.
    """
    out = {}
    for name in CONFIG_FIELDS:
        if name not in env:
            continue
        try:
            out[name] = parse_config_value(name, env[name])
        except ValueError:
            continue
    return out


def collect(mode, args, launcher):
    use_devin, use_orch, use_codex, _ = launcher.split_args(args)
    state, service = read_service(launcher.HOST, launcher.PORT)
    expected = build_id(launcher.HERE)
    problems = []
    if state == 'running' and service.get('build') != expected:
        problems.append('The service is running a different build.')
    requested = requested_configuration(os.environ)
    problems.extend(configuration_mismatches(os.environ, service.get('configuration', {})))
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
    if mode == '--explain':
        # --explain answers "what would this command line do", which it can
        # do whether or not a service happens to be running right now; the
        # service being down is not a failure of the explanation.
        return 0
    return 0 if report['state'] == 'running' else 1
