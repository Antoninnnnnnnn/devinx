"""Small standard-library helpers shared by service, launcher and diagnostics."""
import contextlib
import errno
import hashlib
import os
from pathlib import Path
import time

# Runtime values that can be disclosed safely. Never add credentials, headers,
# prompts, account identifiers or arbitrary environment variables here.
CONFIG_FIELDS = {
    'DEVINX_CONTEXT_TOKENS': 'SWE_CONTEXT_TOKENS',
    'DEVINX_COMPACT_AT': 'COMPACT_AT',
    'DEVINX_COMPACT_STRICT': 'COMPACT_STRICT',
    'DEVINX_MAX_BODY': 'MAX_BODY_BYTES',
    'DEVINX_MAX_FRAME': 'MAX_FRAME_BYTES',
    'DEVINX_MAX_INFLATED_FRAME': 'MAX_INFLATED_FRAME_BYTES',
    'DEVINX_MAX_INFLIGHT': 'MAX_INFLIGHT',
    'DEVINX_MAX_SWE_INFLIGHT': 'MAX_SWE_INFLIGHT',
    'DEVINX_HTTP_READ_TIMEOUT': 'HTTP_READ_TIMEOUT',
    'DEVINX_CLIENT_WRITE_TIMEOUT': 'CLIENT_WRITE_TIMEOUT',
    'DEVINX_RELAY_READ_TIMEOUT': 'RELAY_READ_TIMEOUT',
    'DEVINX_KEEPALIVE': 'KEEPALIVE_EVERY',
    'DEVINX_RATE_WAIT': 'RATE_WAIT_BUDGET',
    'DEVINX_RATE_FLOOR': 'RATE_FLOOR',
    'DEVINX_DRAIN': 'DRAIN_SECONDS',
}


# The libraries the service's behaviour depends on. A dependency upgrade is a
# new service as much as a code change is, and must read as one.
DEPENDENCIES = ('protobuf', 'requests', 'urllib3')


def _dependency_versions():
    try:
        from importlib import metadata
    except ImportError:
        return []
    out = []
    for name in DEPENDENCIES:
        try:
            out.append(f'{name}={metadata.version(name)}')
        except Exception:
            out.append(f'{name}=absent')
    return out


def build_id(directory):
    """Fingerprint shipped runtime code/descriptors, not local state or secrets.

    A file that cannot be read is fingerprinted by its absence rather than
    turning the whole id into 'unknown': 'unknown' switches stale-service
    detection off altogether, so one missing dashboard file used to leave
    last week's service serving today's launcher without a word. Launcher and
    service both call this, from the same interpreter, so they agree.
    """
    root = Path(directory)
    files = [root / name for name in (
        'devinx.py', 'runtime_support.py', 'diagnostics.py',
        'tools/log_stats.py', 'tools/dashboard.html')]
    try:
        files.extend(sorted((root / 'descriptors').glob('*.fdp')))
    except OSError:
        pass
    digest = hashlib.sha256()
    for path in files:
        name = str(path.relative_to(root)).replace('\\', '/').encode()
        try:
            data = path.read_bytes()
        except OSError:
            digest.update(b'missing\0' + name + b'\0')
            continue
        digest.update(name)
        digest.update(b'\0')
        digest.update(len(data).to_bytes(8, 'big'))
        digest.update(data)
    for version in _dependency_versions():
        digest.update(b'dep\0' + version.encode() + b'\0')
    return digest.hexdigest()[:12]


@contextlib.contextmanager
def startup_lock(directory, port, timeout=40):
    """Serialize launchers sharing a data directory and endpoint.

    Do not unlink the lock on release: a waiting launcher holds that same inode.
    OS locks release automatically if the holder exits. This is coordination,
    not a security boundary between users of the machine.
    """
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f'launch-{port}.lock')
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    acquired = False
    try:
        if os.name == 'nt':
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'0')
            def lock():
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            def unlock():
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            def lock():
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def unlock():
                fcntl.flock(fd, fcntl.LOCK_UN)
        deadline = time.monotonic() + timeout
        while True:
            try:
                lock()
                acquired = True
                break
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError('Another launcher is still starting devinx') from error
                time.sleep(0.05)
        yield
    finally:
        try:
            if acquired:
                unlock()
        finally:
            os.close(fd)
