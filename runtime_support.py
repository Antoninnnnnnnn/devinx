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
    'DEVINX_HTTP_READ_TIMEOUT': 'HTTP_READ_TIMEOUT',
    'DEVINX_CLIENT_WRITE_TIMEOUT': 'CLIENT_WRITE_TIMEOUT',
    'DEVINX_RELAY_READ_TIMEOUT': 'RELAY_READ_TIMEOUT',
    'DEVINX_KEEPALIVE': 'KEEPALIVE_EVERY',
    'DEVINX_RATE_WAIT': 'RATE_WAIT_BUDGET',
    'DEVINX_DRAIN': 'DRAIN_SECONDS',
}


def build_id(directory):
    """Fingerprint shipped runtime code/descriptors, not local state or secrets."""
    root = Path(directory)
    files = [root / name for name in (
        'devinx.py', 'runtime_support.py', 'diagnostics.py',
        'tools/log_stats.py', 'tools/dashboard.html')]
    files.extend(sorted((root / 'descriptors').glob('*.fdp')))
    digest = hashlib.sha256()
    try:
        for path in files:
            data = path.read_bytes()
            digest.update(str(path.relative_to(root)).replace('\\', '/').encode())
            digest.update(b'\0')
            digest.update(len(data).to_bytes(8, 'big'))
            digest.update(data)
        return digest.hexdigest()[:12]
    except OSError:
        return 'unknown'


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
