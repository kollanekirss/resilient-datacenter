"""Bounded local subprocess execution. No shell, inherited secrets or log output.

Callers validate operation-specific arguments and establish ownership before
mutating. A failed command has an uncertain outcome; the journal, not retries,
resolves that ambiguity. Successful output is private data until allowlisted.
"""
from __future__ import annotations

import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

from .contracts import ApplianceError, require


class Runner:
    def __init__(self, *, allowed_executables=None, max_output_bytes=4 * 1024 * 1024):
        require(type(max_output_bytes) is int and 0 < max_output_bytes <= 64 * 1024 * 1024,
                'command-output-bound')
        self.allowed_executables = None if allowed_executables is None else frozenset(allowed_executables)
        self.max_output_bytes = max_output_bytes

    def run(self, argv: list[str], *, stdin: bytes = b'', timeout_s: int = 30):
        require(type(argv) is list and 0 < len(argv) <= 1024
                and all(type(a) is str and '\0' not in a and len(a) <= 65536 for a in argv)
                and Path(argv[0]).is_absolute() and '..' not in Path(argv[0]).parts, 'command-arguments')
        require(type(stdin) is bytes and len(stdin) <= 16 * 1024 * 1024, 'command-input-bound')
        require(type(timeout_s) is int and 0 < timeout_s <= 7200, 'command-timeout-bound')
        require(self.allowed_executables is None or argv[0] in self.allowed_executables, 'command-not-allowed')
        process = None
        try:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False, cwd='/', close_fds=True, start_new_session=True,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                     'HOME': '/root', 'PYTHONNOUSERSITE': '1'}, umask=0o077)
            deadline = time.monotonic() + timeout_s
            outputs = {'stdout': bytearray(), 'stderr': bytearray()}
            offset, total = 0, 0
            with selectors.DefaultSelector() as selector:
                for stream, label in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, label)
                if stdin:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
                else:
                    process.stdin.close()
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, 'command-timeout')
                    for key, _ in selector.select(min(remaining, 0.1)):
                        if key.data == 'stdin':
                            try:
                                offset += os.write(key.fd, stdin[offset:offset + 65536])
                            except BrokenPipeError:
                                offset = len(stdin)
                            if offset == len(stdin):
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                        else:
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                            else:
                                total += len(chunk)
                                require(total <= self.max_output_bytes, 'command-output-limit')
                                outputs[key.data].extend(chunk)
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'command-timeout')
                code = process.wait(timeout=remaining)
                require(code == 0, 'command-failed')
                return subprocess.CompletedProcess(argv, code, bytes(outputs['stdout']), bytes(outputs['stderr']))
        except subprocess.TimeoutExpired:
            raise ApplianceError('command-timeout') from None
        except OSError:
            raise ApplianceError('command-execution') from None
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
