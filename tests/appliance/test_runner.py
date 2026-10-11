"""Real child processes expose output bounds, timeout and secret handling."""
import importlib
import os
from pathlib import Path
import sys

import pytest

from appliance.contracts import ApplianceError


def runner(**kwargs):
    return importlib.import_module('appliance.runner').Runner(**kwargs)


def test_child_receives_bytes_and_fixed_environment(monkeypatch):
    monkeypatch.setenv('APPLIANCE_SECRET', 'private')
    proc = runner().run([sys.executable, '-c',
        'import os,sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); '
        'sys.stdout.write("|" + str(os.environ.get("APPLIANCE_SECRET")))'], stdin=b'input')
    assert proc.stdout == b'input|None'
    assert proc.returncode == 0


def test_nonzero_error_never_exposes_child_output_or_arguments():
    with pytest.raises(ApplianceError) as error:
        runner().run([sys.executable, '-c',
            'import sys; print("SECRET"); print("SECRET", file=sys.stderr); sys.exit(4)'])
    assert error.value.code == 'command-failed'
    assert 'SECRET' not in str(error.value)


def test_timeout_is_bounded_and_redacted():
    with pytest.raises(ApplianceError, match='command-timeout'):
        runner().run([sys.executable, '-c', 'import time; time.sleep(30)'], timeout_s=1)


def test_output_flood_is_stopped():
    with pytest.raises(ApplianceError, match='command-output-limit'):
        runner(max_output_bytes=1024).run([sys.executable, '-c',
            'import sys; sys.stdout.buffer.write(b"x" * 2000000)'])


@pytest.mark.parametrize('argv', [[], ['sh', '-c', 'true'], ['/bin/echo', 'bad\x00argument']])
def test_invalid_command_is_refused_before_launch(argv):
    with pytest.raises(ApplianceError, match='command-arguments'):
        runner().run(argv)


def test_executable_allowlist_is_enforced(tmp_path):
    marker = tmp_path / 'never'
    with pytest.raises(ApplianceError, match='command-not-allowed'):
        runner(allowed_executables=('/usr/bin/true',)).run(
            [sys.executable, '-c', f'open({str(marker)!r}, "w").close()'])
    assert not marker.exists()


def test_descendant_holding_pipe_cannot_extend_deadline():
    with pytest.raises(ApplianceError, match='command-timeout'):
        runner().run([sys.executable, '-c',
            'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])'],
            timeout_s=1)
