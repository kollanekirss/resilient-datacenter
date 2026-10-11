"""Local repair uses a deliberately entered TTY, never captured shell input."""
import os
from pathlib import Path

import pytest

from appliance.contracts import ApplianceError
from appliance.installer import entry


def test_repair_console_requires_live_context_and_local_tty(monkeypatch):
    monkeypatch.setattr(entry,'live_environment',lambda:False)
    with pytest.raises(ApplianceError,match='live-environment-required'):
        entry.repair_console()
    monkeypatch.setattr(entry,'live_environment',lambda:True)
    monkeypatch.setattr(os,'isatty',lambda fd:False)
    with pytest.raises(ApplianceError,match='repair-console-tty'):
        entry.repair_console()


def test_repair_console_direct_tty_has_bounded_environment(monkeypatch):
    calls=[]
    monkeypatch.setattr(entry,'live_environment',lambda:True)
    monkeypatch.setattr(os,'isatty',lambda fd:True)
    monkeypatch.setattr(os,'spawnve',lambda *args:calls.append(args) or 0)
    monkeypatch.setenv('HOST_SECRET','must-not-forward')
    entry.repair_console()
    assert calls[0][0:3] == (os.P_WAIT,'/bin/bash',['/bin/bash','--noprofile','--norc','-i'])
    assert calls[0][3]['HISTFILE']=='/dev/null'
    assert 'HOST_SECRET' not in calls[0][3]
    assert calls[0][3]['PYTHONPATH']=='/usr/lib/rdc-appliance'
