"""Local startup independent of Internet or role enrollment."""
from pathlib import Path
import time

from .contracts import ApplianceError, identity, require
from .proxmox import start_owned

PRIVATE = Path('/var/lib/rdc-appliance/private')


class _DeadlineRunner:
    def __init__(self, runner, timeout):
        self.runner = runner
        self.deadline = time.monotonic() + timeout

    def run(self, argv, *, stdin=b'', timeout_s=30):
        remaining = int(self.deadline - time.monotonic())
        require(remaining > 0, 'startup-timeout')
        return self.runner.run(argv, stdin=stdin, timeout_s=min(timeout_s, remaining))


def start_local(plan, runner, *, state=PRIVATE, timeout_s=120):
    require(type(timeout_s) is int and 0 < timeout_s <= 120, 'startup-timeout')
    result = {'schema': 1, 'capability': 'router', 'state': 'blocked',
              'plan_id': identity(plan), 'checked_at': int(time.time()),
              'next_action': 'Complete the disconnected console installation and disk-only boot.'}
    try:
        observed = start_owned(plan, 'router', _DeadlineRunner(runner, timeout_s), state)
        result.update(state='configured', next_action='Verify the installed router through its pinned management channel.')
        result['running'] = observed.get('running') is True
    except ApplianceError as error:
        result['code'] = error.code
    # Always returns to the local menu. No ordinary guest/role startup is hidden
    # inside router readiness, even if the upstream happens to be reachable.
    return [result]


def start_roles(plan, runner, *, state=PRIVATE):
    require(not any(item.get('selected') for item in plan['roles'].values()), 'role-provisioning-unavailable')
    return []
