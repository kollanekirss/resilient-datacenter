"""Small operation records and fixed, privacy-safe messages."""
from dataclasses import dataclass, field
from enum import IntEnum


class Exit(IntEnum):
    SUCCESS = 0
    FAILED = 1
    INVALID = 2
    BLOCKED = 3
    PENDING = 4


@dataclass(frozen=True)
class Check:
    code: str
    outcome: str
    next_step: str


@dataclass(frozen=True)
class ActionResult:
    state: str
    exit_code: Exit
    checks: tuple[Check, ...] = ()
    details: dict = field(default_factory=dict)  # Local display only; never a report input.


CATALOGUE = {
    'manifest.invalid': ('Configuration is invalid or unreadable. Use a complete supported manifest.', 'review-configuration'),
    'platform.unsupported': ('Local apply requires Ubuntu 24.04 amd64 with systemd. This computer can prepare configurations only.', 'use-supported-node'),
    'platform.supported': ('This computer supports local node installation.', 'none'),
    'tooling.sudo_missing': ('Install/configure sudo or run through local root administration.', 'prepare-local-tools'),
    'ownership.invalid': ('Cannot read valid local ownership. Inspect permissions using local administration.', 'inspect-local-permissions'),
    'ownership.unowned': ('Existing unowned installation: migration requires review; no state was changed.', 'review-migration'),
    'ownership.mismatch': ('Ownership/controller/node differs; migration requires review.', 'review-migration'),
    'ownership.missing': ('Install this local node before enrollment/status checks.', 'install-node'),
    'ownership.valid': ('Local ownership checks passed.', 'none'),
    'client.unavailable': ('Persistent node state exists but tailscaled is unavailable. Inspect/start the existing daemon through local administration, then rerun.', 'inspect-service'),
    'client.inspect_denied': ('Could not verify current client identity/controller. Inspect locally; if access was denied, rerun the read-only check using sudo.', 'inspect-local-permissions'),
    'client.state_mismatch': ('Client state or controller does not match. Inspect existing identity; no reset was attempted.', 'review-migration'),
    'client.awaiting_enrollment': ('Node is awaiting enrollment or administrator approval.', 'contact-controller-admin'),
    'client.stopped': ('The client backend is not running. Inspect it through local administration.', 'inspect-service'),
    'client.verified': ('Existing client identity checks passed.', 'none'),
    'client.not_installed': ('The local client is not installed yet.', 'install-node'),
    'controller.connection_failed': ('Controller TLS/DNS connection failed. Check DNS, connectivity, certificate trust/hostname and the local clock; TLS verification was not bypassed.', 'check-connectivity'),
    'controller.verified': ('Controller TLS verification passed.', 'none'),
    'dns.resolve': ('Controller DNS resolution', 'check-dns'),
    'tcp.connect': ('Controller HTTPS connection', 'check-connectivity'),
    'tls.verify': ('Controller certificate trust and hostname', 'inspect-certificate'),
    'tls.expiry': ('Controller certificate validity period', 'inspect-certificate'),
    'probe.timeout': ('Controller diagnostic timed out. Check DNS and network reachability.', 'check-connectivity'),
    'probe.unavailable': ('Controller diagnostic could not complete.', 'check-connectivity'),
    'operation.failed': ('Operation failed. Inspect prerequisites and service state; no reset was attempted.', 'inspect-service'),
    'operation.invalid': ('Unsupported command or input. Consult command help.', 'review-configuration'),
    'report.failed': ('Cannot write a private report. Use a new file in a private directory you own.', 'choose-report-path'),
    'check.unknown': ('Check could not be classified safely.', 'inspect-locally'),
}
OUTCOMES = frozenset({'pass', 'fail', 'unknown', 'not-applicable'})


def check(code: str, outcome: str) -> Check:
    if code not in CATALOGUE or outcome not in OUTCOMES:
        return Check('check.unknown', 'unknown', 'inspect-locally')
    return Check(code, outcome, CATALOGUE[code][1])


def message(item: Check | str) -> str:
    return CATALOGUE.get(item.code if isinstance(item, Check) else item, CATALOGUE['check.unknown'])[0]


class OperationError(Exception):
    def __init__(self, code: str, exit_code: Exit):
        self.code = code if code in CATALOGUE else 'operation.failed'
        self.exit_code = exit_code
        super().__init__(message(self.code))


def result_for_state(state: str, *, details: dict | None = None) -> ActionResult:
    codes = {**dict.fromkeys(('prepared', 'draft', 'checks-passed', 'installed', 'enrolled'), Exit.SUCCESS),
             **dict.fromkeys(('awaiting_enrollment', 'cancelled'), Exit.PENDING),
             **dict.fromkeys(('client_not_running', 'blocked'), Exit.BLOCKED), 'failed': Exit.FAILED}
    if state not in codes:
        raise OperationError('operation.failed', Exit.FAILED)
    return ActionResult(state, codes[state], details=details or {})


def blocking_checks(checks):
    """A known pending enrollment must not prevent requesting approval."""
    return [c for c in checks if c.outcome in ('fail','unknown') and c.code!='client.awaiting_enrollment']
