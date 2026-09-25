from pathlib import Path


def test_managed_daemon_opts_out_of_upstream_diagnostic_uploads():
    unit=(Path(__file__).resolve().parents[1]/'roles/client/templates/tailscaled.service.j2').read_text()
    assert 'Environment=TS_NO_LOGS_NO_SUPPORT=true\n' in unit
    assert '--state=/var/lib/tailscale/tailscaled.state' in unit
