"""Additional destructive recovery acceptance, called only by the disposable service fixture."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from backup_snapshot import capture
from restore_runtime import Runtime,install_guards
from restore_transaction import apply,recover,RestoreError


def exercise(role):
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('Recovery acceptance is restricted to disposable runners')
    owner=json.loads(Path('/etc/server-connectivity-profile.json').read_text())
    state=Path('/var/lib/headscale' if role=='controller' else '/var/lib/sc-derp')
    if role=='relay': Path('/etc/sc-derp').mkdir(mode=0o750)
    Path('/etc/letsencrypt').mkdir(mode=0o700,exist_ok=True)
    Path('/etc/letsencrypt/ci-account').write_text('disposable account fixture')
    Path('/etc/systemd/system/rdc-certificate-renew.service').write_text('[Service]\nType=oneshot\nExecStart=/bin/true\n')
    Path('/etc/systemd/system/rdc-certificate-renew.timer').write_text('[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n')
    install_guards(owner)
    subprocess.run(['systemctl','start','rdc-certificate-renew.timer'],check=True)
    cert=Path('/etc/rdc-tls/active/tls.crt').read_bytes()
    marker=state/'recovery-ci-proof';marker.write_text('snapshot contents')
    with tempfile.TemporaryDirectory(prefix='rdc-restore-ci-') as directory:
        stage=Path(directory)/'snapshot';capture(Path('/'),stage,owner)
        marker.write_text('replacement contents')
        result=apply(stage,owner)
        assert result['state']=='restored-service-verified'
        assert marker.read_text()=='snapshot contents'
        assert Path('/etc/rdc-tls/active/tls.crt').read_bytes()==cert
        assert not Path('/etc/rdc-restore-pending.json').exists()
        assert Runtime(owner).table() is None
        marker.write_text('data before failure')
        class FailOnce(Runtime):
            def __init__(self,owner): super().__init__(owner);self.once=True
            def verify(self,owner):
                super().verify(owner)
                if self.once: self.once=False;raise ValueError('injected validation failure')
        try: apply(stage,owner,runtime=FailOnce(owner))
        except RestoreError as error: assert error.recovered is True
        else: raise AssertionError('Injected recovery failure was not detected')
        assert marker.read_text()=='data before failure'
        class Interrupt(Runtime):
            def verify(self,owner):
                super().verify(owner);raise KeyboardInterrupt()
        runtime=Interrupt(owner)
        try: apply(stage,owner,runtime=runtime)
        except KeyboardInterrupt: pass
        else: raise AssertionError('Restore interruption not delivered')
        # Model process exit releasing flock, while durable guard/journal/firewall remain.
        if runtime.lock: runtime.lock.close();runtime.lock=None
        service='headscale' if role=='controller' else 'sc-derp'
        subprocess.run(['systemctl','stop',service],check=True)
        assert subprocess.run(['systemctl','start',service],capture_output=True).returncode!=0
        subprocess.run(['systemctl','reset-failed',service],check=True)
        assert recover(owner)['state']=='previous-data-restored'
        assert marker.read_text()=='data before failure'
        assert Runtime(owner).table() is None
        assert subprocess.run(['systemctl','is-active','rdc-certificate-renew.timer'],capture_output=True).returncode==0
    print(role+': actual service backup/promotion, failed-validation rollback and interrupted recovery PASS; old-instance fencing is an operator prerequisite.')
