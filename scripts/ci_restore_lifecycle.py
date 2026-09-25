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
    def command(*args): return subprocess.run(list(args),check=True,capture_output=True,text=True)
    command('ip','netns','add','rdc-recovery-ci')
    command('ip','link','add','rdc-host','type','veth','peer','name','rdc-guest')
    command('ip','link','set','rdc-guest','netns','rdc-recovery-ci')
    command('ip','address','add','10.231.252.1/30','dev','rdc-host')
    command('ip','link','set','rdc-host','up')
    command('ip','netns','exec','rdc-recovery-ci','ip','address','add','10.231.252.2/30','dev','rdc-guest')
    command('ip','netns','exec','rdc-recovery-ci','ip','link','set','rdc-guest','up')
    def reachable():
        return subprocess.run(['ip','netns','exec','rdc-recovery-ci','/usr/bin/python3','-c',
            "import socket; socket.create_connection(('10.231.252.1',443),timeout=1).close()"],capture_output=True).returncode==0
    assert reachable(), 'Real service ingress must work before testing isolation'
    class Observed(Runtime):
        def isolate(self,owner):
            super().isolate(owner)
            assert not reachable(), 'Recovery isolation did not block real non-loopback ingress'
    cert=Path('/etc/rdc-tls/active/tls.crt').read_bytes()
    def users(*args):
        return subprocess.run(['/usr/bin/headscale','--config','/etc/headscale/config.yaml','users',*args,'--output','json'],check=True,capture_output=True,text=True).stdout
    if role=='controller': users('create','ci-before')
    marker=state/'recovery-ci-proof';marker.write_text('snapshot contents')
    with tempfile.TemporaryDirectory(prefix='rdc-restore-ci-') as directory:
        stage=Path(directory)/'snapshot';capture(Path('/'),stage,owner)
        marker.write_text('replacement contents')
        if role=='controller':
            users('create','ci-after')
            assert 'ci-after' in users('list')
        result=apply(stage,owner,runtime=Observed(owner))
        assert result['state']=='restored-service-verified'
        assert marker.read_text()=='snapshot contents'
        if role=='controller':
            restored=users('list')
            assert 'ci-before' in restored and 'ci-after' not in restored
        assert Path('/etc/rdc-tls/active/tls.crt').read_bytes()==cert
        assert not Path('/etc/rdc-restore-pending.json').exists()
        assert Runtime(owner).table() is None
        assert reachable(), 'Ingress must resume only after successful recovery'
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
    command('ip','link','delete','rdc-host')
    command('ip','netns','delete','rdc-recovery-ci')
    print(role+': actual service backup/promotion, failed-validation rollback and interrupted recovery PASS; old-instance fencing is an operator prerequisite.')
