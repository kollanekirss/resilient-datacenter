"""Fixed synthetic guest actions for combined recovery; never an operator CLI."""
import builtins
import getpass
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from ci_portable_applications import guard
from ci_site_recovery_contract import extract

BASE=Path('/root/rs-guest')


def main(role,phase):
    guard()
    if role not in ('chat','files') or phase not in ('install','snapshot','restore'):raise ValueError('Unsupported fixture action')
    plan=json.loads((BASE/'site.json').read_text())
    if role=='chat':import service_runtime as runtime
    else:import nextcloud_runtime as runtime
    if phase=='install':
        prepared=Path('/etc/rdc-prepared');prepared.mkdir(mode=0o700)
        for suffix in ('crt','key'):
            target=prepared/(role+'.'+suffix);target.write_bytes((BASE/('role.'+suffix)).read_bytes());target.chmod(0o600)
        Path('/usr/local/share/ca-certificates/rs-fixture.crt').write_bytes((BASE/'ca.crt').read_bytes())
        subprocess.run(['update-ca-certificates'],check=True,stdout=subprocess.DEVNULL)
        from portable_application_install import backend
        password=(BASE/'password').read_text()
        if role=='files':
            builtins.input=lambda *args:'cialice';getpass.getpass=lambda *args:password
        backend(plan,role,offline=True)
        if role=='chat':
            from service_accounts import create
            create('cialice',password,admin=True)
        print('Guest application installed: '+role,flush=True);return
    from backup_scope import include
    from backup_operations import validate_restore
    from restore_runtime import install_guards
    owner=runtime.read_settings()['ownership'];owner=include(owner['network'],owner)
    install_guards(owner)
    stage=BASE/'snapshot'
    if phase=='snapshot':
        from backup_snapshot import capture
        capture(Path('/'),stage,owner);validate_restore(stage,owner)
        with tarfile.open(BASE/'snapshot.tar','w') as archive:archive.add(stage,arcname='.')
        (BASE/'snapshot.tar').chmod(0o600)
    else:
        extract(BASE/'snapshot.tar',stage);validate_restore(stage,owner)
        from restore_transaction import apply
        if apply(stage,owner)['state']!='restored-service-verified':raise ValueError('Native restore did not verify')
    print('Guest native snapshot action passed: '+role+' '+phase,flush=True)


if __name__=='__main__':main(*sys.argv[1:])
