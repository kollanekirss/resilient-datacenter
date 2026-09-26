#!/usr/bin/env python3
"""Synthetic private-package round trip with the entire process offline."""
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sys
import tempfile
from private_recovery_package import seal,inspect
from private_recovery_contract import inventory

ROOT=Path(__file__).resolve().parents[1]


def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.geteuid()!=0 or platform.system()!='Linux':
        raise ValueError('Only disposable GitHub-hosted Linux acceptance is supported')
    probe=socket.socket();probe.settimeout(2)
    try:assert probe.connect_ex(('1.1.1.1',443))!=0
    finally:probe.close()
    artifact=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix='rdc-private-ci-',dir='/var/lib') as temporary:
        work=Path(temporary);source=work/'input';source.mkdir(mode=0o700)
        for category in ('configuration','edge','trust','tls','backup-access','application-backups','operator'):
            folder=source/category;folder.mkdir(mode=0o700)
            path=folder/'synthetic';path.write_bytes(b'private synthetic acceptance material');path.chmod(0o600)
        for name,example in [('site.json','portable-site.json'),('network.json','portable-network.json')]:
            path=source/'configuration'/name;path.write_bytes((ROOT/'examples'/example).read_bytes());path.chmod(0o600)
        password=work/'password';password.write_text(os.urandom(32).hex());password.chmod(0o600)
        wrong=work/'wrong';wrong.write_text(os.urandom(32).hex());wrong.chmod(0o600)
        expected=inventory(source);repo=work/'repository'
        result=seal(source,repo,password,artifact)
        assert result['state']=='private-package-sealed'
        args=(repo,password,artifact,result['snapshot_id'],result['manifest_sha256'])
        assert inspect(*args)['state']=='private-package-verified'
        restored=work/'restored';assert inspect(*args,output=restored)['state']=='private-material-staged'
        assert inventory(restored,manifest=True)==expected
        for bad_password,bad_hash in [(wrong,result['manifest_sha256']),(password,'a'*64)]:
            target=work/'refused'
            try:inspect(repo,bad_password,artifact,result['snapshot_id'],bad_hash,output=target)
            except ValueError:pass
            else:raise AssertionError('Invalid recovery credential or manifest was accepted')
            assert not target.exists()
        data=next(p for p in (repo/'data').rglob('*') if p.is_file())
        data.write_bytes(b'corrupt synthetic repository data')
        try:inspect(*args,output=work/'corrupt')
        except ValueError:pass
        else:raise AssertionError('Corrupt encrypted data accepted')
        assert not (work/'corrupt').exists()
    print('Offline private package seal/check/open, exact byte recovery, wrong-password/hash and corrupt-repository refusal PASS')
    print('Synthetic transport proof only. Complete-site recovery and real private credential usability are NOT TESTED.')


if __name__=='__main__':main()
