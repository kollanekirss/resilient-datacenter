from pathlib import Path
import importlib
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_regional_agreements import NOW


def api():return importlib.import_module('regional_workspace')


def profile(name,address):
    return {'kind':'regional-identity-request','schema_version':1,'institution_id':name,'regional_controller':'region.example.test',
            'gateway_node':name+'-gateway','gateway_ipv4':address,'services':{'matrix':'matrix.'+name+'.test'}}


def workspaces(tmp_path):
    m=api();a=m.Workspace(tmp_path/'north');b=m.Workspace(tmp_path/'south')
    a.initialize(profile('north','100.64.0.10'),'north offline phrase')
    b.initialize(profile('south','100.64.0.11'),'south offline phrase')
    return a,b


def test_encrypted_key_resume_and_public_exports(tmp_path):
    m=api();a,b=workspaces(tmp_path);original=a.identity();secret=(a.base/'signing-key.pem').read_bytes()
    assert b'ENCRYPTED PRIVATE KEY' in secret
    assert (a.base/'signing-key.pem').stat().st_mode&0o077==0
    a.initialize(profile('north','100.64.0.10'),'north offline phrase')
    assert a.identity()==original and (a.base/'signing-key.pem').read_bytes()==secret
    with pytest.raises(ValueError):a.private_seed('wrong password')
    with pytest.raises(ValueError):a.initialize(profile('other','100.64.0.10'),'north offline phrase')
    assert 'PRIVATE' not in a.export_identity().decode()


def test_two_institutions_can_approve_and_revoke_without_claiming_connectivity(tmp_path):
    m=api();a,b=workspaces(tmp_path)
    from regional_agreements import fingerprint
    afp=fingerprint(a.identity());bfp=fingerprint(b.identity())
    a.approve(b.identity(),confirmed_fingerprint=bfp);b.approve(a.identity(),confirmed_fingerprint=afp)
    offered=a.offer(bfp,['matrix'],passphrase='north offline phrase',now=NOW,expires_at=NOW+3600)
    accepted=b.accept(offered,passphrase='south offline phrase',now=NOW+1)
    a.import_agreement(accepted)
    for workspace in (a,b):
        summary=workspace.status(now=NOW+2)
        assert summary['agreements'][0]['state']=='mutually-approved'
        assert summary['transport']=='not-installed-or-verified'
    identifier=accepted['offer']['payload']['agreement_id']
    a.revoke(identifier)
    assert a.status(now=NOW+2)['agreements'][0]['state']=='revoked'
    with pytest.raises(ValueError):a.import_agreement(accepted)
    assert b.status(now=NOW+2)['agreements'][0]['state']=='mutually-approved'


def test_unknown_partner_and_changed_identity_require_explicit_review(tmp_path):
    a,b=workspaces(tmp_path)
    from regional_agreements import fingerprint
    bfp=fingerprint(b.identity())
    with pytest.raises(ValueError):a.offer(bfp,['matrix'],passphrase='north offline phrase',now=NOW,expires_at=NOW+60)
    with pytest.raises(ValueError):a.approve(b.identity(),confirmed_fingerprint='00'*32)
    a.approve(b.identity(),confirmed_fingerprint=bfp)
    offered=a.offer(bfp,['matrix'],passphrase='north offline phrase',now=NOW,expires_at=NOW+60)
    with pytest.raises(ValueError):b.accept(offered,passphrase='south offline phrase',now=NOW+1)


def test_workspace_rejects_linked_or_shared_administration_files(tmp_path):
    a,b=workspaces(tmp_path)
    (a.base/'state.json').chmod(0o644)
    with pytest.raises(ValueError):a.status(now=NOW)
    (a.base/'state.json').unlink();(a.base/'state.json').symlink_to(b.base/'state.json')
    with pytest.raises(ValueError):a.status(now=NOW)
