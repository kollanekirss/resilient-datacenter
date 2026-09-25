"""Fixed Nextcloud snapshot validation, permissions and client recovery epoch."""
import json
import os
from pathlib import Path
import re
import secrets
from nextcloud_contracts import image_pins,from_owner
from nextcloud_rendering import application_config,apache_ports,apache_site,proxy

CONFIG_FILES={'ownership.json','runtime.json','database-password','identity.json','code-seeded.json','config','ports.conf','site.conf','Caddyfile'}


def validate_data(root,application):
    root=Path(root);base=root/'etc/rdc-nextcloud';state=root/'var/lib/rdc-nextcloud'
    if set(p.name for p in base.iterdir())!=CONFIG_FILES or set(p.name for p in state.iterdir())!={'postgres','files'}:
        raise ValueError('Unknown file-service snapshot resources')
    if set(p.name for p in (base/'config').iterdir())!={'config.php'}:raise ValueError('Unreviewed application PHP configuration exists')
    if any(p.is_symlink() for parent in (base,state) for p in parent.rglob('*')):raise ValueError('File-service snapshot data/configuration must not contain links')
    if json.loads((base/'ownership.json').read_text())!=application:raise ValueError('File-service snapshot ownership differs')
    settings=json.loads((base/'runtime.json').read_text())
    if set(settings)!={'schema_version','ownership','bind_address','components'} or settings['schema_version']!=1 or settings['ownership']!=application or settings['components']!=image_pins():
        raise ValueError('File-service snapshot runtime identity differs')
    if json.loads((base/'code-seeded.json').read_text())!={'image':image_pins()['nextcloud']['image']}:raise ValueError('File-service source image differs')
    if not re.fullmatch('[a-f0-9]{64}\\n',(base/'database-password').read_text()):raise ValueError('Invalid database bootstrap credential')
    profile=from_owner(application);identity=json.loads((base/'identity.json').read_text())
    expected={'config/config.php':application_config(profile,identity),'ports.conf':apache_ports(),'site.conf':apache_site(),'Caddyfile':proxy(profile,settings['bind_address'])}
    if any((base/name).read_text()!=content for name,content in expected.items()):raise ValueError('File-service snapshot configuration differs from the fixed package')
    if (state/'postgres/PG_VERSION').read_text().strip()!='17' or not (state/'postgres/global/pg_control').is_file() or (state/'postgres/postmaster.pid').exists():
        raise ValueError('File-service database is missing, unsupported or was not quiesced')
    if (state/'files/.ncdata').read_text()!='# Nextcloud data directory\n# Do not change this file':raise ValueError('Snapshot has no valid Nextcloud data-directory marker')


def restore_permissions(path,name):
    path=Path(path)
    for entry in [path,*path.rglob('*')]:
        if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):raise ValueError('Unsupported file-service restore entry')
        relative=entry.relative_to(path).parts;uid=gid=0;mode=0o700 if entry.is_dir() else 0o600
        if name=='var/lib/rdc-nextcloud' and relative:
            if relative[0] not in ('postgres','files'):raise ValueError('Unknown file-service data directory')
            uid=gid=999 if relative[0]=='postgres' else 33
        elif name=='etc/rdc-nextcloud' and relative:
            if relative[0] not in CONFIG_FILES:raise ValueError('Unknown file-service configuration')
            if relative[0]=='config':uid=gid=33;mode=0o700 if entry.is_dir() else 0o400
            elif relative[0]=='database-password':uid=gid=999;mode=0o400
            elif relative[0] in ('ports.conf','site.conf','Caddyfile'):mode=0o644
        os.chown(entry,uid,gid);entry.chmod(mode)


def refresh_client_fingerprint(candidate,application):
    # Equivalent configuration effect to maintenance:data-fingerprint, while the
    # staged instance is stopped and its fixed configuration remains read-only.
    candidate=Path(candidate);identity=json.loads((candidate/'identity.json').read_text())
    identity['data_fingerprint']=secrets.token_hex(16)
    (candidate/'identity.json').write_text(json.dumps(identity))
    (candidate/'config/config.php').write_text(application_config(from_owner(application),identity))


def include_services():
    from backup_operations import configured,BASE
    from backup_scope import include,network_owner
    from backup_schedule import owned_schedule,refresh_runtime,private_json
    from restore_runtime import install_guards
    import nextcloud_runtime as runtime
    data,_=configured();settings=runtime.read_settings();owner=include(network_owner(data['ownership']),settings['ownership'])
    if 'applications' in data['ownership'] and data['ownership']!=owner:raise ValueError('Changing backup application identity requires review')
    if Path('/etc/rdc-restore-pending.json').exists():raise ValueError('Finish pending recovery before extending backup scope')
    for name in runtime.UNITS:runtime.ready(name,settings,attempts=1)
    install_guards(owner)
    if (BASE/'schedule.json').exists():
        owned_schedule(check_runtime=False);refresh_runtime(Path(__file__).resolve().parent)
    private_json(BASE/'configuration.json',dict(data,ownership=owner))
    return {'state':'application-backup-scope-configured','packages':['nextcloud'],'credentials':'preserved','snapshot_history':'preserved',
            'restore_test':'not-run','next_step':'Run backup, inspect its age and perform a file recovery exercise; network-only snapshots do not protect uploaded files.'}
