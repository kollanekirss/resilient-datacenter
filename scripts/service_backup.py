"""Matrix snapshot validation and fixed numeric application ownership on recovery."""
import json
import os
from pathlib import Path
from backup_scope import application_profile
from service_rendering import synapse,logging_config,element,element_nginx,proxy
from service_contracts import image_pins

CONFIG_FILES={'ownership.json','runtime.json','secrets.json','database-password','element.json','element-nginx.conf','Caddyfile','synapse'}


def validate_data(root,application):
    root=Path(root);base=root/'etc/rdc-services';state=root/'var/lib/rdc-services'
    if set(p.name for p in base.iterdir())!=CONFIG_FILES or set(p.name for p in state.iterdir())!={'postgres','synapse'}:
        raise ValueError('Application snapshot contains an unexpected resource')
    if set(p.name for p in (base/'synapse').iterdir())!={'homeserver.yaml','log.config'}:
        raise ValueError('Application snapshot contains unreviewed server configuration')
    if any(p.is_symlink() for parent in (base,state) for p in parent.rglob('*')):
        raise ValueError('Application snapshots do not support linked configuration or data')
    generated=json.loads((base/'secrets.json').read_text());profile=application_profile(application)
    settings=json.loads((base/'runtime.json').read_text())
    if set(settings)!={'schema_version','ownership','bind_address','components'} or settings['schema_version']!=1 or settings['ownership']!=application or settings['components']!=image_pins():
        raise ValueError('Snapshot application component identity differs')
    expected={'synapse/homeserver.yaml':synapse(profile,generated),'synapse/log.config':logging_config(),
              'element.json':element(profile),'element-nginx.conf':element_nginx(),
              'Caddyfile':proxy(profile,settings['bind_address']),'database-password':generated['database_password']+'\n'}
    if any((base/name).read_text()!=content for name,content in expected.items()):
        raise ValueError('Snapshot configuration differs from the fixed application package')
    if (state/'postgres/PG_VERSION').read_text().strip()!='17' or not (state/'postgres/global/pg_control').is_file():
        raise ValueError('Snapshot does not contain a supported PostgreSQL database')
    if (state/'postgres/postmaster.pid').exists(): raise ValueError('Snapshot database was not shut down cleanly')
    key=state/'synapse/server.signing.key'
    if not key.is_file() or not 20<key.stat().st_size<4096: raise ValueError('Snapshot has no Matrix signing identity')


def restore_permissions(path,name):
    path=Path(path)
    for entry in [path,*path.rglob('*')]:
        if entry.is_symlink() or not (entry.is_file() or entry.is_dir()): raise ValueError('Unsupported application restore entry')
        relative=entry.relative_to(path).parts
        uid=gid=0;mode=0o700 if entry.is_dir() else 0o600
        if name=='var/lib/rdc-services' and relative:
            if relative[0] not in ('postgres','synapse'): raise ValueError('Unknown persistent application directory')
            uid=gid=999 if relative[0]=='postgres' else 991
        elif name=='etc/rdc-services' and relative:
            if relative[0] not in CONFIG_FILES: raise ValueError('Unknown application configuration')
            if relative[0]=='synapse': gid=991;mode=0o750 if entry.is_dir() else 0o640
            elif relative[0]=='database-password':uid=gid=999;mode=0o400
            elif relative[0] in ('element.json','element-nginx.conf','Caddyfile'):mode=0o644
        os.chown(entry,uid,gid);entry.chmod(mode)


def include_services():
    """Caller holds the backup operation lock and has reviewed this transition."""
    from backup_operations import configured,BASE
    from backup_scope import include,network_owner
    from service_runtime import read_settings,ready,UNITS
    from backup_schedule import owned_schedule,refresh_runtime,private_json
    from restore_runtime import install_guards
    data,_=configured();settings=read_settings()
    owner=include(network_owner(data['ownership']),settings['ownership'])
    if 'applications' in data['ownership'] and data['ownership']!=owner: raise ValueError('Application backup migration requires review')
    if Path('/etc/rdc-restore-pending.json').exists():raise ValueError('Resolve the pending restore before changing backup scope')
    for name in UNITS:ready(name,settings,attempts=1)
    install_guards(owner)
    if (BASE/'schedule.json').exists():
        owned_schedule(check_runtime=False)
        refresh_runtime(Path(__file__).resolve().parent)
    private_json(BASE/'configuration.json',dict(data,ownership=owner))
    return {'state':'application-backup-scope-configured','packages':['matrix'],
            'next_step':'Run backup, inspect its age, and perform a recovery exercise. Existing network-only snapshots do not protect chat.',
            'credentials':'preserved','snapshot_history':'preserved','restore_test':'not-run'}
