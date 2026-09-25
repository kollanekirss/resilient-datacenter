"""One reviewed Nextcloud patch migration in a copied, isolated candidate."""
import base64
import json
import os
from pathlib import Path
from nextcloud_contracts import from_owner
from nextcloud_rendering import configuration_values,application_config,IDENTITY_FIELDS
import nextcloud_runtime as runtime


def verify_configuration_files(folder,baseline):
    # Nextcloud's reviewed Updater::upgrade removes CAN_INSTALL on release
    # builds. Require its absence, while still rejecting extra secret copies.
    # https://github.com/nextcloud/server/blob/v35.0.1/lib/private/Updater.php
    expected=(baseline-{'CAN_INSTALL'})|{'config.php'}
    if {p.name for p in folder.iterdir()}!=expected or any(p.is_symlink() or not p.is_file() for p in folder.iterdir()):
        raise ValueError('Unexpected generated configuration; keep candidate private')


def migrate(settings):
    from backup_operations import require_platform,root_json
    from upgrade_runtime import command,write
    from nextcloud_operations import code_entries,freeze_code
    require_platform();runtime.ready('postgres',settings,attempts=1)
    identity=root_json(runtime.BASE/'identity.json');profile=from_owner(settings['ownership'])
    configuration_values(profile,identity)
    if not identity['version'].startswith('35.0.0.') or settings['components']['nextcloud']['version']!='35.0.1':raise ValueError('No reviewed Nextcloud schema migration for this version')
    code_entries(runtime.APP)
    image=settings['components']['nextcloud']['image']
    # The entire old code tree is retained outside this copied candidate.
    command(runtime.common(settings)+['--rm','--user=0:0','--entrypoint=rsync','--volume',str(runtime.APP)+':/var/www/html:rw',
            image,'-rlt','--delete','/usr/src/nextcloud/','/var/www/html/'],timeout=180)
    folder=runtime.APP/'config'
    if folder.is_symlink() or not folder.is_dir():raise ValueError('Unsafe candidate configuration directory')
    for file in folder.glob('*.config.php'):
        if file.is_symlink() or not file.is_file():raise ValueError('Unexpected candidate configuration entry')
        file.unlink()
    baseline={p.name for p in folder.iterdir()}
    if 'config.php' in baseline:raise ValueError('Pinned source unexpectedly contains a private installation configuration')
    os.chown(folder,33,33);folder.chmod(0o700)
    values=configuration_values(profile,identity)
    values.update(config_is_read_only=False,maintenance=True)
    encoded=base64.b64encode(json.dumps(values,sort_keys=True).encode()).decode()
    write(folder/'config.php','<?php\n$CONFIG = json_decode(base64_decode("'+encoded+'"), true, 512, JSON_THROW_ON_ERROR);\n',uid=33,gid=33)
    base=runtime.common(settings)+['--rm','--user=33:33','--memory=1g','--entrypoint=php',
        '--volume',str(runtime.APP)+':/var/www/html:rw','--volume',str(runtime.STATE/'files')+':/var/www/data:rw',image]
    command(base+['-d','apc.enable_cli=1','/var/www/html/occ','upgrade','--no-interaction'],timeout=600)
    export='$CONFIG=[];require "/var/www/html/config/config.php";echo json_encode(array_intersect_key($CONFIG,array_flip('+json.dumps(sorted(IDENTITY_FIELDS-{'data_fingerprint'}))+')));'
    upgraded=json.loads(command(base+['-r',export],timeout=30));upgraded['data_fingerprint']=identity['data_fingerprint']
    configuration_values(profile,upgraded)
    if not upgraded['version'].startswith('35.0.1.') or {k:v for k,v in upgraded.items() if k!='version'}!={k:v for k,v in identity.items() if k!='version'}:
        raise ValueError('Migration changed a stable file-service identity or returned an unexpected version')
    verify_configuration_files(folder,baseline)
    write(runtime.BASE/'identity.json',json.dumps(upgraded))
    write(runtime.BASE/'config/config.php',application_config(profile,upgraded),mode=0o400,uid=33,gid=33)
    write(runtime.BASE/'code-seeded.json',json.dumps({'image':image}))
    freeze_code(runtime.APP)
