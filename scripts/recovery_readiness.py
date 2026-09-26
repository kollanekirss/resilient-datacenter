#!/usr/bin/env python3
"""Read-only, offline evidence report for carried crisis-kit recovery material."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
from offline_bundle import verify as software_verify,require,safe_path,open_file,decode
from private_recovery_contract import verify as private_verify,small_json,CATEGORIES
from readiness_checks import status,certificate,backup,exercise,timestamp

TLS_ROLES=('frontend-chat','frontend-element','frontend-files','backend-chat','backend-files')
ACCESS={'router-export':'edge','recovery-credentials':'backup-access','emergency-login':'operator','recovery-runbook':'operator'}
FAILURES={'missing','invalid','expired','stale'}


def example():
    return {'schema_version':1,'max_backup_age_hours':24,'max_exercise_age_days':30,
        'certificates':{role:{'certificate':'tls/'+role+'.crt','private_key':'tls/'+role+'.key','ca':'trust/'+role+'.crt'} for role in TLS_ROLES},
        'backups':{role:{'metadata':'application-backups/'+role+'/snapshot.json','repository':'application-backups/'+role+'/repository'} for role in ('chat','files')},
        'access':{key:category+'/'+key+'.txt' for key,category in ACCESS.items()},
        'exercises':{role:None for role in ('chat','files','site')}}


def fields(value,expected):require(isinstance(value,dict) and set(value)==set(expected),'Unexpected readiness fields')


def reference(value,category):
    if value is None:return
    safe_path(value);require(value.startswith(category+'/'),'Reference is outside its required category')


def settings(data):
    fields(data,example())
    require(type(data['schema_version']) is int and data['schema_version']==1,'Unsupported readiness schema')
    for key,maximum in [('max_backup_age_hours',8760),('max_exercise_age_days',365)]:
        require(type(data[key]) is int and 1<=data[key]<=maximum,'Invalid readiness age policy')
    fields(data['certificates'],TLS_ROLES);fields(data['backups'],('chat','files'));fields(data['access'],ACCESS);fields(data['exercises'],('chat','files','site'))
    for item in data['certificates'].values():
        if item is None:continue
        fields(item,('certificate','private_key','ca'))
        for key,category in [('certificate','tls'),('private_key','tls'),('ca','trust')]:reference(item[key],category)
    for item in data['backups'].values():
        if item is None:continue
        fields(item,('metadata','repository'))
        for value in item.values():reference(value,'application-backups')
    for key,category in ACCESS.items():reference(data['access'][key],category)
    for value in data['exercises'].values():reference(value,'operator')
    return data


def read(root,files,name,category,maximum=4*1024**2):
    reference(name,category)
    if name is None or name not in files:raise FileNotFoundError('Required carried file is absent')
    require(files[name]['size']<=maximum,'Readiness evidence exceeds supported size')
    with open_file(root,name) as stream:raw=stream.read(maximum+1)
    require(len(raw)==files[name]['size'] and hashlib.sha256(raw).hexdigest()==files[name]['sha256'],'Evidence changed after verification')
    return raw


def summarize(checks):
    return 'blocked' if any(item['state'] in FAILURES for item in checks.values()) else 'needs-exercise'


def assessed(checks,key,fn):
    try:checks[key]=fn()
    except FileNotFoundError:checks[key]=status('missing','required-carried-material-missing')
    except (ValueError,OSError,TypeError,KeyError,OverflowError,RecursionError):checks[key]=status('invalid','evidence-invalid-unsafe-or-changed')


def report(software_dir,software_sha256,private_dir,private_sha256,*,now=None):
    now=now or datetime.now(timezone.utc)
    require(now.tzinfo is not None,'Assessment time requires timezone')
    checks={'whole-site-acceptance':status('not-tested','complete-disconnected-site-exercise-required'),
            'credential-usability':status('not-tested','offline-decryption-and-emergency-login-exercise-required'),
            'device-trust':status('not-tested','client-trust-installation-not-inspected'),
            'clock-accuracy':status('not-tested','report-uses-assessment-clock-without-independent-time-proof'),
            'boot-media':status('not-tested','guest-and-hypervisor-media-not-covered-by-role-software-bundle')}
    def software():
        from offline_bundle_install import closure
        if not Path(software_dir).exists() and not Path(software_dir).is_symlink():raise FileNotFoundError()
        data=software_verify(software_dir,software_sha256);closure(data)
        require(timestamp(data['created_at'])<=now,'Software manifest time is in the future')
        return status('verified','role-software-byte-integrity-and-layout-verified')
    assessed(checks,'software',software)
    material=None
    try:
        material=private_verify(private_dir,private_sha256)
        require(timestamp(material['captured_at'])<=now,'Private capture time is in the future')
        checks['private-material']=status('verified','carried-private-bytes-verified')
    except FileNotFoundError:checks['private-material']=status('missing','private-staging-or-manifest-missing')
    except (ValueError,OSError,TypeError,KeyError,OverflowError,RecursionError):checks['private-material']=status('invalid','private-material-invalid-unsafe-or-changed');material=None
    # No evidence is interpreted when its enclosing material cannot be verified.
    if material is not None:
        root=Path(private_dir);files=material['files']
        for category in sorted(CATEGORIES):checks['material-'+category]=status('recorded','verified-files-present-usability-not-established')
        cfg=None
        try:
            cfg=settings(decode(read(root,files,'operator/readiness.json','operator',65536)))
            checks['readiness-settings']=status('verified','assessment-policy-and-references-valid')
        except FileNotFoundError:checks['readiness-settings']=status('missing','add-readiness-settings-before-sealing')
        except (ValueError,OSError,TypeError,KeyError,RecursionError):checks['readiness-settings']=status('invalid','readiness-policy-invalid')
        if cfg is not None:
            plan=decode(read(root,files,'configuration/site.json','configuration',65536))
            days=plan['offline_days']+plan['certificate_margin_days']
            for role in TLS_ROLES:
                def check_certificate(role=role):
                    item=cfg['certificates'][role]
                    if item is None:raise FileNotFoundError()
                    raw=read(root,files,item['certificate'],'tls');key=read(root,files,item['private_key'],'tls');ca=read(root,files,item['ca'],'trust')
                    names=[plan['domains'][role.split('-')[1]]]
                    if role=='backend-chat':names.append(plan['domains']['element'])
                    return certificate(raw,key,ca,names,now,days)
                assessed(checks,'certificate-'+role,check_certificate)
            metadata={}
            for role in ('chat','files'):
                def check_backup(role=role):
                    item=cfg['backups'][role]
                    if item is None:raise FileNotFoundError()
                    raw=read(root,files,item['metadata'],'application-backups',65536)
                    data=decode(raw);result=backup(data,plan,role,now,cfg['max_backup_age_hours'])
                    if result['state'] in ('recorded','stale'):metadata[role]=(hashlib.sha256(raw).hexdigest(),timestamp(data['captured_at']))
                    return result
                assessed(checks,'backup-'+role,check_backup)
                def check_repository(role=role):
                    item=cfg['backups'][role]
                    if item is None or item['repository'] is None:raise FileNotFoundError()
                    prefix=item['repository']+'/'
                    require(item['repository'] not in files,'Repository must be a directory')
                    if prefix+'config' not in files or not all(any(name.startswith(prefix+part+'/') for name in files) for part in ('data','index','keys','snapshots')):raise FileNotFoundError()
                    return status('recorded','local-repository-layout-present-decryption-not-tested')
                assessed(checks,'backup-copy-'+role,check_repository)
                checks['backup-recoverability-'+role]=status('not-tested','application-repository-and-data-restore-not-executed')
            for key,category in ACCESS.items():
                def check_access(key=key,category=category):
                    require(len(read(root,files,cfg['access'][key],category))>0,'Empty recovery reference')
                    return status('recorded','carried-reference-present-content-not-operationally-tested')
                assessed(checks,key,check_access)
            for role in ('chat','files','site'):
                def check_exercise(role=role):
                    path=cfg['exercises'][role]
                    if path is None:return status('not-tested','no-saved-exercise-record')
                    required=('chat','files') if role=='site' else (role,)
                    require(all(r in metadata for r in required),'No valid matching backup metadata')
                    if role=='site':
                        from portable_network import fingerprint
                        digest=fingerprint({r:metadata[r][0] for r in required})
                    else:digest=metadata[role][0]
                    data=decode(read(root,files,path,'operator',65536))
                    require(timestamp(data['performed_at'])>=max(metadata[r][1] for r in required),'Exercise predates the selected backup')
                    return exercise(data,plan,role,digest,now,cfg['max_exercise_age_days'])
                assessed(checks,'exercise-'+role,check_exercise)
    return {'schema_version':1,'state':summarize(checks),'assessed_at':now.isoformat(),'checks':checks,
            'notice':'Offline evidence assessment only. Recorded history is not independent execution; no complete-site readiness is claimed.'}


def render(result):
    lines=['Recovery readiness: '+result['state'],'Assessed at: '+result['assessed_at']]
    for key,item in sorted(result['checks'].items()):
        detail=''
        if 'age_seconds' in item:detail+='; age '+format(item['age_seconds']/3600,'.1f')+' hours'
        if 'captured_at' in item:detail+='; captured '+item['captured_at']
        if 'performed_at' in item:detail+='; recorded exercise '+item['performed_at']
        if 'coverage_days' in item:detail+='; required coverage '+str(item['coverage_days'])+' days'
        lines.append(key.replace('-',' ')+': '+item['state']+' — '+item['reason'].replace('-',' ')+detail)
    return '\n'.join(lines+[result['notice']])


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--software-dir',type=Path,required=True);parser.add_argument('--software-sha256',required=True)
    parser.add_argument('--private-dir',type=Path,required=True);parser.add_argument('--private-sha256',required=True)
    parser.add_argument('--json',action='store_true');args=parser.parse_args(argv)
    try:
        result=report(args.software_dir,args.software_sha256,args.private_dir,args.private_sha256)
        print(json.dumps(result,indent=2) if args.json else render(result))
        return 1 if result['state']=='blocked' else 2
    except (ValueError,OSError,TypeError,KeyError,OverflowError,RecursionError):
        print('Readiness assessment failed; no readiness is claimed.',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
