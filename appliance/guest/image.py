"""Offline Linux role-image recipe and build boundary.

A recipe with unresolved distro packages is intentionally not executable. All
installed package versions and all added bytes must be pinned before building.
An assembled image is still unqualified until disposable guest tests run.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from ..contracts import ApplianceError, canonical, fields, identity, load_json, require
from .. import state as records
from ..media import verify_file
from ..installer.media import _safe_parents, _write_new
from ..installer.payload import file_record

ROOT=Path(__file__).resolve().parent
LOCK=ROOT.parent/'releases/role-image.inputs.json'
REQUIRED={'python3','cloud-init','qemu-guest-agent','iproute2','openssl','ca-certificates','sqlite3','systemd'}


def template():
    return load_json(LOCK)


def validate_recipe(recipe):
    fields(recipe,{'schema','qualification','base_sha256','binaries','derper_build','packages','package_manifest','package_provenance','notes'})
    require(recipe['schema']==1 and recipe['qualification']=='not-run','role-image-recipe')
    require(type(recipe['packages']) is list and bool(recipe['packages']),'role-image-packages-unpinned')
    require(type(recipe['package_manifest']) is dict and REQUIRED<=set(recipe['package_manifest']),'role-image-package-manifest')
    require(all(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::amd64)?',name) and type(version) is str and re.fullmatch(r'[A-Za-z0-9.+:~_-]+',version)
                for name,version in recipe['package_manifest'].items()),'role-image-package-manifest')
    require(type(recipe['package_provenance']) is dict and set(recipe['package_provenance'])=={'inrelease_sha256','packages_sha256'},'role-image-package-provenance')
    require(all(type(x) is str and re.fullmatch(r'[a-f0-9]{64}',x) for x in [recipe['base_sha256'],*recipe['package_provenance'].values()]),'role-image-package-provenance')
    names=set();files=set()
    for package in recipe['packages']:
        fields(package,{'name','version','filename','sha256','size_bytes','max_bytes'})
        require(package['name'] not in names and package['filename'] not in files and recipe['package_manifest'].get(package['name'])==package['version'],'role-image-package-manifest')
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*\.deb',package['filename']),'role-image-package-filename')
        names.add(package['name']);files.add(package['filename'])
    require(set(recipe['binaries'])=={'tailscale','tailscaled','headscale','derper'},'role-image-binaries')
    for name,binary in recipe['binaries'].items():
        fields(binary,{'version','filename','sha256','size_bytes','max_bytes'})
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*',binary['filename']),'role-image-binary-filename')
    return recipe


def install_script():
    return '''#!/bin/sh
set -eu
umask 077
export DEBIAN_FRONTEND=noninteractive
# Package archives are pinned and staged by the host; network is disabled.
dpkg -i /tmp/rdc-role-stage/packages/*.deb
mkdir -p /usr/lib/python3/dist-packages/appliance /usr/lib/rdc-guest
cp -R /tmp/rdc-role-stage/appliance/. /usr/lib/python3/dist-packages/appliance/
install -m 0755 /tmp/rdc-role-stage/tailscale /usr/bin/tailscale
install -m 0755 /tmp/rdc-role-stage/tailscaled /usr/sbin/tailscaled
install -m 0755 /tmp/rdc-role-stage/headscale /usr/bin/headscale
install -m 0755 /tmp/rdc-role-stage/derper /usr/bin/derper
install -m 0755 /tmp/rdc-role-stage/helper /usr/lib/rdc-guest/helper
install -m 0755 /tmp/rdc-role-stage/initialize /usr/lib/rdc-guest/initialize
install -m 0755 /tmp/rdc-role-stage/recover-snapshots /usr/lib/rdc-guest/recover-snapshots
install -m 0644 /tmp/rdc-role-stage/*.service /etc/systemd/system/
install -m 0644 /tmp/rdc-role-stage/image.json /etc/rdc-image.json
systemctl mask ssh.service ssh.socket apt-daily.service apt-daily.timer apt-daily-upgrade.service apt-daily-upgrade.timer unattended-upgrades.service
systemctl disable headscale.service derper.service tailscaled.service
systemctl enable qemu-guest-agent.service rdc-guest.service rdc-guest-recovery.service
passwd -l root
if id ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi
cloud-init clean --logs --machine-id --seed
rm -f /etc/ssh/ssh_host_* /var/lib/dbus/machine-id /var/lib/systemd/random-seed /etc/rdc-guest.json
rm -rf /var/lib/tailscale /var/lib/headscale /var/lib/rdc-guest /root/.ssh
mkdir -m 0700 /var/lib/rdc-guest
mkdir -p /etc/sysctl.d
printf '%s\\n' net.ipv4.ip_forward=0 net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 > /etc/sysctl.d/90-rdc-guest.conf
dpkg-query -W -f='${Package}=${Version}\\n' | sort > /etc/rdc-image-packages
rm -rf /tmp/rdc-role-stage
'''


def _sources():
    return {str(path.relative_to(ROOT.parent)):file_record(path) for path in sorted([*ROOT.parent.rglob('*.py'),*ROOT.glob('*.service')]) if '__pycache__' not in path.parts}


def build_image(recipe,base,inputs,output,runner):
    """Requires Linux libguestfs/qemu tools, never runs on the user's host OS."""
    validate_recipe(recipe)
    base=_safe_parents(base);inputs=_safe_parents(inputs);output=_safe_parents(output)
    release=load_json(ROOT.parent/'releases/v1.lock.json')
    component=next(c for c in release['components'] if c['id']=='linux-base')
    require(component['sha256']==recipe['base_sha256'],'role-image-base-changed');verify_file(base,component)
    require(output.suffix=='.qcow2' and not output.exists(),'role-image-output')
    # Closed inputs are verified before any command or build-directory mutation.
    for item in [*recipe['packages'],*recipe['binaries'].values()]:verify_file(inputs/item['filename'],item)
    result=runner.run(['/usr/bin/qemu-img','info','--output=json',str(base)])
    try:info=json.loads(result.stdout)
    except (ValueError,UnicodeError):raise ApplianceError('role-image-base-format') from None
    require(info.get('format')=='qcow2' and not any(info.get(k) for k in ('backing-filename','full-backing-filename','encrypted'))
            and not any(info.get('format-specific',{}).get('data',{}).get(k) for k in ('data-file','encrypt')),'role-image-base-format')
    source_records=_sources();recipe_id=identity({'inputs':recipe,'sources':source_records,
        'install_script':hashlib.sha256(install_script().encode()).hexdigest()})
    with records.lock(output.parent):
        with tempfile.TemporaryDirectory(prefix='.role-build-',dir=output.parent) as temporary:
            work=Path(temporary);stage=work/'rdc-role-stage';stage.mkdir(mode=0o700);(stage/'packages').mkdir(mode=0o700)
            for item in recipe['packages']:shutil.copyfile(inputs/item['filename'],stage/'packages'/item['filename'])
            for name,item in recipe['binaries'].items():shutil.copyfile(inputs/item['filename'],stage/name)
            shutil.copytree(ROOT.parent,stage/'appliance',ignore=shutil.ignore_patterns('__pycache__','*.pyc','releases'))
            from .headscale import service_unit as headscale_unit
            from .derp import service_unit as derp_unit
            assets={'helper':'#!/usr/bin/python3\nfrom appliance.guest.helper import main\nmain()\n',
                'initialize':'#!/usr/bin/python3\nfrom appliance.guest.image import initialize\ninitialize()\n',
                'recover-snapshots':'#!/usr/bin/python3\nfrom appliance.guest.image import recover_boot_snapshots\nrecover_boot_snapshots()\n',
                'rdc-guest.service':(ROOT/'rdc-guest.service').read_text(),
                'rdc-guest-recovery.service':(ROOT/'rdc-guest-recovery.service').read_text(),
                'tailscaled.service':(ROOT/'tailscaled.service').read_text(),
                'headscale.service':headscale_unit(),'derper.service':derp_unit(),
                'image.json':canonical({'schema':1,'recipe_id':recipe_id,'versions':{name:item['version'] for name,item in recipe['binaries'].items()}}).decode()+'\n'}
            for name,raw in assets.items():_write_new(stage/name,raw.encode())
            script=work/'install.sh';_write_new(script,install_script().encode());candidate=work/'image.qcow2'
            runner.run(['/usr/bin/qemu-img','convert','-f','qcow2','-O','qcow2',str(base),str(candidate)],timeout_s=600)
            runner.run(['/usr/bin/virt-customize','--no-network','--format','qcow2','-a',str(candidate),'--copy-in',str(stage)+':/tmp','--run',str(script)],timeout_s=1800)
            observed=runner.run(['/usr/bin/virt-cat','--format','qcow2','-a',str(candidate),'/etc/rdc-image-packages'],timeout_s=120)
            try:manifest=dict(line.split('=',1) for line in observed.stdout.decode().splitlines())
            except (ValueError,UnicodeError):raise ApplianceError('role-image-package-manifest') from None
            require(manifest==recipe['package_manifest'],'role-image-package-manifest')
            candidate.chmod(0o600);image=file_record(candidate)
            receipt={'schema':1,'recipe_id':recipe_id,'recipe':recipe,'sources':source_records,'image':image,'filename':output.name,
                     'qualification':'not-run','remaining':['two-distinct-machine-identities','guest-agent-transport','network-isolation','role-runtime']}
            os.link(candidate,output);records.write(output.with_suffix('.qcow2.json'),receipt)
            return receipt


def initialize():
    """One guest boot: bind the seed before QEMU administration or role start."""
    from .state import initialize as bind
    require(os.geteuid()==0,'guest-root-required');state=Path('/var/lib/rdc-guest')
    seed=load_json(Path('/etc/rdc-guest.json'),limit=4096)
    bind(state,seed,Path('/etc/machine-id').read_text().strip())
    image=load_json(Path('/etc/rdc-image.json'),limit=16384)
    path=state/'image.json'
    if path.exists():require(records.read(path)==image,'guest-image-changed')
    else:records.write(path,image)


def recover_boot_snapshots(state=Path('/var/lib/rdc-guest'),runner=None):
    """Run after binding and role startup, never before services we may start."""
    require(os.geteuid()==0,'guest-root-required')
    records.read(Path(state)/'binding.json')
    if runner is None:
        from ..runner import Runner
        runner=Runner()
    from .snapshot import recover_snapshots
    return recover_snapshots(Path(state),runner)


BASE_MANIFEST={'url':'https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.manifest',
    'sha256':'cfe3667617da8f136b7a1673e197d46dbb99cdc248a73f4457ad0ffcfc9796eb','size_bytes':21262,'max_bytes':21262}
ARCHIVE_KEYRING=Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
SNAPSHOT='https://snapshot.ubuntu.com/ubuntu/20260926T000000Z'


def prepare_packages(base_manifest,inputs,output,runner):
    """Download-only APT root: never reads/modifies installed host package state."""
    import pwd
    inputs=_safe_parents(inputs);output=_safe_parents(output);base_manifest=_safe_parents(base_manifest)
    require(inputs.is_dir() and output.parent.is_dir() and not output.exists(),'role-image-prepare-output')
    require(ARCHIVE_KEYRING.is_file(),'role-image-ubuntu-keyring-required')
    if not base_manifest.exists():
        from ..media import _open_https
        with _open_https(BASE_MANIFEST['url']) as source:
            raw=source.read(BASE_MANIFEST['max_bytes']+1)
        require(len(raw)==BASE_MANIFEST['size_bytes'] and hashlib.sha256(raw).hexdigest()==BASE_MANIFEST['sha256'],'role-image-base-manifest')
        _write_new(base_manifest,raw)
    verify_file(base_manifest,BASE_MANIFEST)
    try:
        manifest={}
        for line in base_manifest.read_text().splitlines():
            name,version=line.split();name=name.removesuffix(':amd64')
            require(name not in manifest and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*',name) and re.fullmatch(r'[A-Za-z0-9.+:~_-]+',version),'role-image-base-manifest')
            manifest[name]=version
    except (ValueError,UnicodeError):raise ApplianceError('role-image-base-manifest') from None
    with records.lock(output.parent):
        with tempfile.TemporaryDirectory(prefix='.role-apt-',dir=output.parent) as temporary:
            apt=Path(temporary)
            for directory in ('etc/apt','var/lib/apt/lists/partial','var/cache/apt/archives/partial','var/log/apt'):(apt/directory).mkdir(parents=True,exist_ok=True)
            status=apt/'status';_write_new(status,('\n\n'.join('Package: '+name+'\nStatus: install ok installed\nArchitecture: amd64\nVersion: '+version for name,version in sorted(manifest.items()))+'\n').encode())
            sources=apt/'etc/apt/sources.list'
            _write_new(sources,(''.join('deb [arch=amd64 signed-by='+str(ARCHIVE_KEYRING)+'] '+SNAPSHOT+' '+suite+' main universe\n' for suite in ('noble','noble-updates','noble-security'))).encode())
            options={'Dir':str(apt),'Dir::State::status':str(status),'Dir::Etc::sourcelist':str(sources),
                'Dir::Etc::sourceparts':'-','Dir::Etc::parts':'-','Dir::Etc::main':'-',
                'Dir::Etc::trusted':str(ARCHIVE_KEYRING),'Dir::Etc::trustedparts':'-',
                'APT::Architecture':'amd64','APT::Architectures::':'amd64','APT::Sandbox::User':pwd.getpwuid(os.geteuid()).pw_name,
                'Acquire::Check-Valid-Until':'false','Acquire::GzipIndexes':'false','APT::Get::List-Cleanup':'false'}
            command=['/usr/bin/apt-get','--download-only','--yes','--no-install-recommends','--no-remove']
            for key,value in options.items():command+=['-o',key+'='+value]
            runner.run(command+['update'],timeout_s=600)
            runner.run(command+['install',*sorted(REQUIRED)],timeout_s=1200)
            packages=[]
            for archive in sorted((apt/'var/cache/apt/archives').glob('*.deb')):
                result=runner.run(['/usr/bin/dpkg-deb','--field',str(archive),'Package','Version','Architecture'])
                try:metadata=dict(line.split(': ',1) for line in result.stdout.decode().splitlines())
                except (ValueError,UnicodeError):raise ApplianceError('role-image-package-metadata') from None
                require(metadata.get('Architecture') in ('amd64','all'),'role-image-package-architecture')
                name=metadata['Package'];version=metadata['Version'];manifest[name]=version
                # APT verified each archive against authenticated indexes.
                item={'name':name,'version':version,'filename':archive.name,**file_record(archive)}
                target=inputs/archive.name
                if target.exists():verify_file(target,item)
                else:
                    from ..installer.media import _copy_verified
                    _copy_verified(archive,target,item)
                packages.append(item)
            lists=apt/'var/lib/apt/lists'
            releases={p.name:file_record(p)['sha256'] for p in lists.glob('*InRelease')}
            indexes={p.name:file_record(p)['sha256'] for p in lists.glob('*Packages*') if p.is_file()}
            require(releases and indexes,'role-image-package-indexes')
            recipe=template();recipe.update(packages=packages,package_manifest=manifest,
                package_provenance={'inrelease_sha256':identity(releases),'packages_sha256':identity(indexes)})
            validate_recipe(recipe);records.write(output,recipe)
            return recipe


def read_build_receipt(path):
    receipt=records.read(path)
    fields(receipt,{'schema','recipe_id','recipe','sources','image','filename','qualification','remaining'})
    require(receipt['schema']==1 and receipt['qualification']=='not-run','role-image-receipt')
    validate_recipe(receipt['recipe'])
    expected=template()
    require(all(receipt['recipe'][key]==expected[key] for key in ('base_sha256','binaries','derper_build')),'role-image-inputs-changed')
    require(receipt['sources']==_sources(),'role-image-runtime-changed')
    expected_id=identity({'inputs':receipt['recipe'],'sources':receipt['sources'],
        'install_script':hashlib.sha256(install_script().encode()).hexdigest()})
    require(receipt['recipe_id']==expected_id and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.qcow2',receipt['filename']),'role-image-receipt')
    return receipt


def extract_tailscale(archive,inputs,recipe):
    import tarfile
    from .. import files
    try:
        with tarfile.open(archive,'r:gz') as source:
            for name in ('tailscale','tailscaled'):
                item=recipe['binaries'][name];member=source.getmember('tailscale_'+item['version']+'_amd64/'+name)
                require(member.isfile() and member.size==item['size_bytes'],'role-image-archive-member')
                stream=source.extractfile(member);require(stream is not None,'role-image-archive-member')
                raw=stream.read(item['size_bytes']+1)
                require(len(raw)==item['size_bytes'] and hashlib.sha256(raw).hexdigest()==item['sha256'],'role-image-binary-digest')
                target=Path(inputs)/item['filename']
                if target.exists():verify_file(target,item)
                else:files.atomic_write(Path('/'),target,raw,mode=0o600)
    except (tarfile.TarError,KeyError,OSError):raise ApplianceError('role-image-archive-member') from None


def prepare_binaries(inputs,runner):
    """Obtain vendor binaries and cross-build the pinned relay without executing it."""
    from ..media import prepare_component
    from ..installer.media import _copy_verified
    inputs=_safe_parents(inputs);require(inputs.is_dir(),'role-image-inputs')
    recipe=template();binaries=recipe['binaries']
    present={name:(inputs/item['filename']).exists() for name,item in binaries.items()}
    for name,exists in present.items():
        if exists:verify_file(inputs/binaries[name]['filename'],binaries[name])
    release=load_json(ROOT.parent/'releases/v1.lock.json')
    if not all(present[name] for name in ('tailscale','tailscaled')):
        component=next(c for c in release['components'] if c['id']=='tailscale')
        artifact=prepare_component(component,inputs/'vendor-cache')
        extract_tailscale(artifact,inputs,recipe)
    if not present['headscale']:
        component=next(c for c in release['components'] if c['id']=='headscale')
        artifact=prepare_component(component,inputs/'vendor-cache')
        _copy_verified(artifact,inputs/binaries['headscale']['filename'],binaries['headscale'])
    if not present['derper']:
        go=shutil.which('go');require(go is not None and Path(go).is_absolute(),'role-image-go-required')
        work=inputs/'go-build'
        with records.lock(work):
            build=recipe['derper_build'];require(build['go']=='1.27.1' and build['module']=='tailscale.com/cmd/derper@v1.104.1','role-image-build-toolchain')
            argv=['/usr/bin/env','GOPATH='+str(work/'go'),'GOCACHE='+str(work/'cache'),'GOTOOLCHAIN=go'+build['go'],
                'GOOS=linux','GOARCH=amd64','CGO_ENABLED=0','GOAMD64=v1',go,'install',*build['flags'],build['module']]
            runner.run(argv,timeout_s=1800)
            # Go installs native targets in bin, cross-targets in bin/GOOS_GOARCH.
            candidates=[work/'go/bin/linux_amd64/derper',work/'go/bin/derper']
            source=next((p for p in candidates if p.exists()),None);require(source is not None,'role-image-derper-output')
            verify_file(source,binaries['derper']);_copy_verified(source,inputs/'derper',binaries['derper'])
    for item in binaries.values():verify_file(inputs/item['filename'],item)
    return {'schema':1,'qualification':'not-run','binaries':binaries,'binary_execution':'not-run'}


def main():
    parser=argparse.ArgumentParser(description='Prepare or build the unqualified offline role image.')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('template')
    binaries=sub.add_parser('prepare-binaries');binaries.add_argument('--inputs',type=Path,required=True)
    prepare=sub.add_parser('prepare',help='Resolve signed snapshot packages without installing on the host')
    for name in ('base-manifest','inputs','output'):prepare.add_argument('--'+name,type=Path,required=True)
    build=sub.add_parser('build')
    for name in ('recipe','base','inputs','output'):build.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.command=='template':result=template()
        elif args.command=='prepare-binaries':
            from ..runner import Runner
            result=prepare_binaries(args.inputs,Runner())
        elif args.command=='prepare':
            from ..runner import Runner
            result=prepare_packages(args.base_manifest,args.inputs,args.output,Runner())
        else:
            from ..runner import Runner
            result=build_image(load_json(args.recipe),args.base,args.inputs,args.output,Runner())
        print(canonical(result).decode());return 0
    except ApplianceError as error:
        print(canonical({'state':'blocked','code':error.code}).decode());return 2


if __name__=='__main__':raise SystemExit(main())
