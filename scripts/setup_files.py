"""Private, checked output bundles; no installation or enrollment side effects."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import yaml
from setup_contracts import validate_infrastructure, validate_local_manifest


def prepare_outputs(kind: str, configuration: dict) -> dict[str,str]:
    if kind=='join':
        if validate_local_manifest(configuration): raise ValueError('Invalid local manifest')
        manifests=[configuration]; outputs={}
    elif kind=='independent':
        if validate_infrastructure(configuration,check_files=False): raise ValueError('Invalid infrastructure configuration')
        v=configuration['all']['vars']
        manifests=[{'kind':'local-node','schema_version':1,'institution_id':v['institution_id'],'node_name':n['name'],'headscale_hostname':v['headscale_hostname'],'node_tag':n['node_tag']} for n in v['enrollment_nodes']]
        outputs={'infrastructure.yml':yaml.safe_dump(configuration,sort_keys=False)}
    else: raise ValueError('Select independent or join setup')
    for m in manifests: outputs['node-'+m['node_name']+'.yml']=yaml.safe_dump(m,sort_keys=False)
    steps=['# Prepared network setup','', 'These files contain configuration, not enrollment permission. No servers were changed.','']
    if kind=='independent':
        steps += ['On the operator workstation, from the project directory:', '```sh', '.venv/bin/python scripts/validate_setup.py /ABSOLUTE/PATH/infrastructure.yml --kind infrastructure', '.venv/bin/ansible-playbook -i /ABSOLUTE/PATH/infrastructure.yml playbooks/infrastructure-preflight.yml', '.venv/bin/ansible-playbook -i /ABSOLUTE/PATH/infrastructure.yml playbooks/infrastructure-deploy.yml','```','Replace the example path with this bundle location. Verify DNS, SSH host keys and TLS first.', 'On the controller, create the configured enrollment administrator once after checking existing users.','']
    steps += ['Copy each node manifest to its intended Ubuntu 24.04 amd64 machine. Install the project tooling there using docs/guided-setup.md. Confirm the controller with its operator.','For each manifest, run the local_node.py check, apply, enroll and status subcommands as documented. Applying requires sudo; enrollment requires controller administrator approval.', 'Do not copy tailscaled identity state between nodes. No application, backup or gateway is installed by this step.']
    outputs['NEXT-STEPS.md']='\n'.join(steps)+'\n'
    return outputs


def write_bundle(directory: Path, outputs: dict[str,str], *, overwrite: bool = False) -> list[Path]:
    directory=Path(directory).absolute()
    if not outputs or any(not isinstance(n,str) or not n or n in ('.','..','BUNDLE.json') or '/' in n or '\\' in n for n in outputs):
        raise ValueError('Output names must be plain filenames; BUNDLE.json is reserved')
    if any(p.is_symlink() for p in [directory,*directory.parents]): raise ValueError('Refusing a symlink output path')
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    if directory.stat().st_uid!=os.getuid() or directory.stat().st_mode & 0o022:
        raise ValueError('Output directory must be owned by you and not writable by others')
    names=[*outputs,'BUNDLE.json']
    for n in names:
        p=directory/n
        if p.is_symlink() or (p.exists() and not p.is_file()): raise ValueError('Refusing nonregular output target')
        if p.exists() and not overwrite: raise FileExistsError('Setup output already exists; choose explicit replacement or another directory')
    meta={'state':'draft' if set(outputs)=={'draft.yml'} else 'prepared','sha256':{n:hashlib.sha256(t.encode()).hexdigest() for n,t in outputs.items()}}
    contents={**outputs,'BUNDLE.json':json.dumps(meta,indent=2)+'\n'}
    # Invalidate any older completion record before replacing a bundle.
    if overwrite and (directory/'BUNDLE.json').exists(): (directory/'BUNDLE.json').unlink()
    written=[]
    for name,content in contents.items():
        fd,temp=tempfile.mkstemp(prefix='.setup-',dir=directory)
        try:
            with os.fdopen(fd,'w') as stream:
                os.fchmod(stream.fileno(),0o600); stream.write(content); stream.flush(); os.fsync(stream.fileno())
            target=directory/name
            if target.is_symlink(): raise ValueError('Output target changed to a symlink')
            if overwrite: os.replace(temp,target)
            else:
                os.link(temp,target)  # exclusive creation, including race with another writer
                os.unlink(temp)
            written.append(target)
        finally:
            if os.path.exists(temp): os.unlink(temp)
    return written
