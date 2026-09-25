"""Project-local Ansible execution; inherited execution overrides are discarded."""
import os
from pathlib import Path


def ansible_environment(root: Path) -> dict[str,str]:
    for directory in (root/'.cache/ansible',root/'.work/ansible-tmp'):
        directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    env={key:value for key,value in os.environ.items() if not key.startswith('ANSIBLE_')}
    env.update(ANSIBLE_CONFIG=str(root/'ansible.cfg'),
               ANSIBLE_HOME=str(root/'.cache/ansible'),
               ANSIBLE_LOCAL_TEMP=str(root/'.work/ansible-tmp'))
    return env
