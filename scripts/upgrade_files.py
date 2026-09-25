"""Copied upgrade candidates and untouched originals on each owned filesystem."""
import os
from pathlib import Path
import re
import shutil
import stat
from backup_scope import package
from backup_snapshot import copy_resource
from restore_transaction import durable_rename,sync_tree,remove


def paths(owner):
    selected=package(owner['applications'])
    if selected=='matrix':return ('etc/rdc-services','var/lib/rdc-services','usr/local/lib/rdc-services')
    if selected=='nextcloud':return ('etc/rdc-nextcloud','var/lib/rdc-nextcloud','usr/local/lib/rdc-nextcloud','opt/rdc-nextcloud-app')
    raise ValueError('No upgrade filesystem catalogue for this role')


def workspace(root,name,identifier,index):
    if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9]{32}',identifier) or type(index) is not int or not 0<=index<4:raise ValueError('Unknown upgrade workspace identity')
    if name not in ('etc/rdc-services','var/lib/rdc-services','usr/local/lib/rdc-services','etc/rdc-nextcloud','var/lib/rdc-nextcloud','usr/local/lib/rdc-nextcloud','opt/rdc-nextcloud-app'):raise ValueError('Unknown upgrade resource')
    return (Path(root)/name).parent/('.rdc-upgrade-'+identifier+'-'+str(index))


def inspect(path,root):
    if path.is_symlink() or not path.is_dir() or path.is_mount():raise ValueError('Upgrade resource must be an owned directory, not a link or mount root')
    info=path.lstat()
    if info.st_uid!=os.geteuid() or info.st_mode&0o022:raise ValueError('Unsafe upgrade resource ownership')
    for parent in path.parents:
        if parent==root:break
        if parent.is_symlink():raise ValueError('Linked upgrade resource parent')


def check_workspace(path):
    if not path.exists() and not path.is_symlink():return False
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Unsafe upgrade workspace')
    if any(p.name not in ('old','new') or p.is_symlink() or not p.is_dir() for p in path.iterdir()):raise ValueError('Unexpected upgrade workspace contents')
    return True


def preflight(root,owner,identifier):
    root=Path(root);needed={}
    for index,name in enumerate(paths(owner)):
        path=root/name;inspect(path,root);folder=workspace(root,name,identifier,index)
        if folder.exists() or folder.is_symlink():raise ValueError('Upgrade workspace already exists; recover its transaction')
        size=sum(p.stat().st_size for p in path.rglob('*') if p.is_file() and not p.is_symlink())
        device=path.parent.stat().st_dev;parent,total=needed.get(device,(path.parent,0));needed[device]=(parent,total+size)
    for parent,size in needed.values():
        if shutil.disk_usage(parent).free<size*1.1+64*1024*1024:raise ValueError('Insufficient space for an upgrade candidate and retained original')


def stage(root,owner,identifier):
    root=Path(root);preflight(root,owner,identifier)
    for index,name in enumerate(paths(owner)):
        folder=workspace(root,name,identifier,index);folder.mkdir(mode=0o700)
        copy_resource(root/name,folder/'new');sync_tree(folder)
    # No original is renamed until every candidate copy is durable.
    for index,name in enumerate(paths(owner)):
        folder=workspace(root,name,identifier,index)
        durable_rename(root/name,folder/'old');durable_rename(folder/'new',root/name)


def restore(root,owner,identifier):
    root=Path(root)
    for index,name in reversed(list(enumerate(paths(owner)))):
        folder=workspace(root,name,identifier,index)
        if not check_workspace(folder):continue
        if (folder/'old').exists():
            # The caller stopped every candidate writer before this boundary.
            remove(root/name);durable_rename(folder/'old',root/name)
    for name in paths(owner):inspect(root/name,root)


def clean(root,owner,identifier):
    for index,name in enumerate(paths(owner)):
        folder=workspace(root,name,identifier,index)
        if check_workspace(folder):shutil.rmtree(folder)
