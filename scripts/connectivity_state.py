"""Private connectivity records with conflict detection; no service state adoption."""
from pathlib import Path
from portable_plan import require
from portable_state import directory, lock, read, write
from connectivity_plan import validate

NAME='connectivity.json'


def load(path):
    path=Path(path).absolute()
    require(path.name==NAME,'Resume using the saved connectivity.json file.')
    require(path.parent.exists(),'Connectivity workspace does not exist; nothing was created.')
    directory(path.parent)
    return validate(read(path))


def save(folder,data,*,expected=None):
    folder=Path(folder).absolute();data=validate(data)
    folder=directory(folder)
    require(set(p.name for p in folder.iterdir()) <= {NAME,'.lock','provisioning'},
            'Choose a dedicated connectivity workspace; unrelated files will not be adopted.')
    with lock(folder):
        if (folder/'provisioning').exists() or (folder/'provisioning').is_symlink():
            directory(folder/'provisioning')
            require(expected is not None and data==expected,
                    'This plan is bound to provisioning records. Use a separately reviewed migration or a new workspace; existing resources were not changed.')
        path=folder/NAME
        if path.exists() or path.is_symlink():
            current=load(path)
            require(expected is not None and current==expected,'Saved connectivity state changed or already exists. Resume it explicitly; nothing was overwritten.')
        else:
            require(expected is None,'Saved connectivity record disappeared; do not overwrite from a stale session.')
        write(path,data)
    return path
