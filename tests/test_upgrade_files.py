from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def fixture(tmp_path):
    import upgrade_files as m
    owner={'applications':{'packages':['matrix']}}
    for name in m.paths(owner):
        path=tmp_path/name;path.mkdir(parents=True);(path/'proof').write_text('original')
    return m,owner


def test_candidate_changes_cannot_modify_the_retained_original(tmp_path):
    m,owner=fixture(tmp_path);identifier='a'*32
    m.stage(tmp_path,owner,identifier)
    for index,name in enumerate(m.paths(owner)):
        path=tmp_path/name;(path/'proof').write_text('migrated')
        assert (m.workspace(tmp_path,name,identifier,index)/'old/proof').read_text()=='original'
    m.restore(tmp_path,owner,identifier)
    assert all((tmp_path/name/'proof').read_text()=='original' for name in m.paths(owner))
    m.clean(tmp_path,owner,identifier)


def test_interrupted_swap_can_recover_each_original_without_recopying(tmp_path,monkeypatch):
    m,owner=fixture(tmp_path);identifier='b'*32;rename=m.durable_rename;count=0
    def interrupt(source,target):
        nonlocal count
        count+=1
        if count==2:raise KeyboardInterrupt()
        rename(source,target)
    monkeypatch.setattr(m,'durable_rename',interrupt)
    with pytest.raises(KeyboardInterrupt):m.stage(tmp_path,owner,identifier)
    monkeypatch.setattr(m,'durable_rename',rename)
    m.restore(tmp_path,owner,identifier)
    assert all((tmp_path/name/'proof').read_text()=='original' for name in m.paths(owner))


def test_linked_resource_or_foreign_workspace_blocks_before_data_changes(tmp_path):
    m,owner=fixture(tmp_path);identifier='c'*32;name=m.paths(owner)[0]
    directory=tmp_path/name;directory.rename(directory.with_name('unmanaged'));directory.symlink_to(directory.with_name('unmanaged'))
    with pytest.raises(ValueError):m.stage(tmp_path,owner,identifier)
    assert (directory/'proof').read_text()=='original'
