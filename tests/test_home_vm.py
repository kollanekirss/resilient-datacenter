from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))


def test_home_vm_has_nat_and_only_loopback_console_forwarding(tmp_path):
    from ci_home_vm import qemu_command
    command=qemu_command(tmp_path,22222)
    assert '-enable-kvm' in command
    network=command[command.index('-netdev')+1]
    assert network=='user,id=home,hostfwd=tcp:127.0.0.1:22222-:22'
    assert '443' not in network and '0.0.0.0' not in network
    assert '-m' in command and command[command.index('-m')+1]=='4096'
    with pytest.raises(ValueError):qemu_command(tmp_path,22)


def test_home_vm_cannot_run_on_developer_computer(monkeypatch):
    import ci_home_vm
    monkeypatch.delenv('GITHUB_ACTIONS',raising=False)
    with pytest.raises(ValueError):ci_home_vm.guard()
