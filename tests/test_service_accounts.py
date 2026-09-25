import importlib
import hashlib
import hmac
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))

def api():return importlib.import_module('service_accounts')


def test_registration_uses_nonce_mac_and_does_not_create_an_unused_login_session():
    data=api().registration_payload('nonce','alice','a secure test password','c'*64,admin=True)
    expected=hmac.new(('c'*64).encode(),b'nonce\0alice\0a secure test password\0admin',hashlib.sha1).hexdigest()
    assert data['mac']==expected and data['inhibit_login'] is True
    assert data['admin'] is True

@pytest.mark.parametrize('username,password',[('alice\x00admin','secure password here'),('Alice','secure password here'),('alice','short'),('alice','password\nwith newline')])
def test_invalid_account_inputs_fail_before_network_access(username,password):
    with pytest.raises(ValueError):api().registration_payload('nonce',username,password,'c'*64,admin=False)
