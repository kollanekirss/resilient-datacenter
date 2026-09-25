import importlib
import os
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from test_service_runtime import settings
from test_certificate_activation import Runtime,validate


def test_service_certificate_checks_both_names_before_activation(tmp_path):
    m=importlib.import_module('service_certificates');seen=[]
    def check(cert,key,name):
        seen.append(name)
        if name==settings()['ownership']['element_hostname']:raise ValueError('Element name absent')
        return validate(cert,key,name)
    with pytest.raises(ValueError):m.activate_pair(tmp_path,settings(),b'new',b'key',initial=True,validator=check,gid=os.getgid(),runtime=Runtime())
    assert seen==[settings()['ownership']['matrix_hostname'],settings()['ownership']['element_hostname']]
    assert not (tmp_path/'active').exists()


def test_service_certificate_failure_restores_previous_pair(tmp_path):
    m=importlib.import_module('service_certificates')
    m.activate_pair(tmp_path,settings(),b'old',b'key',initial=True,validator=validate,gid=os.getgid(),runtime=Runtime())
    from certificate_lifecycle import ActivationError
    with pytest.raises(ActivationError) as error:
        m.activate_pair(tmp_path,settings(),b'new',b'key',validator=validate,gid=os.getgid(),runtime=Runtime(fail=1))
    assert error.value.recovered and (tmp_path/'active/tls.crt').read_bytes()==b'old'
