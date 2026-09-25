"""Adapt the fixed gateway runtime to consistent backup/readiness operations."""
from pathlib import Path
import gateway_runtime as gateway
from gateway_store import Store,decode
from regional_workspace import private_read
from gateway_backup import ownership

UNITS={'gateway':'rdc-regional-gateway'}


def read_settings():
    gateway.verify_runtime();store=Store(gateway.BASE)
    application=ownership(store.profile(),store.identity(),gateway.root_json(Path('/etc/server-connectivity-profile.json')))
    if decode(private_read(gateway.BASE/'ownership.json'))!=application:raise ValueError('Gateway backup ownership changed')
    return {'ownership':application,'identity':store.identity(),'profile':store.profile()}


def verify_image(component,settings):
    if component!='gateway':raise ValueError('Unknown gateway component')
    gateway.verify_image()


def inspect_container(component,settings):
    if component!='gateway':raise ValueError('Unknown gateway component')
    return gateway.inspect(settings['identity'])


def ready(component,settings,attempts=None):
    if component!='gateway':raise ValueError('Unknown gateway component')
    gateway.main('ready')
    from gateway_certificates import status
    if not status(Store(gateway.BASE))['serving_certificate_verified']:raise ValueError('Gateway TLS readiness was not verified')
