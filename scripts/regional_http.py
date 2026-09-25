"""Fixed, method-scoped Nextcloud federation endpoints shared by both proxies."""
import re
from urllib.parse import unquote

NEXTCLOUD_ROUTES=(
    (('GET','HEAD'),r'^/\.well-known/ocm$'),
    (('GET','HEAD'),r'^/ocm-provider/?$'),
    (('POST',),r'^(/index\.php)?/ocm/(shares|notifications)$'),
    (('GET','HEAD'),r'^(/index\.php)?/apps/cloud_federation_api/api/v1/jwks$'),
    (('POST',),r'^(/index\.php)?/apps/cloud_federation_api/api/v1/access-token$'),
    (('GET','HEAD','OPTIONS','PROPFIND','PUT','MKCOL','DELETE','MOVE','COPY','PROPPATCH'),r'^/public\.php/webdav(/.*)?$'),
)


def nextcloud_allowed(method,path):
    """Offline diagnostic matcher; native proxies still validate normalized paths."""
    if not isinstance(path,str) or '?' in path or '#' in path or '\\' in path:return False
    decoded=unquote(path)
    if any(part in ('.','..') for part in decoded.split('/')):return False
    return any(method in methods and re.fullmatch(pattern,decoded) for methods,pattern in NEXTCLOUD_ROUTES)
