"""Reproducible private application preparation kit; no private keys or server calls."""
import hashlib
import json
import os
from pathlib import Path
from portable_state import directory,read,regular,write
from portable_plan import require
from portable_frontend import configuration,nginx
from portable_applications import profiles


def contents(plan,settings):
    c=configuration(plan,settings);apps=profiles(plan)
    from service_contracts import validate as matrix_validate
    from nextcloud_contracts import validate as files_validate
    require(not matrix_validate(apps['chat']) and not files_validate(apps['files']),
            'Replace example service domains with your institution-controlled names before preparing applications.')
    def encoded(value):return json.dumps(value,indent=2)+'\n'
    return {'site.json':encoded(plan),'network.json':encoded(settings),'frontend.json':encoded(c),
        'chat.json':encoded(apps['chat']),'files.json':encoded(apps['files']),'nginx.conf':nginx(c),
        'START-HERE.md':guide(plan,settings)}


def guide(plan,settings):
    return f'''# Portable local applications: {plan['site']}

Preparation does not install services. Use the same reviewed project version on
three dedicated Ubuntu 24.04 amd64 guests. Keep this kit private. Certificate
private keys, application passwords and backup credentials do not belong here.

1. Finish the local network guide first. Verify DNS and time, and retain direct
   Proxmox management access. Use VM consoles for network repairs.
2. Add these OPNsense frontend-interface rules above the final deny, without NAT:
   {plan['vms']['nginx']['address']} -> {plan['vms']['chat']['address']} TCP 443;
   {plan['vms']['nginx']['address']} -> {plan['vms']['files']['address']} TCP 443.
   The existing staff -> frontend HTTPS rule remains. Do not expose database,
   backend HTTP, management or partner endpoints to staff or WAN. No new WAN rule
   is needed. Backend host rules also restrict same-bridge access.
3. Prepare independently trusted certificates while connected. All leaf chains
   must cover at least {plan['offline_days'] + plan['certificate_margin_days']} days.
   On chat: /etc/rdc-prepared/chat.crt and chat.key, naming both
   {plan['domains']['chat']} and {plan['domains']['element']}.
   On files: /etc/rdc-prepared/files.crt and files.key, naming
   {plan['domains']['files']}. Keys must be root-owned mode 0600. Install any
   institution CA in each VM's trust store through your approved process.
   On NGINX, use a private TLS directory with chat.crt/key, element.crt/key and
   files.crt/key naming their corresponding frontend names, plus backend-ca.crt
   containing only approved backend CA certificates. Prefer separate frontend
   and backend keys. Distribute client CA trust in advance if using a private CA.
4. On each intended backend, from the reviewed project directory:
   sudo ./rdc portable applications-apply /private/kit/site.json --role chat
   sudo ./rdc portable applications-apply /private/kit/site.json --role files
   Run only the command for that VM. Confirm the displayed local role. The files
   installer requests its initial administrator password without echoing it.
   Create chat accounts with sudo ./rdc services account [--admin].
5. On the dedicated NGINX VM prepare Ubuntu nginx and nftables packages while
   connected, and disable/stop the stock nginx service. Do not use a VM already
   hosting another website. Then run:
   sudo ./rdc portable frontend-apply /private/kit/site.json --settings /private/kit/network.json --tls-dir /private/frontend-tls
   The installer verifies ownership, local address, certificates and DNS before
   starting a separate rdc-frontend service. It does not edit stock nginx files.
6. Test Element login/message exchange and Nextcloud login/file upload/download
   from a staff client. Then disconnect WAN and stop partner connectivity; cold
   restart the guests and repeat. Listener checks alone do not prove user login.
   Record actual results, versions, recovery time and any lost changes.
7. Configure existing encrypted application backup commands on each backend,
   selecting source role portable, institution {plan['site']}, node chat or files.
   Use a reachable independent local SFTP destination with an independently
   verified host key. Include services, take a snapshot, and exercise fenced
   restore. No Tailscale is needed for the source or SFTP transport. The legacy
   project backup-target installer still requires an overlay; supply an existing
   institution SFTP destination for this mode.
8. Keep the site plan, network settings, this project revision, local trust,
   prepared software and encrypted copies of TLS private material independently
   available. Application snapshots do not include frontend/edge/DNS installation
   or their private TLS keys. Full empty-host offline reconstruction remains a
   separate acceptance gate. Do not boot simultaneous writable copies of an
   application identity.

Renew frontend TLS using frontend-renew with the same plan/settings and a new
private TLS directory. Backend rotation uses the existing services certificate
or files certificate command. Recheck planned certificate coverage afterwards.
No automatic public certificate issuance is required or attempted at local boot.
Do not change site addresses/domains in place; relocation preserves the internal
LAN plan and changes only the edge uplink. Regional federation is deliberately
blocked for this new profile until its separate partner-path acceptance.
'''


def prepare(plan,settings,target):
    files=contents(plan,settings);target=Path(target).absolute();directory(target.parent)
    require(not target.exists() and not target.is_symlink(),'Choose a new application-kit directory; existing paths are not overwritten.')
    target.mkdir(mode=0o700)
    for name,value in files.items():
        fd=os.open(target/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:stream.write(value);stream.flush();os.fsync(stream.fileno())
    write(target/'manifest.json',{'schema_version':1,'files':{name:hashlib.sha256(value.encode()).hexdigest() for name,value in files.items()}})
    verify(target,plan,settings)
    return {'state':'applications-prepared','kit':str(target),'deployment':'not-performed','notice':'Follow START-HERE.md on the intended VMs. No server was changed.'}


def verify(target,plan,settings):
    target=Path(target)
    require(target.exists(),'Application kit does not exist.')
    directory(target);expected=contents(plan,settings);manifest=read(target/'manifest.json')
    require(manifest=={'schema_version':1,'files':{name:hashlib.sha256(value.encode()).hexdigest() for name,value in expected.items()}},'Application-kit manifest differs from this plan or project version.')
    require({p.name for p in target.iterdir()}==set(expected)|{'manifest.json'},'Unexpected application-kit files.')
    for name,wanted in expected.items():
        with regular(target/name) as stream:actual=stream.read(262145)
        require(actual==wanted.encode(),'Application-kit contents changed; regenerate a new kit.')
    return {'state':'application-kit-verified','deployment':'not-verified'}
