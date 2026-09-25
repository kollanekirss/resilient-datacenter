#!/usr/bin/env python3
"""Actual private relays and enrolled-controller recovery; disposable Ubuntu only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import yaml
from jinja2 import Environment,FileSystemLoader,StrictUndefined
import ci_regional_network as network


def reachable(client,address,hostname):
    result=subprocess.run(['ip','netns','exec',client['name'],'curl','--silent','--show-error','--fail','--noproxy','*',
        '--connect-timeout','3','--max-time','5','--resolve',hostname+':443:'+address,'https://'+hostname+'/proof'],capture_output=True,text=True,timeout=7)
    return result.returncode==0 and result.stdout=='resilience-proof'


def await_traffic(client,address,hostname,*,seconds=90):
    started=time.monotonic()
    while time.monotonic()-started<seconds:
        if reachable(client,address,hostname):return round(time.monotonic()-started,2)
        time.sleep(1)
    raise ValueError('Useful HTTPS traffic did not recover within the disposable test bound')


def exercise():
    network.require_ci();run=network.run;root=network.ROOT
    if root.exists():raise ValueError('Fresh network fixture required')
    root.mkdir(mode=0o700);network.prepare_binaries()
    run('ip','link','add','rdc-wan','type','bridge');run('ip','link','set','rdc-wan','up')
    run('ip','address','add','172.29.10.2/24','dev','rdc-wan')
    control=['/usr/bin/headscale','--config','/etc/headscale/config.yaml']
    user=json.loads(run(*control,'users','create','ci-resilience','--output','json'))
    network.CONTROLLERS['primary']={'hostname':'control.ci.test','address':'172.29.10.2','command':control,'user_id':str(user['id'])}
    from ci_certificate_lifecycle import download
    binary=root/'derper'
    download('https://github.com/kollanekirss/resilient-datacenter/releases/download/v0.2.0-alpha.1/derper-linux-amd64',binary,'1ae593bc6e4d31c774538982cd6400f6503e053d6a15f9373f98aa5e141f85e5')
    binary.chmod(0o755)
    relays=[];processes={}
    for index in (1,2):
        name='relay-'+str(index);hostname=name+'.ci.test';folder=root/name;folder.mkdir(mode=0o700)
        network.namespace(name,index+2);network.issue(hostname,folder)
        (folder/'tls.crt').rename(folder/(hostname+'.crt'));(folder/'tls.key').rename(folder/(hostname+'.key'))
        address='172.29.10.'+str(22+index);region=900+index
        process=network.spawn(name,['ip','netns','exec',name,str(binary),'-a',':443','-http-port=-1','-stun=true','-stun-port=3478',
            '-hostname='+hostname,'-certmode=manual','-certdir='+str(folder),'-c='+str(folder/'identity.key'),
            '-verify-client-url=https://control.ci.test/verify','-verify-client-url-fail-open=false'])
        relays.append({'host':name,'hostname':hostname,'region_id':region,'address':address});processes['rdc'+str(region)]=process
    template=Environment(loader=FileSystemLoader(network.SOURCE/'roles'),undefined=StrictUndefined).get_template('controller/templates/derp-map.yml.j2')
    Path('/etc/headscale/derp-map.yml').write_text(template.render(profile_relays=relays))
    Path('/etc/headscale/policy.json').write_text(json.dumps({'grants':[{'src':['*'],'dst':['*'],'ip':['tcp:443']}]}))
    run('systemctl','restart','headscale')
    clients=[network.client('resilience-user','primary',1),network.client('resilience-service','primary',2)]
    for client in clients:
        with (Path('/etc/netns')/client['name']/'hosts').open('a') as stream:
            stream.write(''.join(entry['address']+' '+entry['hostname']+'\n' for entry in relays))
        # Permit STUN only. The peers cannot establish a direct UDP data path.
        run('ip','netns','exec',client['name'],'nft','-f','-',input='table inet rdc_force_relay {\n chain output {\n type filter hook output priority -50; policy accept;\n udp dport != 3478 drop;\n }\n}\n')
    service=clients[1];hostname='service.resilience.ci.test';folder=root/'https';folder.mkdir();network.issue(hostname,folder)
    script=folder/'serve.py'
    script.write_text('''import http.server,ssl,sys
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'resilience-proof')
 def log_message(self,*args):pass
server=http.server.HTTPServer((sys.argv[1],443),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(sys.argv[2],sys.argv[3])
server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()
''')
    network.spawn('https',['ip','netns','exec',service['name'],'python3',str(script),service['address'],str(folder/'tls.crt'),str(folder/'tls.key')])
    await_traffic(clients[0],service['address'],hostname)
    status=json.loads(run(*clients[0]['command'],'status','--json'))
    peer=next(record for record in status['Peer'].values() if service['address'] in record['TailscaleIPs'])
    assert not peer.get('CurAddr'),'A direct path would invalidate relay acceptance'
    relay=peer.get('Relay');assert relay in processes,'Traffic did not identify a reviewed relay region'
    processes[relay].terminate();processes[relay].wait(timeout=15)
    elapsed=await_traffic(clients[0],service['address'],hostname)
    status=json.loads(run(*clients[0]['command'],'status','--json'))
    peer=next(record for record in status['Peer'].values() if service['address'] in record['TailscaleIPs'])
    assert not peer.get('CurAddr') and peer.get('Relay') in processes and peer['Relay']!=relay
    print('Actual production relay loss: HTTPS data recovered through surviving region in '+str(elapsed)+' seconds; direct UDP paths blocked. This is a test observation, not an availability guarantee.',flush=True)

    # Move the already verified restricted SFTP daemon to a separate routed
    # namespace. The controller has no Tailscale membership and uses this route.
    from backup_target import SERVICE
    network.namespace('recovery-storage',5)
    run('ip','address','del','100.64.0.12/32','dev','lo')
    run('ip','netns','exec','recovery-storage','ip','address','add','100.64.0.12/32','dev','lo')
    run('ip','route','add','100.64.0.12/32','via','172.29.10.25','dev','rdc-wan')
    dropin=Path('/etc/systemd/system/'+SERVICE+'.service.d');dropin.mkdir()
    (dropin/'ci-namespace.conf').write_text('[Unit]\nRequires=\nAfter=\nPartOf=\n[Service]\nNetworkNamespacePath=/run/netns/recovery-storage\n')
    run('systemctl','daemon-reload');run('systemctl','start',SERVICE)
    from backup_operations import backup_now,configured,stage_restore,WORK
    selected=backup_now()['snapshot_id'];data,transport=configured();transport.wait_ready();stage_restore(selected)
    noise=Path('/var/lib/headscale/noise_private.key');identity=hashlib.sha256(noise.read_bytes()).hexdigest()
    before={client['name']:(client['public_key'],client['address']) for client in clients}
    run('systemctl','stop','headscale')
    assert subprocess.run(['systemctl','is-active','headscale'],capture_output=True).returncode!=0
    # Simulate loss of the controller's persistent state after fencing its sole
    # process. The same prepared OS/TLS baseline is retained, not a fresh-host ISO.
    state=Path('/var/lib/headscale');state.rename(root/'fenced-controller-state');state.mkdir(mode=0o700);shutil.chown(state,user='headscale',group='headscale')
    started=time.monotonic()
    from restore_transaction import apply
    assert apply(WORK/'restores'/selected,data['ownership'])['state']=='restored-service-verified'
    assert hashlib.sha256(noise.read_bytes()).hexdigest()==identity
    await_traffic(clients[0],service['address'],hostname)
    for client in clients:
        current=json.loads(run(*client['command'],'status','--json'))['Self']
        assert (current['PublicKey'],next(ip for ip in current['TailscaleIPs'] if '.' in ip))==before[client['name']]
    additional=network.client('new-after-recovery','primary',6)
    with (Path('/etc/netns')/additional['name']/'hosts').open('a') as stream:stream.write(''.join(entry['address']+' '+entry['hostname']+'\n' for entry in relays))
    await_traffic(additional,service['address'],hostname)
    print('Enrolled controller encrypted routed-SFTP backup and fenced state-loss recovery: retained authority and existing client keys/addresses; useful HTTPS and fresh enrollment verified. Recovery exercise elapsed '+str(round(time.monotonic()-started,2))+' seconds. Physical sites, public CA and fresh OS reconstruction NOT RUN.',flush=True)


def main():
    network.require_ci()
    import ci_certificate_lifecycle
    sys.argv=[sys.argv[0],'controller']
    try:ci_certificate_lifecycle.main(controller_exercise=exercise)
    except BaseException:
        for path in network.ROOT.glob('*.log'):
            print('Disposable component: '+path.name,flush=True)
            for line in path.read_text(errors='replace').splitlines()[-20:]:
                if not any(term in line.lower() for term in ('auth','token','key=','key:','register')):print(line[:500],flush=True)
        raise
    finally:network.cleanup()


if __name__=='__main__':main()
