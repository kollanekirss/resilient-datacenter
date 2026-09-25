"""Packet-level application boundary acceptance on disposable Ubuntu only."""
import os
from pathlib import Path
import subprocess
import time


def check(address,hostname,path,unit):
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise ValueError('Disposable CI only')
    def run(*args):return subprocess.run(args,check=True,capture_output=True,timeout=20).stdout
    namespaces=[]
    try:
        for kind,interface,network in (('lan','rdc-lan-test','10.218.10'),('overlay','tailscale0','10.218.11')):
            namespace='rdc-ingress-'+kind;namespaces.append(namespace)
            run('ip','netns','add',namespace)
            run('ip','link','add',interface,'type','veth','peer','name','rdc-peer')
            run('ip','link','set','rdc-peer','netns',namespace)
            run('ip','address','add',network+'.1/30','dev',interface);run('ip','link','set',interface,'up')
            run('ip','netns','exec',namespace,'ip','address','add',network+'.2/30','dev','rdc-peer')
            run('ip','netns','exec',namespace,'ip','link','set','rdc-peer','up')
            run('ip','netns','exec',namespace,'ip','link','set','lo','up')
            run('ip','netns','exec',namespace,'ip','route','add','default','via',network+'.1')
        spoof='100.64.99.2'
        run('ip','netns','exec','rdc-ingress-lan','ip','address','add',spoof+'/32','dev','rdc-peer')
        run('ip','route','add',spoof+'/32','dev','rdc-lan-test')
        # A separate port proves routing works for both source addresses; an
        # unreachable LAN cannot accidentally pass the denial assertions.
        listener=subprocess.Popen(['python3','-u','-c',
            'import socket; s=socket.socket(); s.bind(("'+address+'",8444)); s.listen();\nwhile True:\n c,a=s.accept(); c.sendall(b"route-proof"); c.close()'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            time.sleep(.25)
            for source in ('10.218.10.2',spoof):
                code='import socket,sys; s=socket.socket(); s.settimeout(2); s.bind((sys.argv[2],0)); s.connect((sys.argv[1],8444)); assert s.recv(30)==b"route-proof"'
                run('ip','netns','exec','rdc-ingress-lan','python3','-c',code,address,source)
            for attempt in range(2):
                for source in ('10.218.10.2',spoof):
                    probe=subprocess.run(['ip','netns','exec','rdc-ingress-lan','curl','--silent','--show-error','--noproxy','*',
                        '--connect-timeout','2','--max-time','3','--interface',source,'--resolve',hostname+':443:'+address,
                        '--header','X-Forwarded-For: 100.64.0.1','https://'+hostname+path],capture_output=True,timeout=5)
                    assert probe.returncode==28,'LAN or spoofed source reached private HTTPS'
                result=run('ip','netns','exec','rdc-ingress-overlay','curl','--silent','--show-error','--fail','--noproxy','*',
                    '--max-time','10','--resolve',hostname+':443:'+address,'https://'+hostname+path)
                assert result
                if attempt==0:run('systemctl','restart',unit)
        finally:listener.terminate();listener.wait(timeout=5)
        print('Private HTTPS rejects routed LAN and spoofed overlay sources; separate-port routing proof, synthetic overlay-interface access and proxy restart PASS. Real VPN acceptance is separate.',flush=True)
    finally:
        for namespace in namespaces:subprocess.run(['ip','netns','delete',namespace],capture_output=True,timeout=10)
