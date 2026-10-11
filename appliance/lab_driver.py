"""Concrete disposable QEMU driver and namespace-local controlled network peers.

All privileged network operations occur after a new user/network namespace is
created and independently checked empty. This module never configures the host
network, uses host block devices, accepts caller shell commands, or downloads.
The frame protocol executes only the source-pinned ``lab_guest`` action set.
"""
from __future__ import annotations

import base64
import ctypes
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import uuid

from .contracts import ApplianceError, canonical, identity, require

ACTIONS=frozenset({'prepare','observe','fault','probe','reboot','recover'})
MAX_FRAME=2*1024*1024
PREFIX=b'RDC-LAB-RESULT '


def encode_request(action,parameters,*,sequence,token,machine):
    require(action in ACTIONS and type(parameters) is dict,'lab-action')
    require(type(sequence) is int and sequence>0 and re.fullmatch('[0-9a-f]{64}',token),'lab-request')
    value={'schema':1,'action':action,'parameters':parameters,'sequence':sequence,'token':token,'machine':machine}
    raw=canonical(value);require(len(raw)<=MAX_FRAME//2,'lab-frame-limit')
    return base64.b64encode(raw)+b'\n'


def decode_response(raw,*,sequence,token):
    require(type(raw) is bytes and len(raw)<=MAX_FRAME,'lab-frame-limit')
    lines=[line.removesuffix(b'\r') for line in raw.split(b'\n') if line.startswith(PREFIX)]
    require(bool(lines),'lab-response-missing')
    try:value=json.loads(base64.b64decode(lines[-1][len(PREFIX):],validate=True))
    except (ValueError,UnicodeError):raise ApplianceError('lab-response-invalid') from None
    require(type(value) is dict and value.get('schema')==1 and value.get('sequence')==sequence
            and value.get('token')==token and type(value.get('data')) is dict,'lab-response-binding')
    return value


def verify_namespace(previous,current,interfaces):
    require(previous!=current and re.fullmatch(r'net:\[[0-9]+\]',current),'lab-network-namespace-required')
    require(set(interfaces)=={'lo'},'lab-namespace-not-empty')


def enter_namespace():
    """Run in the dedicated worker, never in the caller's process."""
    require(sys.platform=='linux' and len(os.listdir('/proc/self/task'))==1,'lab-linux-single-thread-required')
    previous=os.readlink('/proc/self/ns/net');uid,gid=os.getuid(),os.getgid()
    libc=ctypes.CDLL(None,use_errno=True)
    require(libc.unshare(0x10000000|0x40000000)==0,'lab-private-namespace-unavailable')
    Path('/proc/self/setgroups').write_text('deny\n')
    Path('/proc/self/uid_map').write_text(f'0 {uid} 1\n')
    Path('/proc/self/gid_map').write_text(f'0 {gid} 1\n')
    current=os.readlink('/proc/self/ns/net')
    verify_namespace(previous,current,[name for _,name in socket.if_nameindex()])
    require(Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()=='0','lab-namespace-forwarding')
    # The fresh namespace starts with loopback down. Local known-positive
    # listeners must be reachable before any denial can be interpreted.
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as ctl:
        fcntl.ioctl(ctl,0x8914,struct.pack('16sH',b'lo',0x1|0x8|0x40))
    return {'parent':previous,'private':current,'uid':uid,'gid':gid}


def _interface(name,address,prefix):
    require(re.fullmatch('rdc(?:mgmt|wan)',name),'lab-interface-name')
    fd=os.open('/dev/net/tun',os.O_RDWR|os.O_CLOEXEC)
    try:
        fcntl.ioctl(fd,0x400454ca,struct.pack('16sH',name.encode(),0x0002|0x1000))
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as ctl:
            hardware=bytes.fromhex('5254007700fe' if name=='rdcwan' else '5254007700fd')
            fcntl.ioctl(ctl,0x8924,struct.pack('16sH14s',name.encode(),1,hardware+b'\0'*8))
            for code,ip in ((0x8916,address),(0x891c,str(ipaddress.IPv4Network('0.0.0.0/'+str(prefix)).netmask))):
                fcntl.ioctl(ctl,code,struct.pack('16sH2s4s8s',name.encode(),socket.AF_INET,b'\0\0',socket.inet_aton(ip),b'\0'*8))
            fcntl.ioctl(ctl,0x8914,struct.pack('16sH',name.encode(),0x1|0x40))
        return fd
    except BaseException:os.close(fd);raise


def namespace_route(namespace,address,gateway=None,*,remove=False):
    require(namespace['private']==os.readlink('/proc/self/ns/net') and namespace['private']!=namespace['parent'],
            'lab-network-namespace-required')
    destination=ipaddress.IPv4Address(address).packed
    interface=socket.if_nametoindex('rdcwan')
    def attr(kind,value):
        size=4+len(value);return struct.pack('=HH',size,kind)+value+b'\0'*((-size)%4)
    body=struct.pack('=BBBBBBBBI',socket.AF_INET,32,0,0,254,4,253 if gateway is None else 0,1,0)
    body+=attr(1,destination)+attr(4,struct.pack('=I',interface))
    if gateway is not None:body+=attr(5,ipaddress.IPv4Address(gateway).packed)
    sequence=secrets.randbelow(2**30)+1
    header=struct.pack('=IHHII',16+len(body),25 if remove else 24,1|4|(0 if remove else 0x400|0x200),sequence,0)
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as sock:
        sock.settimeout(5);sock.bind((0,0));sock.send(header+body)
        reply=sock.recv(65536)
    require(len(reply)>=20 and struct.unpack('=IHHII',reply[:16])[3]==sequence
            and struct.unpack('=i',reply[16:20])[0]==0,'lab-private-route-failed')


def namespace_neighbor(namespace,address,mac,*,remove=False):
    require(namespace['private']==os.readlink('/proc/self/ns/net') and namespace['private']!=namespace['parent'],
            'lab-network-namespace-required')
    require(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac),'lab-neighbor-mac')
    def attr(kind,value):
        size=4+len(value);return struct.pack('=HH',size,kind)+value+b'\0'*((-size)%4)
    body=struct.pack('=BBHiHBB',socket.AF_INET,0,0,socket.if_nametoindex('rdcwan'),0x80,0,1)
    body+=attr(1,ipaddress.IPv4Address(address).packed)+attr(2,bytes.fromhex(mac.replace(':','')))
    sequence=secrets.randbelow(2**30)+1
    header=struct.pack('=IHHII',16+len(body),29 if remove else 28,1|4|(0 if remove else 0x400|0x200),sequence,0)
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as sock:
        sock.settimeout(5);sock.bind((0,0));sock.send(header+body);reply=sock.recv(65536)
    require(len(reply)>=20 and struct.unpack('=IHHII',reply[:16])[3]==sequence
            and struct.unpack('=i',reply[16:20])[0]==0,'lab-private-neighbor-failed')


def _options(raw):
    result={};offset=240
    while offset<len(raw):
        code=raw[offset];offset+=1
        if code==255:break
        if code==0:continue
        if offset>=len(raw) or offset+1+raw[offset]>len(raw):return {}
        size=raw[offset];offset+=1
        result[code]=raw[offset:offset+size];offset+=size
    return result


def dhcp_reply(raw,address,gateway,prefix,lease,*,server=None):
    server=gateway if server is None else server
    if len(raw)<240 or raw[:3]!=b'\x01\x01\x06' or raw[236:240]!=b'\x63\x82\x53\x63':return None
    options=_options(raw);kind=options.get(53)
    if kind not in (b'\x01',b'\x03',b'\x08'):return None
    if kind==b'\x03' and options.get(54,socket.inet_aton(server))!=socket.inet_aton(server):return None
    response=bytearray(raw[:240]);response[0]=2
    response[16:20]=socket.inet_aton(address);response[20:24]=socket.inet_aton(server)
    response[24:28]=b'\0'*4;response[44:236]=b'\0'*192
    mask=ipaddress.IPv4Network('0.0.0.0/'+str(prefix)).netmask.packed
    response+=b'\x35\x01'+(b'\x02' if kind==b'\x01' else b'\x05')
    for code,data in ((54,socket.inet_aton(server)),(1,mask),(3,socket.inet_aton(gateway)),
                      (6,socket.inet_aton(gateway)),(42,socket.inet_aton(gateway)),(51,struct.pack('!I',lease)),
                      (58,struct.pack('!I',max(1,lease//2))),(59,struct.pack('!I',max(2,lease*7//8)))):
        response+=bytes((code,len(data)))+data
    return bytes(response)+b'\xff'


def dns_reply(raw,address):
    if len(raw)<17 or raw[2]&0x80 or raw[4:6]!=b'\0\x01':return None
    end=12
    while end<len(raw) and raw[end]:
        size=raw[end]
        if size>63:return None
        end+=1+size
    if end+5!=len(raw) or raw[end+1:end+5]!=b'\0\x01\0\x01':return None
    return raw[:2]+b'\x81\x80\0\x01\0\x01\0\0\0\0'+raw[12:]+b'\xc0\x0c\0\x01\0\x01\0\0\0\x01\0\x04'+socket.inet_aton(address)


def ntp_reply(raw,now):
    if len(raw)!=48 or raw[0]&7!=3:return None
    seconds=int(now)+2208988800
    stamp=struct.pack('!II',seconds,int((now-int(now))*2**32))
    return b'\x24\x01\x04\xec'+b'\0'*8+b'LOCL'+stamp+raw[40:48]+stamp+stamp


class ControlledPeers:
    """Bounded event-loop services on private interfaces; no implicit routing."""
    def __init__(self,plan,run,*,namespace):
        require(namespace['private']==os.readlink('/proc/self/ns/net') and namespace['private']!=namespace['parent'],
                'lab-network-namespace-required')
        self.plan,self.run=plan,Path(run);self.selector=selectors.DefaultSelector();self.sockets=[];self.taps={}
        self.frames=[];self.events=[];self.flow_buffers={};self.nonce='';self.enabled=True;self.last_ra=0;self.capture_started_at=int(time.time())
        network=ipaddress.IPv4Network(plan['upstream']['cidrs'][0]);require(network.prefixlen<=28,'lab-upstream-network')
        self.gateway=str(network.network_address+1);self.server_address=self.gateway;self.lease_address=str(network.network_address+2)
        self.prefix=network.prefixlen;self.lease=30
        self.taps['management']=_interface('rdcmgmt',plan['networks']['management']['admin_ip'],ipaddress.IPv4Network(plan['networks']['management']['cidr']).prefixlen)
        self.taps['wan']=_interface('rdcwan',self.gateway,self.prefix)
        for zone,name in (('management','rdcmgmt'),('wan','rdcwan')):
            packet=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));packet.bind((name,0));self._add(packet,('capture',zone))
        for port,kind in ((67,'dhcp'),(53,'dns'),(123,'ntp')):
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'rdcwan\0')
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
            sock.bind(('',port));self._add(sock,(kind,'wan'))
        for zone,address in (('management',plan['networks']['management']['admin_ip']),('wan',self.gateway)):
            for port in (80,443,4443,18080):
                sock=socket.socket();sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);sock.bind((address,port));sock.listen(8)
                self._add(sock,('tcp',zone))

    def _add(self,sock,kind):
        sock.setblocking(False);self.sockets.append(sock);self.selector.register(sock,selectors.EVENT_READ,kind)

    def tick(self,timeout=0):
        for key,_ in self.selector.select(timeout):
            sock=key.fileobj;kind,zone=key.data
            if kind=='flow':
                try:
                    raw=sock.recv(8192)
                    if not raw:self.selector.unregister(sock);sock.close();continue
                    buffered=self.flow_buffers.get(sock,b'')+raw
                    require(len(buffered)<=8192,'lab-flow-frame')
                    if b'\n' not in buffered:self.flow_buffers[sock]=buffered;continue
                    line,_,remaining=buffered.partition(b'\n');self.flow_buffers[sock]=remaining
                    require(line.startswith(b'RDCFLOW '),'lab-flow-frame')
                    sock.sendall(line[8:]+b'\n')
                except ssl.SSLWantReadError:continue
                except (OSError,ApplianceError):
                    self.selector.unregister(sock);sock.close()
                continue
            if kind=='tcp':
                client,_=sock.accept();client.settimeout(1);keep=False
                try:
                    if sock.getsockname()[1] in (443,4443):
                        client=self.tls.wrap_socket(client,server_side=True)
                    request=client.recv(8192)
                    if request.startswith(b'RDCFLOW ') and request.endswith(b'\n'):
                        client.sendall(request[8:]);self._add(client,('flow',zone));keep=True;continue
                    first=request.split(b'\r\n',1)[0].split()
                    challenge=first[1].removeprefix(b'/').decode('ascii') if len(first)>=2 else ''
                    body=(challenge if re.fullmatch('[0-9a-f]{16,64}',challenge) else self.nonce).encode()+b'\n'
                    client.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
                except OSError:pass
                finally:
                    if not keep:client.close()
                continue
            try:raw,address=sock.recvfrom(65536)
            except BlockingIOError:continue
            if kind=='capture':
                require(len(self.frames)<100000,'lab-capture-limit')
                self.frames.append({'time':int(time.time()),'zone':zone,'hex':raw.hex()});continue
            if kind=='dhcp':
                self.events.append({'kind':kind,'request':raw.hex(),'time':int(time.time())})
                answer=dhcp_reply(raw,self.lease_address,self.gateway,self.prefix,self.lease,server=self.server_address) if self.enabled else None
                if answer:sock.sendto(answer,('255.255.255.255',68))
            elif kind=='dns':
                answer=dns_reply(raw,self.server_address)
                if answer:sock.sendto(answer,address)
            elif kind=='ntp':
                answer=ntp_reply(raw,time.time())
                if answer:sock.sendto(answer,address)
        if time.monotonic()-self.last_ra>=3:
            self.last_ra=time.monotonic();self.advertise_ipv6();self.offer_control()

    def advertise_ipv6(self):
        # Ethernet multicast RA with a ULA /64 and valid ICMPv6 checksum; raw
        # packet injection is confined to the private WAN TAP.
        src=ipaddress.IPv6Address('fe80::1').packed;dst=ipaddress.IPv6Address('ff02::1').packed
        prefix=ipaddress.IPv6Address('fd77:18::').packed
        payload=b'\x86\0\0\0\x40\0\0\x1e'+b'\0'*8+b'\x03\x04\x40\xc0'+struct.pack('!II',60,30)+b'\0'*4+prefix
        data=src+dst+struct.pack('!I',len(payload))+b'\0\0\0\x3a'+payload
        if len(data)%2:data+=b'\0'
        total=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
        while total>>16:total=(total&65535)+(total>>16)
        checksum=(~total)&65535;payload=payload[:2]+struct.pack('!H',checksum)+payload[4:]
        packet=bytes.fromhex('3333000000015254007700fe86dd')+struct.pack('!IHBB',6<<28,len(payload),58,255)+src+dst+payload
        for key in self.selector.get_map().values():
            if key.data[0]=='capture':key.fileobj.send(packet)

    def offer_control(self):
        request=bytearray(240);request[:4]=b'\x01\x01\x06\x00';request[4:8]=os.urandom(4)
        request[28:34]=bytes.fromhex('5254007700fc');request[236:240]=bytes.fromhex('63825363')
        request+=b'\x35\x01\x01\xff'
        response=dhcp_reply(bytes(request),self.lease_address,self.gateway,self.prefix,self.lease,server=self.server_address)
        udp=struct.pack('!HHHH',67,68,8+len(response),0)+response
        header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0,0,64,17,0,socket.inet_aton(self.gateway),b'\xff'*4)
        total=sum(struct.unpack('!10H',header));total=(total&65535)+(total>>16);total=(total&65535)+(total>>16)
        header=header[:10]+struct.pack('!H',(~total)&65535)+header[12:]
        packet=b'\xff'*6+bytes.fromhex('5254007700fe0800')+header+udp
        for key in self.selector.get_map().values():
            if key.data[0]=='capture':key.fileobj.send(packet)

    def close(self):
        self.selector.close()
        for sock in self.sockets:sock.close()
        for fd in self.taps.values():os.close(fd)


def full_qemu_arguments(qemu,handles,execution,*,machine,qmp,boot,variant):
    from .lab_runner import qemu_arguments
    require(boot in ('installer','disk') and variant in ('normal','duplicate-identity','changed-capacity','hot-remove',
        'spanning-storage','non-target-pve','cancel','invalid-media','boot-media-target','nic-order','replace-nic','wrong-cable'),'lab-variant')
    args=qemu_arguments(qemu,handles,execution)
    args.remove('-no-reboot')
    index=args.index('-boot');args[index+1]='order='+('d' if boot=='installer' else 'c')+',menu=off,strict=on'
    index=args.index('-monitor');args[index:index+2]=['-qmp','unix:'+str(qmp)+',server=on,wait=off']
    args+=['-uuid',machine,'-smbios','type=1,product=RDC Disposable Acceptance']
    for index,value in enumerate(args):
        if value.startswith('scsi-hd,drive=target'):args[index]=value+',id=target-disk'
        elif value.startswith('scsi-hd,drive=canary'):
            args[index]=value+',id=canary-disk'
            if variant=='duplicate-identity':args[index]=args[index].replace('RDC-LAB-CANARY','RDC-LAB-TARGET')
    for zone,mac,address in (('management','52:54:00:77:00:01','0x5'),('wan','52:54:00:77:00:02','0x6')):
        old=f'virtio-net-pci,id={zone},mac={mac},romfile='
        index=args.index(old)
        if variant=='replace-nic' and zone=='management':mac='52:54:00:77:00:03'
        backend=('wan' if zone=='management' else 'management') if variant=='wrong-cable' else zone
        args[index]=f'virtio-net-pci,id={zone},netdev={backend},mac={mac},addr={address},romfile='
    for zone in ('management','wan'):args+=['-netdev',f'tap,id={zone},fd={handles[zone+"_tap"]},script=no,downscript=no']
    if boot=='disk':
        # Remove all optical devices; the disk-only case never merely changes
        # boot order while leaving its installer mounted.
        remove=[]
        for i,value in enumerate(args):
            if value.startswith(('if=none,id=installer,','scsi-cd,drive=installer')):remove.extend((i-1,i))
        args=[value for i,value in enumerate(args) if i not in remove]
    return args


class Qmp:
    def __init__(self,path):
        self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket.settimeout(10)
        deadline=time.monotonic()+15
        while True:
            try:self.socket.connect(str(path));break
            except (FileNotFoundError,ConnectionRefusedError):
                require(time.monotonic()<deadline,'lab-qmp-unavailable');time.sleep(.05)
        self.stream=self.socket.makefile('rwb',buffering=0)
        greeting=json.loads(self.stream.readline(65536));require('QMP' in greeting,'lab-qmp-protocol')
        self.command('qmp_capabilities')
    def command(self,name,arguments=None):
        require(name in ('qmp_capabilities','set_link','device_del','block_resize','system_reset','system_powerdown','query-status','query-block'), 'lab-qmp-command')
        nonce=uuid.uuid4().hex;value={'execute':name,'id':nonce}
        if arguments is not None:value['arguments']=arguments
        self.stream.write(canonical(value)+b'\n')
        for _ in range(100):
            value=json.loads(self.stream.readline(65536))
            if value.get('id')==nonce:
                require('error' not in value,'lab-qmp-command-failed');return value['return']
        raise ApplianceError('lab-qmp-response')
    def close(self):self.stream.close();self.socket.close()


class SerialGuest:
    def __init__(self,console,peers,*,run,token,machine,timeout):
        self.console,self.peers,self.run=console,peers,Path(run)
        self.token,self.machine,self.timeout=token,machine,timeout;self.buffer=bytearray();self.sequence=0;self.protocol=False;self.menu_transcript=b''
        self.log=self.run.joinpath('boot-console.log').open('xb');os.chmod(self.log.name,0o600)
    def send(self,raw):
        for offset in range(0,len(raw),16):self.console.send(raw[offset:offset+16])
    def wait(self,marker,timeout=None):
        from .lab_runner import ANSI,MAX_LOG
        deadline=time.monotonic()+(self.timeout if timeout is None else timeout)
        while True:
            clean=ANSI.sub(b'',bytes(self.buffer)).replace(b'\r\n',b'\n')
            index=clean.find(marker)
            if index>=0:
                before=clean[:index+len(marker)];self.buffer=bytearray(clean[index+len(marker):]);return before
            require(time.monotonic()<deadline,'lab-console-observation-timeout')
            self.peers.tick(0)
            for channel,raw in self.console.receive(.05):
                if channel=='serial':
                    self.buffer.extend(raw);require(len(self.buffer)<=MAX_FRAME,'lab-console-limit')
                    if not self.protocol:
                        require(self.log.tell()+len(raw)<=MAX_LOG,'lab-console-log-limit');self.log.write(raw);self.log.flush()
    def live_shell(self):
        from .lab_runner import GRUB,MENU,CONSOLE
        self.menu_transcript+=self.wait(GRUB);self.send(b'\x1b[B\r');self.menu_transcript+=self.wait(MENU)
        self.send(b'\r');self.menu_transcript+=self.wait(MENU)
        self.send(b'3\r');self.menu_transcript+=self.wait(CONSOLE)
        self.send(b'exit\r');self.menu_transcript+=self.wait(MENU)
        self.send(b'3\r');self.menu_transcript+=self.wait(CONSOLE)
        self.start_protocol()
    def installed_shell(self,password):
        self.wait(b'login:');self.send(b'root\r');self.wait(b'Password:');self.protocol=True
        self.send(password.encode()+b'\r');self.wait(b'# ')
        self.start_protocol()
    def start_protocol(self):
        self.protocol=True
        self.send(b'stty -icanon -echo min 1 time 0; PYTHONPATH=/usr/lib/rdc-appliance python3 -u -m appliance.lab_guest\r')
        self.wait(b'RDC-LAB-READY\n')
    def request(self,action,parameters):
        self.sequence+=1;request=encode_request(action,parameters,sequence=self.sequence,token=self.token,machine=self.machine)
        self.send(request)
        raw=self.wait(PREFIX);raw+=self.wait(b'\n')
        return decode_response(raw,sequence=self.sequence,token=self.token)
    def close(self):self.log.close()


class DisposableDriver:
    """The real driver exists only inside its freshly created namespace."""
    synthetic=False
    def __init__(self,config,context,run,handles,*,namespace):
        self.config,self.context,self.run,self.handles=config,context,Path(run),handles
        self.namespace=namespace;self.plan=context['plan'];self.sequence=0;self.machine=str(uuid.uuid4());self.token=os.urandom(32).hex()
        self.profile=None;self.variant='normal';self.console=None;self.guest=None;self.qmp=None;self.closed=False
        self.on_launch=None
        require(self.source_identity()==context['source_id'],'lab-worker-source-changed')
        self.peers=ControlledPeers(self.plan,self.run,namespace=namespace)
        self.timeout=config['acceptance']['case_timeout_seconds'];self.lastdeps={'host_boot':'not-booted'}
        self.password=base64.urlsafe_b64encode(os.urandom(30)).decode();self.credentials=self._credentials()
        self.export_credential=base64.urlsafe_b64encode(os.urandom(40)).decode()+'\n'
        self._make_tls();self.initial_hashes={};self.saved=None;self.installed=False;self.routed=False;self.wan=True
    def _tool(self,name,args,stdin=None,*,check=True):
        pin=self.config['acceptance']['tools'][name]
        from .lab_runner import _open_regular,_hash_fd
        fd=os.dup(self.handles['tool_'+name])
        try:
            require(_hash_fd(fd)==pin['sha256'],'lab-tool-pin-changed')
            result=subprocess.run([pin['path'],*args],executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),
                input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False,
                cwd=self.run,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','HOME':str(self.run)},umask=0o077)
            require(len(result.stdout)<65536 and len(result.stderr)<65536,'lab-private-tool-output')
            if check:require(result.returncode==0,'lab-private-tool-failed')
            return result.stdout if check else result
        finally:os.close(fd)
    def source_identity(self):
        from .lab_runner import _hash_fd
        records=[]
        for item in self.config['_source_descriptors']:
            fd=item['fd'];size=os.fstat(fd).st_size
            require(size==item['size_bytes'],'lab-source-changed')
            records.append({'path':item['path'],'sha256':_hash_fd(fd),'size_bytes':size,'max_bytes':size})
        return identity({'schema':1,'files':records})
    def _credentials(self):
        key=self.run/'management-key'
        self._tool('ssh-keygen',['-q','-t','ed25519','-N','','-f',str(key),'-C','disposable-acceptance'])
        hashed=self._tool('openssl',['passwd','-6','-stdin'],(self.password+'\n').encode()).decode().strip()
        return {'password_hash':hashed,'password':self.password,'ssh_public':' '.join(key.with_suffix('.pub').read_text().split()[:2])}
    def _make_tls(self):
        key=self.run/'tls.key';cert=self.run/'tls.pem'
        self._tool('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=lab.invalid',
            '-addext','subjectAltName=DNS:lab.invalid,IP:'+self.peers.gateway,'-keyout',str(key),'-out',str(cert)])
        self.peers.tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.peers.tls.load_cert_chain(cert,key)
        self.ca=cert.read_text();self.copy_paths={}
    def _copy_disks(self):
        from .lab_runner import _copy,_new_file,_hash_fd
        dfd=os.open(self.run,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            for role in ('target','canary','uefi_vars'):
                old=self.handles.pop(role+'_copy',None)
                if old is not None:
                    path=self.copy_paths[role];info=os.fstat(old);current=path.stat(follow_symlinks=False)
                    require((info.st_dev,info.st_ino)==(current.st_dev,current.st_ino),'lab-copy-path-changed')
                    archive=self.run/(role+'-retired-'+uuid.uuid4().hex+'.json')
                    archive.write_bytes(canonical({'role':role,'sha256':_hash_fd(old),'size_bytes':info.st_size}));archive.chmod(0o600)
                    os.close(old);path.unlink()
                name=f'{role}-{uuid.uuid4().hex}.raw';fd=_new_file(dfd,name);_copy(self.handles[role],fd)
                self.handles[role+'_copy']=fd;self.copy_paths[role]=self.run/name
                require(_hash_fd(fd)==self.config['images'][role]['sha256'],'lab-copy-sha256-mismatch')
            self.initial_hashes=self.disk_hashes()
        finally:os.close(dfd)
    def disk_hashes(self):
        from .lab_runner import _hash_fd
        # QEMU must flush all writes before a consistent offline image hash.
        paused=self.console is not None
        if paused:
            self.console.process.send_signal(signal.SIGSTOP)
        try:
            return {'sha256':{role:_hash_fd(self.handles[role+'_copy']) for role in ('target','canary')},
                'readonly_inputs':{role:{'initial':item['sha256'],'final':_hash_fd(self.handles[role])} for role,item in self.config['images'].items()},
                'source_identity':self.source_identity()}
        finally:
            if paused:self.console.process.send_signal(signal.SIGCONT)
    def stop(self):
        if self.guest:self.guest.close();self.guest=None
        if self.qmp:self.qmp.close();self.qmp=None
        if self.console:self.console.close();self.console=None
    def boot(self,media,variant='normal'):
        from .lab_runner import QemuConsole
        self.stop();socket_path=self.run/('qmp-'+uuid.uuid4().hex+'.sock')
        handles={**self.handles,**{zone+'_tap':fd for zone,fd in self.peers.taps.items()}}
        args=full_qemu_arguments(self.config['_qemu_path'],handles,self.config['execution'],machine=self.machine,
            qmp=socket_path,boot=media,variant=variant)
        pass_fds=[handles[name] for name in ('uefi_code','uefi_vars_copy','target_copy','canary_copy','management_tap','wan_tap')]
        if media=='installer':pass_fds.append(handles['installer'])
        qemu_fd=handles['qemu'];pass_fds.append(qemu_fd)
        child=self.run/('boot-'+uuid.uuid4().hex);child.mkdir(mode=0o700)
        self.boot_started_at=int(time.time())
        self.console=QemuConsole(args,cwd=child,pass_fds=pass_fds,executable='/proc/self/fd/'+str(qemu_fd),timeout_seconds=self.timeout)
        if self.on_launch:self.on_launch()
        self.qmp=Qmp(socket_path)
        if not self.wan:self.qmp.command('set_link',{'name':'wan','up':False})
        self.guest=SerialGuest(self.console,self.peers,run=child,token=self.token,machine=self.machine,timeout=self.timeout)
        if media=='installer':self.guest.live_shell()
        else:self.guest.installed_shell(self.password)
        self.profile='live' if media=='installer' else 'installed'
        return self._request('prepare',{'profile':self.profile,'variant':'normal','plan':self.plan,
            'credentials':self.credentials,'ca_pem':self.ca,'rename_ports':media=='installer' and variant=='nic-order'})
    def _request(self,action,parameters):
        require(self.guest is not None,'lab-guest-not-started')
        raw=self.guest.request(action,parameters);self.lastdeps=raw['dependencies'] or self.lastdeps
        return raw['data']
    def _command(self,data):
        from .lab_guest import _redact
        data=_redact(data)
        code=data.get('returncode',0)
        result=data.get('result',data)
        if code:result={'error':data.get('code','lab-action-failed'),**data}
        return {**{k:v for k,v in data.items() if k not in ('result','returncode')},'returncode':code,'result':result,'stdout':canonical(result).decode(),'stderr':''}
    def _install(self,variant='normal'):
        self.qmp.command('set_link',{'name':'wan','up':False});self.wan=False
        result=self._request('recover',{'kind':'install','variant':variant})
        result['wan_link']=self.qmp.command('query-status')
        result['network_isolation']={'wan_link_requested':'down','backend':'private-network-namespace','forwarding':Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()}
        result['captured_frames']=len(self.peers.frames)
        self.installed=result.get('returncode')==0
        return self._command(result)
    def _network_confirm(self):
        pending=self._request('recover',{'kind':'network-apply'})
        require('transaction_id' in pending and 'challenge' in pending,'lab-network-apply')
        # Real sshd/logind session; strict host key comes from the local console,
        # never trust-on-first-use over the interface being tested.
        keys=self._request('observe',{'kind':'startup','include_host_key':True})
        key=keys.get('host_public_key');require(type(key) is str and key.startswith('ssh-ed25519 '),'lab-host-key')
        known=self.run/'known-hosts';known.write_text(self.plan['networks']['management']['host_ip']+' '+key+'\n');known.chmod(0o600)
        payload=encode_request('recover',{'kind':'network-confirm',**pending},sequence=1,token=self.token,machine=self.machine)
        # The restricted remote command is fixed harness code. No config string
        # is used as shell syntax; stdin is the sole structured request channel.
        argv=['-F','/dev/null','-tt','-i',str(self.run/'management-key'),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
            '-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),
            '-o','GlobalKnownHostsFile=/dev/null','-o','ClearAllForwardings=yes','-o','ConnectTimeout=10',
            'root@'+self.plan['networks']['management']['host_ip'],
            'stty -icanon -echo min 1 time 0; PYTHONPATH=/usr/lib/rdc-appliance python3 -u -m appliance.lab_guest --once']
        response=self._tool('ssh',argv,payload,check=False)
        self.last_ssh={'returncode':response.returncode,'stderr':response.stderr.decode(errors='replace')}
        require(response.returncode==0,'management-session-required')
        result=decode_response(response.stdout,sequence=1,token=self.token)
        require(result['data'].get('state')=='confirmed','lab-network-confirm')
        return result['data']
    def prepare(self,profile,variant,*,bootstrap_only=False):
        if profile=='live' or self.console is None:
            self.stop();self._copy_disks();self.installed=self.routed=False;self.variant=variant;self.wan=True
            bootvariant=variant if variant=='duplicate-identity' else 'normal';data=self.boot('installer',bootvariant)
            if variant in ('non-target-pve','spanning-storage'):
                data=self._request('prepare',{'profile':'live','variant':variant,'plan':self.plan,'credentials':self.credentials,'ca_pem':self.ca})
            if variant=='changed-capacity':self.qmp.command('block_resize',{'device':'target','size':os.fstat(self.handles['target_copy']).st_size-1024**3})
            if variant=='hot-remove':self.qmp.command('device_del',{'id':'target-disk'})
        if profile in ('installed','routed'):
            if not self.installed:
                result=self._install();require(result['returncode']==0,'lab-install-failed')
            if self.profile=='live':self.boot('disk');self._network_confirm()
            if profile=='routed' and not self.routed:
                self.wan=True;self.qmp.command('set_link',{'name':'wan','up':True})
                result=self._request('recover',{'kind':'router-setup','bootstrap_only':bootstrap_only});require(result.get('returncode',0)==0,'lab-router-setup')
                result=self._request('recover',{'kind':'probe-setup','bootstrap_only':bootstrap_only});require(result.get('returncode',0)==0,'lab-probe-setup')
                self.routed=True
        return {'profile':profile,'initial_disks':self.initial_hashes,'inventory':self._request('observe',{'kind':'disks'})}
    def execute_action(self,action,parameters):
        from .lab_guest import validate_action,_redact
        validate_action(action,parameters);self.sequence+=1
        if action=='prepare':data=self.prepare(parameters['profile'],parameters.get('variant','normal'),bootstrap_only=parameters.get('bootstrap_only',False))
        elif action=='observe' and parameters['kind']=='disks':data=self.disk_hashes()
        elif action=='recover' and parameters['kind']=='install':data=self._install()
        elif action=='observe' and parameters['kind']=='startup':
            data=self._request(action,parameters)
            if self.profile=='live':data['serial_menu']=self.guest.menu_transcript.decode(errors='replace')
            data['source_identity']=self.source_identity()
        elif action=='reboot':
            if parameters['target']=='host':
                self.boot('installer' if parameters.get('usb')=='present' else 'disk',self.variant if self.variant in ('nic-order','replace-nic','wrong-cable') else 'normal')
                data={'boot':self.profile}
            else:
                old=self.lastdeps.get('router_boot')
                data=self._request(action,parameters)
                deadline=time.monotonic()+180
                while self.lastdeps.get('router_boot')==old:
                    require(time.monotonic()<deadline,'lab-router-reboot-timeout');self.peers.tick(.1)
                    self._request('observe',{'kind':'router'})
        elif action=='fault' and parameters['kind'] in ('wan-remove','wan-overlap-first','wan-overlap-renew','nic-order','replace-nic','wrong-cable'):
            kind=parameters['kind']
            if kind=='wan-remove':self.wan=False;self.qmp.command('set_link',{'name':'wan','up':False});data={'link':'down'}
            elif kind.startswith('wan-overlap'):
                network=ipaddress.IPv4Network(self.plan['networks']['workload']['cidr'])
                self.peers.lease_address=str(network.network_address+20);self.peers.gateway=str(network.network_address+1)
                self.peers.prefix=network.prefixlen
                if kind=='wan-overlap-first':self._request('recover',{'kind':'wan-return'})
                data={'lease_address':self.peers.lease_address,'lease_seconds':self.peers.lease}
                deadline=time.monotonic()+self.peers.lease+10
                while time.monotonic()<deadline:self.peers.tick(.1)
            else:
                self.variant=kind
                if kind=='nic-order':data=self._command(self._request('fault',{'kind':'nic-order'}))
                else:
                    self.boot('disk',kind)
                    if kind=='wrong-cable':
                        try:self._network_confirm();data=self._command({'state':'confirmed'})
                        except ApplianceError as error:
                            if error.code!='management-session-required':raise
                            pending=self._request('observe',{'kind':'journal'})['records']['network/pending.json']
                            require(pending['phase']=='pending','lab-wrong-cable-confirmed')
                            data=self._command({'returncode':2,'code':error.code,'ssh':self.last_ssh,'phase':pending['phase']})
                    else:data=self._command(self._request('recover',{'kind':'network-apply'}))
        elif action=='recover' and parameters['kind']=='management-rollback' and parameters.get('mode')=='confirm':
            confirmation=self._network_confirm()
            actual=self._request('observe',{'kind':'journal'})
            pending=actual['records']['network/pending.json']
            data=self._command({**confirmation,'phase':pending['phase'],'transaction_id':pending['transaction_id']})
        elif action=='recover' and parameters['kind']=='management-rollback' and parameters.get('mode')=='cold-reboot':
            self.boot('disk');data=self._command(self._request(action,parameters))
        elif action=='recover' and parameters['kind']=='wan-return':
            network=ipaddress.IPv4Network(self.plan['upstream']['cidrs'][0]);self.peers.gateway=str(network.network_address+1)
            self.peers.lease_address=str(network.network_address+2);self.wan=True;self.qmp.command('set_link',{'name':'wan','up':True})
            data=self._command(self._request(action,parameters))
        elif action=='probe':data=self.probe(parameters)
        elif action in ('recover','fault') and parameters['kind'] in ('export','open-export','corrupt-export','wrong-export-password'):
            result=self._request(action,{**parameters,'export_credential':self.export_credential})
            if result.get('credential_sha256'):
                require(result['credential_sha256']==hashlib.sha256(self.export_credential.encode()).hexdigest(),'lab-export-custody-mismatch')
                result['credential_source']='independently-held'
            data=self._command(result)
        else:
            data=self._request(action,parameters)
            if action in ('recover','fault'):data=self._command(data)
        # Private evidence redaction occurs before publication and again at the
        # caller boundary. A fixture cannot supply or replace this transcript.
        data=_redact(data)
        deps={key:self.context[value] for key,value in (('plan','plan_id'),('build','build_id'),('spec','spec_id'),('source','source_id'),('run','run_id'))}
        deps.update(self.lastdeps)
        envelope={'sequence':self.sequence,'checked_at':int(time.time()),'dependencies':deps,'data':data}
        path=self.run/f'action-{self.sequence:06d}.json';raw=canonical({'action':action,'parameters':parameters,**envelope})
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        envelope['evidence']=[{'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}]
        return envelope
    def probe(self,parameters):
        kind=parameters['kind']
        if kind=='host-wan-addresses':
            samples=[]
            for i in range(3):
                observed=self._request('observe',{'kind':'interfaces'});links=observed['addresses']
                names={'wan':None,'wan_bridge':'vmbr1'}
                for item in links:
                    if item.get('address')==self.plan['ports']['wan']['permanent_mac']:names['wan']=item['ifname']
                interfaces={key:next((item.get('addr_info',[]) for item in links if item['ifname']==name),[]) for key,name in names.items()}
                require(names['wan'] is not None,'lab-wan-device-unobserved')
                samples.append({'at':int(time.time()),'interfaces':interfaces})
                deadline=time.monotonic()+2
                while time.monotonic()<deadline:self.peers.tick(.05)
            return {'samples':samples,'capture_interval':[samples[0]['at'],samples[-1]['at']],
                'frames':self.peers.frames,'host_macs':[v['permanent_mac'] for v in self.plan['ports'].values()],
                'capture_started_at':self.peers.capture_started_at,'boot_started_at':self.boot_started_at,'capture_ended_at':int(time.time())}
        if kind=='physical-dhcp-ra':
            start=len(self.peers.frames);deadline=time.monotonic()+12
            while time.monotonic()<deadline:self.peers.tick(.05)
            return {'frames':self.peers.frames[start:],'packets':[f['hex'] for f in self.peers.frames[start:]],'capture_seconds':12,
                'control_macs':['52:54:00:77:00:fe'],'appliance_macs':[p['permanent_mac'] for p in self.plan['ports'].values()]
                    +[n['mac'] for n in self.plan['vms']['router']['nics']]}
        self.peers.nonce=parameters.get('nonce','')
        raw=self._request('probe',{**parameters,'peer_address':self.peers.server_address})
        if kind in ('wan-admin','management'):
            for check in raw['admin_checks']:
                address=check['destination_control']['destination']
                source=self.peers.server_address if kind=='wan-admin' else self.plan['networks']['management']['admin_ip']
                if kind=='wan-admin':
                    mac=self.plan['ports']['wan']['permanent_mac'] if check['target']=='host' else next(n['mac'] for n in self.plan['vms']['router']['nics'] if n['zone']=='wan')
                    namespace_route(self.namespace,address)
                    namespace_neighbor(self.namespace,address,mac)
                try:
                    # Preserve the local console pin and CA supplied by the
                    # guest, but perform the attempt from the actual WAN peer.
                    cert=self.run/('admin-'+check['target']+'.pem')
                    cert.write_text(check.pop('ca_pem'));check.pop('certificate_pem',None);cert.chmod(0o600)
                    args={'host':address,'port':check['destination_control']['port'],'nonce':parameters['nonce'],
                          'source':source,'ca_file':str(cert),'server_name':check.pop('server_name'),'timeout_s':5}
                    check['attempt']=self.local_probe('https',args)
                    if kind=='wan-admin':check['wan_destination_mac']=mac
                    check['source_control']=self.local_probe('http',{'host':source,'nonce':parameters['nonce'],'source':source,'timeout_s':5})
                finally:
                    if kind=='wan-admin':
                        try:namespace_neighbor(self.namespace,address,mac,remove=True)
                        finally:namespace_route(self.namespace,address,remove=True)
        if kind=='forwarding-state':
            if parameters.get('operation')=='check':
                control=self.local_probe('https',{'host':self.peers.server_address,'nonce':raw['nonce'],'timeout_s':10,
                    'ca_file':str(self.run/'tls.pem'),'server_name':'lab.invalid'})
                raw['control']={'returncode':0 if control.get('error') is None and control.get('response_nonce')==raw['nonce'] else 1,
                                'stdout':control.get('response_nonce') or '','stderr':control.get('error') or ''}
            return raw
        if kind in ('https','dns','ntp'):
            args={'host':self.peers.server_address,'nonce':parameters['nonce'],'timeout_s':10}
            if kind=='https':args.update(ca_file=str(self.run/'tls.pem'),server_name='lab.invalid')
            raw['destination_control']=self.local_probe(kind,args)
        return probe_report(raw)
    def local_probe(self,kind,args):
        code='import json,sys;from appliance.lab_probe import probe_network;print(json.dumps(probe_network(sys.argv[1],**json.loads(sys.argv[2]))))'
        process=subprocess.Popen([sys.executable,'-c',code,kind,canonical(args).decode()],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,close_fds=True,start_new_session=True,cwd=Path(__file__).parent.parent,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','PYTHONPATH':str(Path(__file__).parent.parent),'PYTHONNOUSERSITE':'1'})
        deadline=time.monotonic()+30
        try:
            while process.poll() is None:
                require(time.monotonic()<deadline,'lab-control-probe-timeout');self.peers.tick(.02)
            stdout,stderr=process.communicate(timeout=1)
            require(process.returncode==0 and len(stdout)<=65536,'lab-control-probe-failed')
            return json.loads(stdout)
        finally:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait();process.stdout.close();process.stderr.close()
    def close(self):
        if self.closed:return
        self.closed=True;self.stop();self.peers.close()
        for role in ('target','canary','uefi_vars'):
            fd=self.handles.pop(role+'_copy',None)
            if fd is not None:os.close(fd)


def probe_report(raw):
    """Expose conventional command views *derived from actual wire replies*."""
    def command(value):
        require(type(value) is dict,'lab-probe-observation')
        error=value.get('error');success=error is None and value.get('connected') is True and value.get('response_nonce')==value.get('nonce')
        code=0 if success else 28 if error=='timeout' else 7 if error=='connection-refused' else 1
        return {'returncode':code,'stdout':value['response_nonce'] if success else '', 'stderr':error or ''}
    if 'admin_checks' in raw:
        for check in raw['admin_checks']:
            check['source_control']=command(check['source_control'])
        return raw
    result={**raw,'attempt':command(raw)}
    for key in ('source_control','destination_control'):
        if key in raw:result[key]=command(raw[key])
    if raw.get('protocol')=='https':result['tls']={'verify_returncode':0 if raw.get('certificate_valid') is True else 1,
                                                'peer_certificate_sha256':raw.get('certificate_sha256')}
    return result


class NamespaceWorker:
    """A private worker process creates namespaces; parent never enters them."""
    synthetic=False
    def __init__(self,config,context,run,handles):
        self.launched=False;self.closed=False;self.buffer=bytearray();self.run=Path(run)
        self.timeout=config['acceptance']['case_timeout_seconds'];self.deadline=time.monotonic()+self.timeout
        from .lab_runner import _open_regular,_hash_fd
        from .installer.payload import _allowed
        handles=dict(handles);config=dict(config);source_descriptors=[];opened=[]
        try:
            for name,pin in config['acceptance']['tools'].items():
                fd=_open_regular(pin['path'],trusted=True,maximum=256*1024*1024);opened.append(fd)
                require(_hash_fd(fd)==pin['sha256'],'lab-tool-pin-changed');handles['tool_'+name]=fd
            package=Path(__file__).parent
            for path in sorted(package.rglob('*')):
                relative=path.relative_to(package)
                if any(part.startswith('.') or part=='__pycache__' for part in relative.parts) or not path.is_file() or not _allowed(relative.as_posix()):continue
                fd=_open_regular(path,trusted=True,maximum=2*1024*1024);opened.append(fd)
                source_descriptors.append({'fd':fd,'path':'appliance/'+relative.as_posix(),'size_bytes':os.fstat(fd).st_size})
            config['_source_descriptors']=source_descriptors
            readfd,writefd=os.pipe()
        except BaseException:
            for fd in opened:os.close(fd)
            raise
        inherited=list(handles.values())+[readfd]+[item['fd'] for item in source_descriptors]
        try:
            self.diagnostics=self.run.joinpath('worker.log').open('xb');os.chmod(self.diagnostics.name,0o600)
            self.process=subprocess.Popen([sys.executable,'-m','appliance.lab_driver','--worker',str(readfd)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.diagnostics,close_fds=True,pass_fds=tuple(inherited),
                start_new_session=True,cwd=Path(__file__).resolve().parent.parent,umask=0o077,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','PYTHONNOUSERSITE':'1',
                     'PYTHONPATH':str(Path(__file__).resolve().parent.parent),'HOME':str(self.run)})
        except BaseException:
            os.close(writefd)
            if hasattr(self,'diagnostics'):self.diagnostics.close()
            raise
        finally:
            os.close(readfd)
            for opened_fd in opened:os.close(opened_fd)
        try:
            raw=canonical({'config':config,'context':context,'run':str(run),'handles':handles})
            require(len(raw)<=MAX_FRAME,'lab-worker-config-limit')
            with os.fdopen(writefd,'wb') as stream:stream.write(raw)
            self.selector=selectors.DefaultSelector();os.set_blocking(self.process.stdout.fileno(),False)
            self.selector.register(self.process.stdout,selectors.EVENT_READ)
            ready=self._read(min(60,self.deadline-time.monotonic()));require(ready.get('state')=='namespace-ready','lab-namespace-worker-unavailable')
            self.namespace=ready['namespace']
        except BaseException:self.close();raise
    def _read(self,timeout):
        deadline=time.monotonic()+timeout
        while True:
            if b'\n' in self.buffer:
                raw,_,remaining=self.buffer.partition(b'\n');self.buffer=bytearray(remaining)
                try:value=json.loads(raw)
                except (ValueError,UnicodeError):raise ApplianceError('lab-worker-protocol') from None
                require(type(value) is dict,'lab-worker-protocol')
                if value=={'event':'qemu-started'}:
                    self.launched=True;continue
                if 'error' in value:raise ApplianceError(value['error'])
                return value
            require(time.monotonic()<deadline,'lab-worker-timeout')
            for key,_ in self.selector.select(min(1,max(0,deadline-time.monotonic()))):
                raw=os.read(key.fd,65536);require(raw,'lab-worker-exited')
                self.buffer.extend(raw);require(len(self.buffer)<=8*MAX_FRAME,'lab-worker-output-limit')
            require(self.process.poll() is None,'lab-worker-exited')
    def execute_action(self,action,parameters):
        require(not self.closed and action in ACTIONS,'lab-worker-action')
        require(time.monotonic()<self.deadline,'lab-case-timeout')
        raw=canonical({'action':action,'parameters':parameters})+b'\n'
        require(len(raw)<MAX_FRAME,'lab-worker-input-limit')
        self.process.stdin.write(raw);self.process.stdin.flush()
        value=self._read(self.deadline-time.monotonic())
        self.launched=self.launched or value.pop('qemu_started',False)
        return value
    def close(self):
        if self.closed:return {'termination':'already-closed'}
        self.closed=True;result={'termination':'exited'}
        if hasattr(self,'process'):
            try:
                if self.process.poll() is None:
                    self.process.stdin.close()
                    try:self.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        result['termination']='terminated';os.killpg(self.process.pid,signal.SIGTERM)
                        try:self.process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            result['termination']='killed';os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=5)
                result['returncode']=self.process.returncode
            finally:
                if not self.process.stdin.closed:self.process.stdin.close()
                self.process.stdout.close()
        if hasattr(self,'selector'):self.selector.close()
        if hasattr(self,'diagnostics'):self.diagnostics.close()
        require(result.get('returncode',0)==0,'lab-worker-cleanup-failed')
        return result


def _worker(fd):
    # Install parent-death behavior before accepting any input. This worker and
    # its QEMU child are both bounded even after an abruptly killed caller.
    libc=ctypes.CDLL(None,use_errno=True);parent=os.getppid()
    require(libc.prctl(1,signal.SIGKILL,0,0,0)==0 and os.getppid()==parent,'lab-parent-death-signal-unavailable')
    with os.fdopen(fd,'rb') as stream:raw=stream.read(MAX_FRAME+1)
    require(len(raw)<=MAX_FRAME,'lab-worker-config-limit');initial=json.loads(raw)
    from .lab_runner import source_identity
    require(source_identity()==initial['context']['source_id'],'lab-worker-source-changed')
    namespace=enter_namespace();driver=None
    try:
        driver=DisposableDriver(initial['config'],initial['context'],initial['run'],initial['handles'],namespace=namespace)
        driver.on_launch=lambda:print('{"event":"qemu-started"}',flush=True)
        print(json.dumps({'state':'namespace-ready','namespace':namespace}),flush=True)
        while line:=sys.stdin.buffer.readline(MAX_FRAME+1):
            require(line.endswith(b'\n') and len(line)<=MAX_FRAME,'lab-worker-input-limit')
            value=json.loads(line)
            result=driver.execute_action(value['action'],value['parameters'])
            result['qemu_started']=driver.console is not None
            print(canonical(result).decode(),flush=True)
    finally:
        if driver:driver.close()


if __name__=='__main__':
    try:
        require(len(sys.argv)==3 and sys.argv[1]=='--worker' and sys.argv[2].isdigit(),'lab-worker-entry')
        _worker(int(sys.argv[2]))
    except (ApplianceError,OSError,ValueError,KeyError) as error:
        print(json.dumps({'error':error.code if isinstance(error,ApplianceError) else 'lab-worker-failed'}),flush=True)
        raise SystemExit(2)
