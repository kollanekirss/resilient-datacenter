"""OPNsense 26.7 policy, derived from the official tagged model/inc sources.

Rendering and XML inspection are configuration evidence only. Packet behavior,
installer import and firmware persistence still require the documented guest lab.
Credentials and exports are private material and must never enter public status.
"""
import base64
import hashlib
import ipaddress
import re
import uuid
import xml.etree.ElementTree as ET

from .contracts import ApplianceError, fields, identity, require
from .proxmox import vm_spec

HELPER="/conf/rdc-appliance/helper.php"
FORCED_COMMAND="/usr/local/bin/php "+HELPER
DEFAULT_HASH="$2y$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS"


def _node(parent,name,value=None,**attrs):
    item=ET.SubElement(parent,name,attrs)
    if value is not None:item.text=str(value)
    return item


def _values(parent,values):
    for key,value in values.items():_node(parent,key,value)


def _key(value):
    require(type(value) is str and re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}",value),"router-public-key")
    try:wire=base64.b64decode(value.split()[1],validate=True)
    except ValueError:raise ApplianceError("router-public-key") from None
    require(len(wire)==51 and wire[:19]==b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20","router-public-key")
    return value


def _credentials(plan,credentials):
    fields(credentials,{"root_password_hash","management_public_key","interface_map"},{"stage"})
    require(type(credentials["root_password_hash"]) is str and
            re.fullmatch(r"\$2[by]\$(?:1[2-9]|2[0-9]|3[01])\$[./A-Za-z0-9]{53}",credentials["root_password_hash"])
            and credentials["root_password_hash"]!=DEFAULT_HASH,"router-unique-password")
    _key(credentials["management_public_key"])
    mapping=credentials["interface_map"];nics=vm_spec(plan,"router")["nics"]
    require(type(mapping) is dict and set(mapping)=={n["mac"] for n in nics},"router-interface-map")
    require(all(type(v) is str and re.fullmatch(r"vtnet[0-9]{1,2}",v) for v in mapping.values())
            and len(set(mapping.values()))==len(mapping),"router-interface-map")
    require(credentials.get("stage","bootstrap") in ("bootstrap","transit"),"router-policy-stage")
    return nics


def zone_interfaces(plan):
    result={"wan":"wan","management":"lan","infrastructure":"opt1","workload":"opt2"}
    if "relay" in plan["networks"]:result["relay"]="opt3"
    return result


def authorized_key(plan,public_key):
    key=_key(public_key)
    source=str(ipaddress.IPv4Address(plan["networks"]["management"]["host_ip"]))
    return f'from="{source}",restrict,command="{FORCED_COMMAND}" {key}'


def _rule(parent,interface,action,source,destination,*,protocol="any",port=None,description=""):
    rule=_node(parent,"rule")
    _values(rule,{"type":action,"interface":interface,"ipprotocol":"inet","direction":"in","quick":"1","protocol":protocol,"descr":description})
    src=_node(rule,"source")
    if source=="any":_node(src,"any")
    else:_node(src,"address",source)
    dst=_node(rule,"destination")
    if destination=="any":_node(dst,"any")
    else:_node(dst,"address",destination)
    if port is not None:_node(dst,"port",port)
    return rule


def render_router(plan,credentials):
    nics=_credentials(plan,credentials);zones=zone_interfaces(plan);stage=credentials.get("stage","bootstrap")
    from .hosting import prerequisites
    hosting={role:stage=="transit" and plan["roles"][role]["selected"] and not prerequisites(plan,role)
             for role in ("headscale","derp")}
    doc=ET.Element("opnsense");system=_node(doc,"system")
    _values(system,{"hostname":plan["site_id"]+"-router","domain":"internal","timezone":"Etc/UTC","dnsallowoverride":"1" if plan["upstream"]["mode"]=="dhcp" else "0"})
    group=_node(system,"group");_values(group,{"name":"admins","description":"System Administrators","scope":"system","gid":"1999","member":"0","priv":"page-all"})
    user=_node(system,"user");_values(user,{"name":"root","scope":"system","groupname":"admins","uid":"0","descr":"Appliance administrator","password":credentials["root_password_hash"],
        "authorizedkeys":base64.b64encode(authorized_key(plan,credentials["management_public_key"]).encode()).decode()})
    _values(_node(system,"webgui"),{"protocol":"https","interfaces":"lan"})
    _values(_node(system,"ssh"),{"enabled":"1","permitrootlogin":"1","interfaces":"lan","noauto":"1","group":"admins"})
    # 26.7 migrated the global IPv6 switch to Interfaces/settings below.
    _node(system,"timeservers","0.opnsense.pool.ntp.org 1.opnsense.pool.ntp.org")
    for address in plan["upstream"].get("dns",[]):_node(system,"dnsserver",str(ipaddress.IPv4Address(address)))
    interfaces=_node(doc,"interfaces")
    for nic in nics:
        zone=nic["zone"];item=_node(interfaces,zones[zone]);_values(item,{"if":credentials["interface_map"][nic["mac"]],"descr":zone,"enable":"1"})
        if zone=="wan":
            if plan["upstream"]["mode"]=="dhcp":_node(item,"ipaddr","dhcp")
            else:
                address=ipaddress.IPv4Interface(plan["upstream"]["address"])
                _values(item,{"ipaddr":address.ip,"subnet":address.network.prefixlen,"gateway":"RDC_WAN"})
            if plan["upstream"]["cidrs"] and all(ipaddress.IPv4Network(c).is_global for c in plan["upstream"]["cidrs"]):_node(item,"blockpriv","1")
            _node(item,"blockbogons","1")
        else:
            network=plan["networks"][zone];_values(item,{"ipaddr":network["gateway"],"subnet":ipaddress.IPv4Network(network["cidr"]).prefixlen})
    if plan["upstream"]["mode"]=="static":
        gateway=_node(_node(doc,"gateways"),"gateway_item")
        _values(gateway,{"interface":"wan","gateway":plan["upstream"]["gateway"],"name":"RDC_WAN","ipprotocol":"inet","defaultgw":"1","monitor_disable":"1"})
    dns=_node(doc,"dnsmasq",version="1.0.9")
    guest_ifs=[zones[z] for z in ("infrastructure","workload","relay") if z in zones]
    _values(dns,{"enable":"1","port":"53","interface":",".join(["lan",*guest_ifs]),"strictbind":"1","domain_needed":"1","no_private_reverse":"1","no_ident":"1"})
    _values(_node(dns,"dhcp"),{"enable_ra":"0","default_fw_rules":"1","no_interface":",".join(["lan","opt1",*(["opt3"] if "relay" in zones else [])])})
    workload=ipaddress.IPv4Network(plan["networks"]["workload"]["cidr"])
    pool=_node(dns,"dhcp_ranges",uuid=str(uuid.uuid5(uuid.NAMESPACE_URL,identity(plan)+":pool")))
    _values(pool,{"interface":"opt2","start_addr":str(workload.network_address+1),"subnet_mask":workload.netmask,"mode":"static","lease_time":"3600"})
    for vm in plan["vms"].values():
        for nic in vm["nics"]:
            if nic["zone"]=="workload" and nic.get("address"):
                host=_node(dns,"hosts",uuid=str(uuid.uuid5(uuid.NAMESPACE_URL,identity(plan)+":"+nic["mac"])))
                _values(host,{"host":vm["name"],"domain":"internal","ip":nic["address"],"hwaddr":nic["mac"],"local":"1"})
    _values(_node(doc,"ntpd"),{"interface":",".join(["lan",*guest_ifs]),"prefer":"0.opnsense.pool.ntp.org","ispool":"0.opnsense.pool.ntp.org,1.opnsense.pool.ntp.org"})
    nat_root=_node(doc,"nat");nat=_node(nat_root,"outbound");_node(nat,"mode","advanced")
    if stage=="transit":
        for zone in ("infrastructure","workload"):
            rule=_node(nat,"rule");_values(rule,{"interface":"wan","ipprotocol":"inet","descr":"RDC NAT "+zone})
            _node(_node(rule,"source"),"network",zones[zone]);_node(_node(rule,"destination"),"any")
        rule=_node(nat,"rule");_values(rule,{"interface":"wan","ipprotocol":"inet","descr":"RDC host updates"})
        _node(_node(rule,"source"),"address",plan["networks"]["management"]["host_ip"]+"/32")
        _node(_node(rule,"destination"),"any")
    filters=_node(doc,"filter")
    if stage=="transit":
        # Failed optional hosting prerequisites withhold only those public
        # rules; local management and joining must keep their own transit.
        if hosting["headscale"]:
            address=plan["vms"]["headscale"]["nics"][0]["address"]
            # 26.7's DNat model remains mounted at /nat/rule+. Use its
            # current manual-pass field and disable implicit reflection.
            rule=_node(nat_root,"rule",uuid=str(uuid.uuid5(uuid.NAMESPACE_URL,identity(plan)+":headscale-dnat")))
            _values(rule,{"sequence":"1","interface":"wan","ipprotocol":"inet","protocol":"tcp",
                          "target":address,"local-port":"443","natreflection":"disable",
                          "descr":"RDC Headscale HTTPS"})
            _node(_node(rule,"source"),"network","any")
            destination=_node(rule,"destination");_values(destination,{"network":"wanip","port":"443"})
            _node(rule,"pass")
            _rule(filters,"wan","pass","any",address,protocol="tcp",port=443,description="RDC Headscale HTTPS")
        if hosting["derp"]:
            address=plan["roles"]["derp"]["public_ipv4"]
            for protocol,port in (("tcp",443),("tcp",80),("udp",3478)):
                _rule(filters,"wan","pass","any",address,protocol=protocol,port=port,description="RDC routed relay")
            for kind in ("echoreq","unreach","timex"):
                rule=_rule(filters,"wan","pass","any",address,protocol="icmp",description="RDC relay ICMP")
                _node(rule,"icmptype",kind)
    mgmt=plan["networks"]["management"]
    for address in (mgmt["host_ip"],mgmt["admin_ip"]):
        for port in (22,443):_rule(filters,"lan","pass",address,mgmt["gateway"],protocol="tcp",port=port,description="RDC administration")
    protected=[network["cidr"] for network in plan["networks"].values()]+plan["overlay_cidrs"]
    for zone in ("management","infrastructure","workload","relay"):
        if zone not in zones:continue
        network=plan["networks"][zone];interface=zones[zone]
        for protocol,port in (("tcp",53),("udp",53),("udp",123)):
            _rule(filters,interface,"pass",network["cidr"],network["gateway"],protocol=protocol,port=port,description="RDC local DNS/time")
        if hosting["derp"] and zone=="relay":
            from .derp import derp_config
            binding=derp_config(plan)["verifier_host_binding"]
            if binding:
                _rule(filters,interface,"pass",plan["roles"]["derp"]["public_ipv4"],binding["address"],
                      protocol="tcp",port=443,description="RDC relay controller verification")
        for cidr in protected:_rule(filters,interface,"block",network["cidr"],cidr,description="RDC zone isolation")
        if stage=="transit" and zone=="management":
            for port in (80,443):
                _rule(filters,interface,"pass",mgmt["host_ip"],"any",protocol="tcp",port=port,description="RDC host updates")
        if stage=="transit" and zone in ("infrastructure","workload"):
            _rule(filters,interface,"pass",network["cidr"],"any",protocol="tcp",port=443,description="RDC HTTPS updates")
        if stage=="transit" and zone=="infrastructure" and plan["roles"]["connector"]["selected"]:
            address=plan["vms"]["connector"]["nics"][0]["address"]
            for port in (3478,41641):
                _rule(filters,interface,"pass",address,"any",protocol="udp",port=port,description="RDC connector transport")
        if hosting["derp"] and zone=="relay":
            _rule(filters,interface,"pass",plan["roles"]["derp"]["public_ipv4"],"any",protocol="tcp",port=443,
                  description="RDC relay HTTPS verification and updates")
        _rule(filters,interface,"block",network["cidr"],"any",description="RDC default deny")
    model=_node(doc,"OPNsense");settings=_node(_node(model,"Interfaces"),"settings",version="1.0.0")
    _values(settings,{"disablechecksumoffloading":"1","disablesegmentationoffloading":"1","disablelargereceiveoffloading":"1","disableipv6":"1"})
    unbound=_node(model,"unboundplus",version="1.0.15");_node(_node(unbound,"general"),"enabled","0")
    marker=_node(doc,"rdcappliance");_values(marker,{"schema":"1","plan_id":identity(plan),"stage":stage})
    ET.indent(doc,space="  ")
    return ET.tostring(doc,encoding="utf-8",xml_declaration=True)+b"\n"


def parse_xml(xml):
    require(type(xml) is bytes and 0<len(xml)<=524288 and b"<!" not in xml,"router-xml")
    try:doc=ET.fromstring(xml)
    except ET.ParseError:raise ApplianceError("router-xml") from None
    require(doc.tag=="opnsense","router-xml")
    return doc


def _tree(node):
    if node is None:return None
    return (node.tag,(node.text or "").strip(),tuple(sorted(node.attrib.items())),tuple(_tree(n) for n in node))


def audit_router(plan,config_xml,runtime):
    problems=[]
    if type(runtime) is not dict:return ["router-observation"]
    try:doc=parse_xml(config_xml)
    except ApplianceError:return ["router-xml"]
    try:
        encoded=doc.findtext("system/user/authorizedkeys","")
        line=base64.b64decode(encoded,validate=True).decode()
        public="ssh-ed25519 "+line.rsplit("ssh-ed25519 ",1)[1]
        require(line==authorized_key(plan,public),"router-authorized-key")
        credentials={"root_password_hash":doc.findtext("system/user/password"),"management_public_key":public,
            "interface_map":runtime.get("interface_map"),"stage":runtime.get("stage")}
        expected=ET.fromstring(render_router(plan,credentials))
        # OPNsense creates a TLS certificate on first HTTPS boot and persists
        # its reference under webgui. Accept only a single backed PEM reference;
        # listener policy and every other managed system value still compare.
        references=doc.findall("system/webgui/ssl-certref")
        if len(references)==1:
            reference=references[0].text or ""
            matches=[cert for cert in doc.findall("cert") if cert.findtext("refid")==reference]
            if re.fullmatch(r"[A-Za-z0-9_-]{1,64}",reference) and len(matches)==1 and len(matches[0].findall("crt"))==1:
                try:
                    pem=base64.b64decode(matches[0].findtext("crt", ""),validate=True).decode("ascii")
                    match=re.fullmatch(r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\r\n]+)\n-----END CERTIFICATE-----\s*",pem)
                    der=base64.b64decode("".join(match[1].split()),validate=True) if match else b""
                    if 128<=len(der)<=65536 and der[:1]==b"\x30":
                        _node(expected.find("system/webgui"),"ssl-certref",reference)
                except (ValueError,UnicodeError):pass
        # The pinned community release's firmware/register.php sync adds only
        # empty plugins/type metadata when no optional plugins are selected.
        firmware=doc.findall("system/firmware")
        if len(firmware)==1:
            empty=ET.Element("firmware");_node(empty,"plugins");_node(empty,"type")
            if _tree(firmware[0])==_tree(empty):expected.find("system").append(empty)
        # Compare every managed subtree, including default deny and service binds.
        for node in expected:
            if len(doc.findall(node.tag))!=1 or _tree(doc.find(node.tag))!=_tree(node):problems.append("router-config-"+node.tag)
        allowed={n.tag for n in expected}|{"revision","lastchange","version","cert","ca","syslog"}
        if any(n.tag not in allowed for n in doc):problems.append("router-unmanaged-config")
    except (ApplianceError,ValueError,UnicodeError,IndexError,TypeError):problems.append("router-config-binding")
    checks={"router-plan":runtime.get("plan_id")==identity(plan),
        "router-digest":runtime.get("config_digest")==hashlib.sha256(config_xml).hexdigest(),
        "router-installed-disk":runtime.get("root_kind")=="installed-disk" and bool(runtime.get("root_device")),
        "router-version":runtime.get("os_version")=="26.7",
        "router-ipv6":runtime.get("ipv6_enabled") is False and runtime.get("ra_interfaces")==[],
        "router-dhcp":runtime.get("dhcp_interfaces")==["opt2"],
        "router-ssh":runtime.get("ssh_restricted") is True,
        "router-guard":runtime.get("guard_installed") is True and (runtime.get("stage")!="bootstrap" or runtime.get("guard_blocking") is True),
        "router-running-rules":all(type(runtime.get(key)) is str and bool(re.fullmatch(r"[0-9a-f]{64}",runtime[key])) for key in ("rules_id","nat_id"))}
    problems.extend(name for name,ok in checks.items() if not ok)
    listeners=runtime.get("listeners")
    if not isinstance(listeners,list):problems.append("router-listeners")
    else:
        admin={plan["networks"]["management"]["gateway"],"127.0.0.1","::1"}
        if any(type(item) is not dict or (item.get("port") in (22,80,443) and item.get("address") not in admin) for item in listeners):problems.append("router-admin-listener")
        if not any(item.get("address")==plan["networks"]["management"]["gateway"] and item.get("port")==22 for item in listeners if isinstance(item,dict)):problems.append("router-ssh-listener")
    return sorted(set(problems))
