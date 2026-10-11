"""Release-specific configuration contracts; not guest qualification."""
import base64
import copy
import hashlib
import xml.etree.ElementTree as ET

import pytest

from appliance.contracts import ApplianceError, identity
from appliance.router_config import render_router, audit_router


def credentials(site):
    wire=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+bytes(range(32))
    return {"root_password_hash":"$2y$12$"+"x"*53,
            "management_public_key":"ssh-ed25519 "+base64.b64encode(wire).decode(),
            "interface_map":{nic["mac"]:"vtnet"+str(7-i) for i,nic in enumerate(site["vms"]["router"]["nics"])}}


def runtime(site,xml,creds):
    return {"schema":1,"plan_id":identity(site),"vmid":101,"vm_boot_id":"host-boot", "boot_id":"guest-boot",
            "config_digest":hashlib.sha256(xml).hexdigest(),"root_kind":"installed-disk","root_device":"/dev/gpt/rootfs",
            "os_version":"26.7","interface_map":creds["interface_map"],"stage":"bootstrap",
            "listeners":[{"address":"10.77.0.1","port":22,"protocol":"tcp"},{"address":"10.77.0.1","port":443,"protocol":"tcp"}],
            "dhcp_interfaces":["opt2"],"ra_interfaces":[],"ipv6_enabled":False,"ssh_restricted":True,
            "guard_installed":True,"guard_blocking":True,"rules_id":"a"*64,"nat_id":"b"*64,
            "upstream":{"cidrs":[],"gateway":None},"packet_tests":"not-performed"}


def test_render_uses_observed_mac_mapping_and_is_deterministic(site):
    creds=credentials(site);xml=render_router(site,creds);doc=ET.fromstring(xml)
    assert xml==render_router(site,creds)
    assert doc.findtext("interfaces/lan/if")==creds["interface_map"][site["vms"]["router"]["nics"][0]["mac"]]
    assert doc.findtext("interfaces/wan/if")==creds["interface_map"][site["vms"]["router"]["nics"][1]["mac"]]
    assert doc.findtext("system/webgui/interfaces")=="lan"
    assert doc.findtext("OPNsense/Interfaces/settings/disableipv6")=="1"
    assert doc.find("system/webgui/noantilockout") is None
    assert doc.findtext("dnsmasq/dhcp_ranges/interface")=="opt2"
    assert not doc.findall("nat/outbound/rule")
    assert audit_router(site,xml,runtime(site,xml,creds))==[]


@pytest.mark.parametrize("fault",["mapping","password","key","extra-credential"])
def test_unbound_or_default_credentials_are_rejected(site,fault):
    creds=credentials(site)
    if fault=="mapping":creds["interface_map"][next(iter(creds["interface_map"]))]="vtnet6"
    if fault=="password":creds["root_password_hash"]="opnsense"
    if fault=="key":creds["management_public_key"]="ssh-ed25519 fake"
    if fault=="extra-credential":creds["root_password"]="secret"
    with pytest.raises(ApplianceError):render_router(site,creds)


@pytest.mark.parametrize("fault",["broad-lan","dhcp","ra","ipv6","listener","digest","live-root","ssh","guard"])
def test_audit_refuses_unsafe_configuration_and_runtime(site,fault):
    creds=credentials(site);xml=render_router(site,creds);doc=ET.fromstring(xml);rt=runtime(site,xml,creds)
    if fault=="broad-lan":ET.SubElement(doc.find("filter"),"rule").append(ET.Element("any"))
    if fault=="dhcp":doc.find("dnsmasq/dhcp_ranges/interface").text="lan"
    if fault=="ra":rt["ra_interfaces"]=["lan"]
    if fault=="ipv6":ET.SubElement(doc.find("system"),"ipv6allow").text="1"
    if fault=="listener":rt["listeners"].append({"address":"0.0.0.0","port":443,"protocol":"tcp"})
    if fault=="live-root":rt["root_kind"]="live-iso"
    if fault=="ssh":rt["ssh_restricted"]=False
    if fault=="guard":rt["guard_installed"]=False
    xml=ET.tostring(doc);rt["config_digest"]=hashlib.sha256(xml).hexdigest()
    if fault=="digest":rt["config_digest"]="0"*64
    assert audit_router(site,xml,rt)


def test_transit_has_explicit_cross_zone_blocks_and_narrow_host_updates(site):
    creds=credentials(site);creds["stage"]="transit"
    doc=ET.fromstring(render_router(site,creds))
    rules=doc.findall("filter/rule")
    assert any(r.findtext("type")=="block" and r.findtext("destination/address")=="10.77.0.0/24" for r in rules)
    nat=doc.findall("nat/outbound/rule")
    assert {r.findtext("source/network") for r in nat if r.find("source/network") is not None}=={"opt1","opt2"}
    assert [r.findtext("source/address") for r in nat if r.find("source/address") is not None]==["10.77.0.2/32"]
    host_updates=[r for r in rules if r.findtext("type")=="pass" and r.findtext("interface")=="lan"
                  and r.find("destination/any") is not None]
    assert {(r.findtext("source/address"),r.findtext("protocol"),r.findtext("destination/port"))
            for r in host_updates}=={("10.77.0.2","tcp","80"),("10.77.0.2","tcp","443")}
    isolated=[i for i,r in enumerate(rules) if r.findtext("interface")=="lan" and r.findtext("descr")=="RDC zone isolation"]
    assert max(isolated)<min(rules.index(r) for r in host_updates)


def test_xml_entities_are_rejected_without_expansion(site):
    assert audit_router(site,b'<!DOCTYPE x [<!ENTITY x "xx">]><opnsense>&x;</opnsense>',{})==["router-xml"]


def test_generated_web_certificate_reference_preserves_managed_system_audit(site):
    creds=credentials(site);doc=ET.fromstring(render_router(site,creds))
    web=doc.find('system/webgui');ET.SubElement(web,'ssl-certref').text='69aa001122334'
    cert=ET.SubElement(doc,'cert');ET.SubElement(cert,'refid').text='69aa001122334'
    ET.SubElement(cert,'crt').text=base64.b64encode(b'-----BEGIN CERTIFICATE-----\n'+base64.b64encode(b'0'+b'x'*128)+b'\n-----END CERTIFICATE-----\n').decode()
    xml=ET.tostring(doc);rt=runtime(site,xml,creds)
    assert audit_router(site,xml,rt)==[]
    web.find('interfaces').text='wan'
    assert 'router-config-system' in audit_router(site,ET.tostring(doc),rt)


@pytest.mark.parametrize('fault',['missing-cert','missing-crt','duplicate-reference','duplicate-cert','invalid-pem'])
def test_web_certificate_exception_does_not_accept_unbound_or_ambiguous_references(site,fault):
    creds=credentials(site);doc=ET.fromstring(render_router(site,creds));web=doc.find('system/webgui')
    ET.SubElement(web,'ssl-certref').text='69aa001122334'
    cert=ET.SubElement(doc,'cert');ET.SubElement(cert,'refid').text='69aa001122334'
    ET.SubElement(cert,'crt').text=base64.b64encode(b'-----BEGIN CERTIFICATE-----\n'+base64.b64encode(b'0'+b'x'*128)+b'\n-----END CERTIFICATE-----\n').decode()
    if fault=='missing-cert':doc.remove(cert)
    if fault=='missing-crt':cert.remove(cert.find('crt'))
    if fault=='duplicate-reference':ET.SubElement(web,'ssl-certref').text='69aa001122334'
    if fault=='duplicate-cert':doc.append(copy.deepcopy(cert))
    if fault=='invalid-pem':cert.find('crt').text=base64.b64encode(b'not a certificate').decode()
    xml=ET.tostring(doc)
    assert 'router-config-system' in audit_router(site,xml,runtime(site,xml,creds))


def test_empty_firmware_registration_metadata_is_allowed_but_plugins_are_not(site):
    creds=credentials(site);doc=ET.fromstring(render_router(site,creds))
    firmware=ET.SubElement(doc.find('system'),'firmware')
    ET.SubElement(firmware,'plugins');ET.SubElement(firmware,'type')
    xml=ET.tostring(doc)
    assert audit_router(site,xml,runtime(site,xml,creds))==[]
    firmware.find('plugins').text='os-unknown'
    xml=ET.tostring(doc)
    assert 'router-config-system' in audit_router(site,xml,runtime(site,xml,creds))
    firmware.find('plugins').text=None;firmware.find('type').text='devel'
    xml=ET.tostring(doc)
    assert 'router-config-system' in audit_router(site,xml,runtime(site,xml,creds))
    firmware.find('type').text=None;ET.SubElement(firmware,'mirror').text='https://untrusted.example'
    xml=ET.tostring(doc)
    assert 'router-config-system' in audit_router(site,xml,runtime(site,xml,creds))
