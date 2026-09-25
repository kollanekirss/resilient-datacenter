"""Internal DNS/TCP/TLS worker; the parent enforces an overall deadline."""
import argparse
import json
import socket
import ssl
import time
from operation_results import check
from validate_inventory import hostname as valid_hostname


def probe_controller(hostname: str, *, context=None):
    if not valid_hostname(hostname):
        return [check('manifest.invalid','fail')]
    try:
        addresses=socket.getaddrinfo(hostname,443,type=socket.SOCK_STREAM)
    except OSError:
        return [check('dns.resolve','fail')]
    if not addresses:
        return [check('dns.resolve','fail')]
    results=[check('dns.resolve','pass')]
    context=context or ssl.create_default_context()
    connected=False
    for family,kind,proto,_,address in addresses[:3]:
        try:
            with socket.socket(family,kind,proto) as raw:
                raw.settimeout(3)
                raw.connect(address)
                connected=True
                with context.wrap_socket(raw,server_hostname=hostname) as tls:
                    certificate=tls.getpeercert()
                    results.extend([check('tcp.connect','pass'),check('tls.verify','pass')])
                    expiry=certificate.get('notAfter')
                    if expiry:
                        days=(ssl.cert_time_to_seconds(expiry)-time.time())/86400
                        results.append(check('tls.expiry','pass' if days>14 else 'fail'))
                    else:
                        results.append(check('tls.expiry','unknown'))
                    return results
        except ssl.SSLCertVerificationError as error:
            # OpenSSL's structured expiration code; all other trust failures stay generic.
            results.extend([check('tcp.connect','pass'),check('tls.verify','fail')])
            if error.verify_code==10:
                results.append(check('tls.expiry','fail'))
            return results
        except (OSError,ValueError):
            continue
    return [*results,check('tcp.connect','pass' if connected else 'fail'),
            *([check('tls.verify','unknown')] if connected else [])]


def main():
    parser=argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--hostname',required=True)
    args=parser.parse_args()
    try:
        checks=probe_controller(args.hostname)
    except Exception:
        checks=[check('probe.unavailable','unknown')]
    print(json.dumps([{'code':c.code,'outcome':c.outcome} for c in checks]))


if __name__=='__main__': main()
