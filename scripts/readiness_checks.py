"""Offline readiness evidence checks; recorded history is not a live exercise."""
from datetime import datetime,timedelta,timezone
import re
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509.verification import PolicyBuilder,Store,VerificationError
from portable_network import fingerprint
from offline_bundle import require


def status(state,reason,**values):return dict(state=state,reason=reason,**values)


def timestamp(value):
    require(isinstance(value,str),'Invalid time')
    moment=datetime.fromisoformat(value)
    require(moment.tzinfo is not None,'Time requires timezone')
    return moment.astimezone(timezone.utc)


def certificate(raw,key,anchors,names,now,days):
    try:
        chain=x509.load_pem_x509_certificates(raw)
        roots=x509.load_pem_x509_certificates(anchors)
        require(0<len(chain)<=12 and 0<len(roots)<=32,'Unsupported certificate set')
        leaf=chain[0];private=serialization.load_pem_private_key(key,password=None)
        def public(k):return k.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        require(public(leaf.public_key())==public(private.public_key()),'Certificate/key mismatch')
        deadline=now+timedelta(days=days)
        if leaf.not_valid_after_utc<=now:return status('expired','certificate-expired')
        if leaf.not_valid_before_utc>now:return status('invalid','certificate-not-yet-valid')
        for name in names:
            verified=PolicyBuilder().store(Store(roots)).time(now).build_server_verifier(x509.DNSName(name)).verify(leaf,chain[1:])
            if any(c.not_valid_after_utc<=deadline for c in verified):return status('expired','certificate-chain-expires-before-required-window')
            PolicyBuilder().store(Store(roots)).time(deadline).build_server_verifier(x509.DNSName(name)).verify(leaf,chain[1:])
        return status('verified','name-key-chain-and-offline-window-verified',coverage_days=days)
    except (ValueError,TypeError,VerificationError,OverflowError,UnsupportedAlgorithm):
        return status('invalid','certificate-name-key-or-chain-invalid')


def expected_owner(plan,role):
    from portable_applications import profiles
    from application_access import portable_owner
    from backup_scope import include
    if role=='chat':from service_contracts import ownership
    elif role=='files':from nextcloud_contracts import ownership
    else:raise ValueError('Unsupported backup role')
    profile=profiles(plan)[role];network=portable_owner(profile)
    return include(network,ownership(profile,network))


def backup(data,plan,role,now,hours):
    try:
        from backup_contracts import resources,binary_paths
        expected=expected_owner(plan,role);owned=resources(expected)
        require(isinstance(data,dict) and set(data)=={'schema_version','ownership','paths','captured_at','services_originally_active','binary_sha256'},'Invalid snapshot fields')
        require(type(data['schema_version']) is int and data['schema_version']==1 and data['ownership']==expected and data['paths']==list(owned.paths),'Wrong snapshot ownership or scope')
        active=data['services_originally_active'];binaries=data['binary_sha256']
        require(isinstance(active,dict) and set(active)==set(owned.services) and all(type(v) is bool for v in active.values()),'Invalid service state')
        require(isinstance(binaries,dict) and set(binaries)==set(binary_paths(expected)) and
                all(isinstance(v,str) and re.fullmatch('[a-f0-9]{64}',v) for v in binaries.values()),'Invalid binary identity')
        age=(now-timestamp(data['captured_at'])).total_seconds()
        require(age>=0,'Backup time is in the future')
        return status('stale' if age>hours*3600 else 'recorded','backup-too-old' if age>hours*3600 else 'snapshot-metadata-within-age-limit',
                      age_seconds=int(age),captured_at=timestamp(data['captured_at']).isoformat(),basis='saved-snapshot-metadata')
    except (ValueError,TypeError,KeyError,OverflowError):return status('invalid','snapshot-metadata-invalid-or-wrong-site')


def exercise(data,plan,role,metadata_sha256,now,days):
    try:
        require(isinstance(data,dict) and set(data)=={'schema_version','site_sha256','role','backup_metadata_sha256','performed_at','result'},'Invalid exercise record')
        require(type(data['schema_version']) is int and data['schema_version']==1 and data['site_sha256']==fingerprint(plan)
                and data['role']==role and data['backup_metadata_sha256']==metadata_sha256 and data['result']=='pass','Exercise does not cover selected backup or did not pass')
        age=(now-timestamp(data['performed_at'])).total_seconds();require(age>=0,'Exercise time is in the future')
        return status('stale' if age>days*86400 else 'recorded','exercise-record-too-old' if age>days*86400 else 'operator-records-successful-restoration',
                      age_seconds=int(age),performed_at=timestamp(data['performed_at']).isoformat(),basis='operator-record-not-independent-execution')
    except (ValueError,TypeError,KeyError,OverflowError):return status('invalid','exercise-record-invalid-failed-or-wrong-backup')
