"""Synthetic byte fixtures; these do not qualify a release or boot vendor media."""
import bz2
import hashlib
import io
import os
from pathlib import Path

import pytest

from appliance.contracts import ApplianceError
from appliance import media


PAYLOAD = b"synthetic installer bytes\n"


def component(payload=PAYLOAD):
    return {"id": "router", "version": "test", "url": "https://vendor.example/router.iso",
            "sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload),
            "max_bytes": len(payload), "test_only": True,
            "provenance": {"kind": "official-checksum", "url": "https://vendor.example/SHA256SUMS"}}


def checksum(record):
    return (record["sha256"] + "  " + record.get("filename", "router.iso") + "\n").encode()


def network(monkeypatch, record, payload=PAYLOAD, document=None):
    document = checksum(record) if document is None else document
    def open_url(url):
        return io.BytesIO(document if url == record["provenance"]["url"] else payload)
    monkeypatch.setattr(media, "_open_https", open_url)


def test_integrity_receipt_and_tamper_detection(tmp_path):
    path = tmp_path / "input.iso"
    path.write_bytes(PAYLOAD)
    record = component()
    assert media.verify_file(path, record) == {"sha256": hashlib.sha256(PAYLOAD).hexdigest(), "size_bytes": len(PAYLOAD)}
    path.write_bytes(b"x" * len(PAYLOAD))
    with pytest.raises(ApplianceError, match="media-digest"):
        media.verify_file(path, record)


@pytest.mark.parametrize("payload", [PAYLOAD[:-1], PAYLOAD + b"extra"])
def test_wrong_size_never_verifies(tmp_path, payload):
    path = tmp_path / "input.iso"
    path.write_bytes(payload)
    with pytest.raises(ApplianceError):
        media.verify_file(path, component())


def test_verify_rejects_symlink_and_fifo_without_blocking(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(PAYLOAD)
    link = tmp_path / "link"
    link.symlink_to(target)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for path in (link, fifo):
        with pytest.raises(ApplianceError):
            media.verify_file(path, component())


def test_prepare_publishes_private_bytes_and_reuses_verified_cache_offline(tmp_path, monkeypatch):
    record = component()
    network(monkeypatch, record)
    cache = tmp_path / "cache"
    result = media.prepare_component(record, cache)
    assert result.read_bytes() == PAYLOAD
    assert result.stat().st_mode & 0o777 == 0o600
    assert cache.stat().st_mode & 0o777 == 0o700
    def offline(_):
        raise AssertionError("Verified cache must work without network")
    monkeypatch.setattr(media, "_open_https", offline)
    assert media.prepare_component(record, cache) == result
    result.write_bytes(b"x" * len(PAYLOAD))
    with pytest.raises(ApplianceError, match="media-digest"):
        media.prepare_component(record, cache)


@pytest.mark.parametrize("document", [b"not a checksum\n", b"0" * 64 + b"  router.iso\n",
                                       hashlib.sha256(PAYLOAD).hexdigest().encode() + b"  another.iso\n"])
def test_unmatched_provenance_prevents_artifact_publication(tmp_path, monkeypatch, document):
    record = component()
    network(monkeypatch, record, document=document)
    cache = tmp_path / "cache"
    with pytest.raises(ApplianceError, match="media-provenance"):
        media.prepare_component(record, cache)
    assert not any(p.read_bytes() == PAYLOAD for p in cache.iterdir() if p.is_file())


def test_checksum_document_pin_and_explicit_filename(tmp_path, monkeypatch):
    record = component()
    record["filename"] = "router-release.iso"
    document = ("SHA256 (router-release.iso) = " + record["sha256"] + "\n").encode()
    record["provenance"]["sha256"] = hashlib.sha256(document).hexdigest()
    network(monkeypatch, record, document=document)
    assert media.prepare_component(record, tmp_path / "good").read_bytes() == PAYLOAD
    record["provenance"]["sha256"] = "0" * 64
    with pytest.raises(ApplianceError, match="media-provenance"):
        media.prepare_component(record, tmp_path / "bad")


@pytest.mark.parametrize("payload", [PAYLOAD[:-1], PAYLOAD + b"extra", b"x" * len(PAYLOAD)])
def test_bad_download_does_not_publish_artifact(tmp_path, monkeypatch, payload):
    record = component()
    network(monkeypatch, record, payload=payload)
    cache = tmp_path / "cache"
    with pytest.raises(ApplianceError):
        media.prepare_component(record, cache)
    assert not list(cache.glob("*.artifact"))
    assert not list(cache.glob(".partial-*"))


def test_interrupted_download_retains_no_partial_and_can_retry(tmp_path, monkeypatch):
    record = component()
    class Interrupted(io.BytesIO):
        def read(self, *args):
            raise OSError("connection lost")
    monkeypatch.setattr(media, "_open_https", lambda url: io.BytesIO(checksum(record)) if url.endswith("SUMS") else Interrupted())
    cache = tmp_path / "cache"
    with pytest.raises(ApplianceError):
        media.prepare_component(record, cache)
    assert not list(cache.glob(".partial-*"))
    network(monkeypatch, record)
    assert media.prepare_component(record, cache).read_bytes() == PAYLOAD


def test_bz2_verifies_both_compressed_and_expanded_content(tmp_path, monkeypatch):
    packed = bz2.compress(PAYLOAD)
    record = component(packed)
    record.update(compression="bz2", expanded={"sha256": hashlib.sha256(PAYLOAD).hexdigest(), "size_bytes": len(PAYLOAD), "max_bytes": len(PAYLOAD)})
    network(monkeypatch, record, payload=packed)
    result = media.prepare_component(record, tmp_path / "cache")
    assert result.read_bytes() == PAYLOAD
    result.write_bytes(b"x" * len(PAYLOAD))
    with pytest.raises(ApplianceError, match="media-digest"):
        media.prepare_component(record, tmp_path / "cache")


@pytest.mark.parametrize("fault", ["expansion", "digest", "truncated", "trailing"])
def test_bad_bz2_never_publishes_expanded_file(tmp_path, monkeypatch, fault):
    packed = bz2.compress(PAYLOAD)
    if fault == "truncated":
        packed = packed[:-5]
    if fault == "trailing":
        packed += b"garbage"
    record = component(packed)
    record.update(compression="bz2", expanded={"sha256": hashlib.sha256(PAYLOAD).hexdigest(), "size_bytes": len(PAYLOAD), "max_bytes": len(PAYLOAD)})
    if fault == "expansion":
        record["expanded"].update(size_bytes=4, max_bytes=4)
    if fault == "digest":
        record["expanded"]["sha256"] = "0" * 64
    network(monkeypatch, record, payload=packed)
    cache = tmp_path / "cache"
    with pytest.raises(ApplianceError):
        media.prepare_component(record, cache)
    assert not list(cache.glob("*.expanded"))


@pytest.mark.parametrize("kind", ["symlink", "public", "parent-symlink"])
def test_unsafe_cache_rejected_before_network(tmp_path, monkeypatch, kind):
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    cache = tmp_path / "cache"
    if kind == "public":
        cache.mkdir(mode=0o755)
    elif kind == "symlink":
        cache.symlink_to(actual, target_is_directory=True)
    else:
        link = tmp_path / "link"
        link.symlink_to(actual, target_is_directory=True)
        cache = link / "cache"
    monkeypatch.setattr(media, "_open_https", lambda _: pytest.fail("Unsafe cache must not download"))
    with pytest.raises(ApplianceError):
        media.prepare_component(component(), cache)


@pytest.mark.parametrize("change", [{"id": "../outside"}, {"url": "http://vendor.example/router.iso"},
                                      {"url": "https://user:secret@vendor.example/router.iso"},
                                      {"sha256": "bad"}, {"max_bytes": 1}, {"size_bytes": True},
                                      {"unexpected": 1}, {"compression": "zip"},
                                      {"filename": "../router.iso"},
                                      {"provenance": {"kind": "signature", "key": "untrusted"}}])
def test_invalid_contract_rejected_before_cache_creation(tmp_path, monkeypatch, change):
    record = component()
    record.update(change)
    monkeypatch.setattr(media, "_open_https", lambda _: pytest.fail("Invalid contract must not download"))
    cache = tmp_path / "cache"
    with pytest.raises(ApplianceError):
        media.prepare_component(record, cache)
    assert not cache.exists()


def test_checksum_document_has_a_size_bound(tmp_path, monkeypatch):
    record = component()
    network(monkeypatch, record, document=b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ApplianceError):
        media.prepare_component(record, tmp_path / "cache")


@pytest.mark.parametrize("kind", ["symlink", "public", "hardlink"])
def test_cached_artifact_cannot_point_outside_private_owned_inode(tmp_path, monkeypatch, kind):
    record = component()
    network(monkeypatch, record)
    cache = tmp_path / "cache"
    prepared = media.prepare_component(record, cache)
    if kind == "public":
        prepared.chmod(0o644)
    else:
        external = tmp_path / "external"
        external.write_bytes(PAYLOAD)
        external.chmod(0o600)
        prepared.unlink()
        if kind == "symlink":
            prepared.symlink_to(external)
        else:
            os.link(external, prepared)
    with pytest.raises(ApplianceError):
        media.prepare_component(record, cache)


def test_new_release_can_reuse_cache_when_vendor_updates_checksum_document(tmp_path, monkeypatch):
    record = component()
    network(monkeypatch, record)
    cache = tmp_path / "cache"
    first = media.prepare_component(record, cache)
    updated = component(b"new synthetic release")
    updated["version"] = "test-two"
    network(monkeypatch, updated, payload=b"new synthetic release")
    second = media.prepare_component(updated, cache)
    assert second.read_bytes() == b"new synthetic release"
    assert first.read_bytes() == PAYLOAD


@pytest.mark.parametrize("response_url,status,encoding", [
    ("https://other.example/router.iso", 200, "identity"),
    ("https://vendor.example/router.iso", 302, "identity"),
    ("https://vendor.example/router.iso", 200, "gzip"),
])
def test_transport_rejects_changed_origin_redirect_or_encoded_response(monkeypatch, response_url, status, encoding):
    class Response(io.BytesIO):
        def geturl(self):
            return response_url
    response = Response(PAYLOAD)
    response.status = status
    response.headers = {"Content-Encoding": encoding}
    class Transport:
        def open(self, *_args, **_kwargs):
            return response
    monkeypatch.setattr(media.urllib.request, "build_opener", lambda *_: Transport())
    with pytest.raises(ApplianceError, match="media-response"):
        media._open_https("https://vendor.example/router.iso")
    assert response.closed


RESTIC_URL = "https://github.com/restic/restic/releases/download/v0.18.1/restic_0.18.1_linux_amd64.bz2"
ASSET_URL = "https://release-assets.githubusercontent.com/github-production-release-asset/42/asset?sig=PRIVATE_QUERY"


def test_restic_release_redirect_allows_one_exact_https_asset_hop():
    policy = media._ArtifactRedirect(RESTIC_URL)
    request = media.urllib.request.Request(RESTIC_URL, headers={"Authorization": "PRIVATE_HEADER"})
    redirected = policy.redirect_request(request, None, 302, "Found", {}, ASSET_URL)
    assert redirected is not None and redirected.full_url == ASSET_URL
    assert redirected.get_header("Authorization") is None
    assert policy.redirect_request(redirected, None, 302, "Found", {}, ASSET_URL + "&next=1") is None


@pytest.mark.parametrize("source,destination", [
    (RESTIC_URL, "http://release-assets.githubusercontent.com/file"),
    (RESTIC_URL, "https://release-assets.githubusercontent.com.evil.example/file"),
    (RESTIC_URL, "https://user:secret@release-assets.githubusercontent.com/file"),
    (RESTIC_URL, "https://@release-assets.githubusercontent.com/file"),
    (RESTIC_URL, "https://release-assets.githubusercontent.com:8443/file"),
    (RESTIC_URL, "https://github.com/restic/restic/releases/download/v0.18.1/other"),
    ("https://github.com/other/restic/releases/download/v0.18.1/file", ASSET_URL),
    ("https://github.com/restic/restic/archive/refs/tags/v0.18.1", ASSET_URL),
    ("https://github.com/restic/restic/releases/download/../file", ASSET_URL),
    ("http://github.com/restic/restic/releases/download/v0.18.1/file", ASSET_URL),
    ("https://vendor.example/router.iso", ASSET_URL),
    ("https://vendor.example/router.iso", "https://vendor.example/other.iso"),
])
def test_unqualified_redirect_routes_remain_denied(source, destination):
    policy = media._ArtifactRedirect(source)
    request = media.urllib.request.Request(source)
    assert policy.redirect_request(request, None, 302, "Found", {}, destination) is None


@pytest.mark.parametrize("final_url,accepted", [(ASSET_URL, True), (ASSET_URL + "&changed=1", False), (RESTIC_URL, False)])
def test_response_must_match_the_actual_permitted_redirect(monkeypatch, final_url, accepted):
    class Response(io.BytesIO):
        status = 200
        headers = {}
        def geturl(self):
            return final_url
    response = Response(PAYLOAD)
    def build(*handlers):
        policy = next(handler for handler in handlers if isinstance(handler, media._ArtifactRedirect))
        class Transport:
            def open(self, request, **_kwargs):
                redirected = policy.redirect_request(request, None, 302, "Found", {}, ASSET_URL)
                assert redirected is not None
                return response
        return Transport()
    monkeypatch.setattr(media.urllib.request, "build_opener", build)
    if accepted:
        with media._open_https(RESTIC_URL) as stream:
            assert stream.read() == PAYLOAD
    else:
        with pytest.raises(ApplianceError) as error:
            media._open_https(RESTIC_URL)
        assert "PRIVATE_QUERY" not in str(error.value)
        assert response.closed


def test_redirected_download_still_requires_locked_artifact_hash(tmp_path, monkeypatch):
    record = component()
    record.update(url=RESTIC_URL, filename="restic_0.18.1_linux_amd64.bz2")
    record["provenance"]["url"] = "https://github.com/restic/restic/releases/download/v0.18.1/SHA256SUMS"
    class Response(io.BytesIO):
        status = 200
        headers = {}
        def geturl(self):
            return ASSET_URL
    def build(*handlers):
        policy = next(handler for handler in handlers if isinstance(handler, media._ArtifactRedirect))
        class Transport:
            def open(self, request, **_kwargs):
                assert policy.redirect_request(request, None, 302, "Found", {}, ASSET_URL) is not None
                return Response(checksum(record) if request.full_url.endswith("SUMS") else b"x" * len(PAYLOAD))
        return Transport()
    monkeypatch.setattr(media.urllib.request, "build_opener", build)
    with pytest.raises(ApplianceError, match="media-digest"):
        media.prepare_component(record, tmp_path / "cache")
    assert not list((tmp_path / "cache").glob("*.artifact"))
