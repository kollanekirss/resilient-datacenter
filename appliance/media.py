"""Bounded, verified artifact preparation. Downloaded bytes are never executed.

The reviewed release lock supplies artifact digests and official checksum URLs.
Checksum documents corroborate those pins; this module makes no signature claim.
Redirects are denied except one HTTPS hop from a Restic GitHub release download
to GitHub's exact release-assets host. That transport exception never changes
the locked artifact digest or checksum binding; signed query URLs are not logged.
"""
from contextlib import contextmanager
import bz2
import fcntl
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import urllib.parse
import urllib.request
import uuid

from appliance.contracts import ApplianceError, require

CHUNK = 1024 * 1024
CHECKSUM_LIMIT = 2 * 1024 * 1024
HASH = re.compile(r"[a-f0-9]{64}")


def _limits(record):
    require(type(record) is dict, "media-contract")
    require(type(record.get("sha256")) is str and bool(HASH.fullmatch(record["sha256"])), "media-contract")
    require(type(record.get("size_bytes")) is int and type(record.get("max_bytes")) is int
            and 0 < record["size_bytes"] <= record["max_bytes"] <= 2**63 - 1, "media-contract")


def _url(url):
    require(type(url) is str and len(url) <= 4096 and not any(c.isspace() or ord(c) < 32 for c in url), "media-url")
    try:
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "https" and bool(parsed.hostname) and parsed.port in (None, 443)
                and parsed.username is None and parsed.password is None and not parsed.fragment, "media-url")
        return parsed
    except ValueError:
        raise ApplianceError("media-url") from None


def _component(record):
    _limits(record)
    required = {"id", "version", "url", "sha256", "size_bytes", "max_bytes", "provenance"}
    optional = {"compression", "expanded", "filename", "required_for", "license", "source", "test_only"}
    require(required <= record.keys() and not record.keys() - required - optional, "media-contract")
    require(type(record["id"]) is str and bool(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", record["id"])), "media-contract")
    require(type(record["version"]) is str and 0 < len(record["version"]) <= 128, "media-contract")
    parsed = _url(record["url"])
    filename = record.get("filename", urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1]))
    require(type(filename) is str and 0 < len(filename) <= 255 and filename not in (".", "..")
            and not any(c in filename for c in "/\\\x00\r\n") and filename.strip() == filename, "media-filename")
    provenance = record["provenance"]
    require(type(provenance) is dict, "media-provenance")
    require(provenance.get("kind") == "official-checksum", "media-provenance-unsupported")
    require({"kind", "url"} <= provenance.keys() and not provenance.keys() - {"kind", "url", "sha256"}, "media-provenance")
    _url(provenance["url"])
    if "sha256" in provenance:
        require(type(provenance["sha256"]) is str and bool(HASH.fullmatch(provenance["sha256"])), "media-provenance")
    compression = record.get("compression", "none")
    require(compression in ("none", "bz2"), "media-compression")
    if compression == "bz2":
        expanded = record.get("expanded")
        _limits(expanded)
        require(set(expanded) == {"sha256", "size_bytes", "max_bytes"}, "media-contract")
    else:
        require("expanded" not in record, "media-contract")
    return filename


class _ArtifactRedirect(urllib.request.HTTPRedirectHandler):
    """One fixed vendor route, not a caller-configurable redirect allowlist."""
    def __init__(self, source_url):
        self.source_url = source_url
        self.target_url = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if (self.target_url is not None or req.full_url != self.source_url
                or req.get_method() != "GET" or code not in (301, 302, 303, 307, 308)):
            return None
        try:
            source = _url(self.source_url)
            target = _url(newurl)
        except ApplianceError:
            return None
        if (source.hostname != "github.com" or source.query
                or not re.fullmatch(r"/restic/restic/releases/download/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", source.path)
                or target.hostname != "release-assets.githubusercontent.com"):
            return None
        self.target_url = newurl
        # Carry no credentials/cookies or caller headers across the origin hop.
        return urllib.request.Request(newurl, headers={"Accept-Encoding": "identity"}, method="GET")


def _open_https(url):
    _url(url)
    redirect = _ArtifactRedirect(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), redirect, urllib.request.HTTPSHandler())
    try:
        response = opener.open(urllib.request.Request(url, headers={"Accept-Encoding": "identity"}), timeout=60)
    except (OSError, ValueError):
        raise ApplianceError("media-download") from None
    if response.geturl() != (redirect.target_url or url) or response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
        response.close()
        raise ApplianceError("media-response")
    return response


def _digest(stream, record, output=None):
    _limits(record)
    digest = hashlib.sha256()
    size = 0
    while True:
        data = stream.read(min(CHUNK, record["size_bytes"] - size + 1))
        if not data:
            break
        size += len(data)
        require(size <= record["size_bytes"] and size <= record["max_bytes"], "media-size")
        digest.update(data)
        if output is not None:
            output.write(data)
    require(size == record["size_bytes"], "media-size")
    require(digest.hexdigest() == record["sha256"], "media-digest")
    return {"sha256": digest.hexdigest(), "size_bytes": size}


@contextmanager
def _file(path, *, directory_fd=None, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), "media-file")
        if private:
            require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0 and info.st_nlink == 1, "media-cache-file")
        yield stream


def verify_file(path: Path, component: dict) -> dict:
    """Verify regular-file integrity only; does not assert vendor provenance."""
    try:
        with _file(path) as stream:
            return _digest(stream, component)
    except OSError:
        raise ApplianceError("media-file") from None


@contextmanager
def _cache(path):
    # Walk directory descriptors so no symlinked ancestor can redirect writes.
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            try:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        info = os.fstat(descriptor)
        require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, "media-cache-directory")
        lock = os.open(".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=descriptor)
        try:
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0
                    and info.st_nlink == 1, "media-cache-lock")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield absolute, descriptor
        finally:
            os.close(lock)
    finally:
        os.close(descriptor)


def _exists(name, directory_fd):
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _publish(stream, name, record, directory_fd):
    temporary = ".partial-" + uuid.uuid4().hex
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(descriptor, "wb") as output:
            _digest(stream, record, output)
            output.flush()
            os.fsync(output.fileno())
        # Linking atomically refuses a pre-existing destination, including a
        # racing symlink. Removal of our temporary name leaves one owned inode.
        os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if _exists(temporary, directory_fd):
            os.unlink(temporary, dir_fd=directory_fd)


def _checksum_document(raw, record, filename):
    require(len(raw) <= CHECKSUM_LIMIT, "media-provenance-size")
    pin = record["provenance"].get("sha256")
    require(pin is None or hashlib.sha256(raw).hexdigest() == pin, "media-provenance-digest")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        raise ApplianceError("media-provenance") from None
    matches = []
    for line in lines:
        match = re.fullmatch(r"([a-fA-F0-9]{64}) [ *](.+)", line)
        if match and match[2] == filename:
            matches.append(match[1].lower())
        match = re.fullmatch(r"SHA256\s*\((.+)\)\s*=\s*([a-fA-F0-9]{64})", line)
        if match and match[1] == filename:
            matches.append(match[2].lower())
    require(matches == [record["sha256"]], "media-provenance-mismatch")


def _provenance(record, filename, directory_fd):
    url = record["provenance"]["url"]
    # Vendors may replace a checksum document at the same URL for a new
    # release. Bind the cached evidence to this exact reviewed artifact pin.
    binding = "\0".join((url, filename, record["sha256"], record["provenance"].get("sha256", "")))
    name = "checksum-" + hashlib.sha256(binding.encode()).hexdigest()
    if _exists(name, directory_fd):
        with _file(name, directory_fd=directory_fd, private=True) as stream:
            raw = stream.read(CHECKSUM_LIMIT + 1)
        _checksum_document(raw, record, filename)
        return
    with _open_https(url) as stream:
        raw = stream.read(CHECKSUM_LIMIT + 1)
    _checksum_document(raw, record, filename)
    _publish(io.BytesIO(raw), name, {"sha256": hashlib.sha256(raw).hexdigest(),
             "size_bytes": len(raw), "max_bytes": CHECKSUM_LIMIT}, directory_fd)


class _Expanded:
    """Read one bounded bzip2 stream; reject truncation and trailing payloads."""
    def __init__(self, source):
        self.source = source
        self.decoder = bz2.BZ2Decompressor()
        self.finished = False

    def read(self, count):
        if self.finished:
            return b""
        while True:
            raw = self.source.read(CHUNK) if self.decoder.needs_input else b""
            require(raw or not self.decoder.needs_input, "media-compression-truncated")
            decoded = self.decoder.decompress(raw, max_length=count)
            if self.decoder.eof:
                require(not self.decoder.unused_data and not self.source.read(1), "media-compression-trailing")
                self.finished = True
            if decoded or self.finished:
                return decoded


def prepare_component(component: dict, cache: Path) -> Path:
    """Return verified artifact/expanded bytes, rechecking any cached content."""
    filename = _component(component)
    try:
        with _cache(cache) as (folder, directory_fd):
            _provenance(component, filename, directory_fd)
            name = component["id"] + "-" + component["sha256"] + ".artifact"
            if _exists(name, directory_fd):
                with _file(name, directory_fd=directory_fd, private=True) as stream:
                    _digest(stream, component)
            else:
                with _open_https(component["url"]) as stream:
                    _publish(stream, name, component, directory_fd)
            if component.get("compression", "none") == "bz2":
                expanded = component["id"] + "-" + component["expanded"]["sha256"] + ".expanded"
                if _exists(expanded, directory_fd):
                    with _file(expanded, directory_fd=directory_fd, private=True) as stream:
                        _digest(stream, component["expanded"])
                else:
                    with _file(name, directory_fd=directory_fd, private=True) as stream:
                        _publish(_Expanded(stream), expanded, component["expanded"], directory_fd)
                name = expanded
            return folder / name
    except (OSError, EOFError, ValueError) as error:
        if isinstance(error, ApplianceError):
            raise
        raise ApplianceError("media-preparation") from None
