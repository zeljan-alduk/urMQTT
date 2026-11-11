#!/usr/bin/env python3
"""Mirror the urMQTT GitHub releases into a web directory (C1e, docs/PLAN.md).

    mirror-releases.py --root DIR [--repo OWNER/REPO] [--api-base URL]
        [--keyring FILE | --pubkey FILE...] [--minisign PATH] [--limit-rate BYTES_PER_SECOND]
        [--min-free BYTES] [--token-file FILE] [--dry-run] [--verbose]

GitHub Releases stays the single source of truth. For every new or changed
release this job downloads SHA256SUMS and SHA256SUMS.minisig, verifies the
signature with the release public key (the `minisign` tool), downloads the
template ISO (urmqtt-template-<ver>-universal.iso), checks its size and SHA-256
against the signed sums and looks for the configuration slot. Only when every
check passes are the files moved into <root>/<tag>/ (SHA256SUMS first, the ISO
last, each with os.replace, so a half-copied file is never visible at its final
name). The browser verifies the signature again, so this job is not trusted;
it only refuses to publish what does not verify.

Keys (ROADMAP NOW-2, docs/release-key-rotation.md)
    --keyring FILE        keys/release-keys.json: several minisign public keys,
                          each with the range of tags it may sign. The job
                          takes the key that the signature names (its key id)
                          and refuses the release when that key is not in the
                          ring or the tag is outside its range: the former
                          test key signed v0.1.0 to v0.4.1 and is trusted for
                          those tags only. Key files are relative to the ring.
    --pubkey FILE         one key for every tag (repeatable: each for every
                          tag); the form of the installs before the rotation.
    default               ../keys/release-keys.json next to this script, else
                          /etc/urmqtt-mirror/keys/release-keys.json, else
                          /etc/urmqtt-mirror/minisign.pub.
    A key file that is still the placeholder (REPLACE-WITH-THE-NEW-PUBLIC-KEY)
    is an error: the job does not start.

Layout under --root
    releases.json     what the page reads (schema 1), written atomically after
                      every run that could list GitHub (never in --dry-run)
    <tag>/            SHA256SUMS, SHA256SUMS.minisig, the template ISO, meta.json
    <tag>/meta.json   the job's own state for the tag (see "State")
    .lock             flock; a second instance exits 0 ("already running")
    .tmp/             partial downloads (same filesystem: renames are atomic);
                      emptied at the start of every run

What happens to a release
    no template asset     listed with template null / reason "no-template";
                          nothing is mirrored (the two tiny sums files are
                          fetched only to set `verified`; never an alert)
    template, all good    mirrored; status "ok", verified true
    any check fails       nothing of it is published, files of an earlier good
                          edition of the same tag stay as they were, and the
                          release is flagged (status "unverified" + reason).
                          A failure is remembered, so a deterministic one
                          (bad signature, sha256 mismatch, no slot) is not
                          downloaded again until the release changes or the
                          key does; a transient one (network, disk) is retried.
    edited upstream       assets changed after it was mirrored and the new
                          edition verifies: re-mirrored, "edited": true
    gone upstream         files kept, status "removed" / "removed-upstream"

State (<tag>/meta.json, internal): the asset fingerprint of the last attempt
(ids, names, sizes, digests, updated_at), its result, the verified sums, and
`published`, the edition on disk. releases.json is derived from it plus the
fresh GitHub listing, so a run with nothing changed downloads nothing.

Exit codes: 0 all good (also "nothing to do", "no templates yet", "already
running"); 1 operational error (GitHub unreachable or rate limited, disk full,
bad arguments, a download that failed); 2 at least one release with a template
failed verification (bad or missing signature, sha256 mismatch, no
configuration slot): alert. 2 wins when both happen. A failed GitHub listing
changes nothing on disk (releases.json is kept, nothing is removed).

Python 3.10+, standard library only, plus the `minisign` command-line tool.
Log lines go to stderr; with $JOURNAL_STREAM set they carry the systemd
priority prefixes. The last line on stdout is a JSON summary.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import errno
import fcntl
import hashlib
import http.client
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

DEFAULT_REPO = "zeljan-alduk/urMQTT"
DEFAULT_API = "https://api.github.com"
DEFAULT_RATE = 2 * 1024 * 1024  # bytes per second
DEFAULT_MIN_FREE = 256 * 1024 * 1024  # free space that must remain after a download
SYSTEM_PUBKEY = Path("/etc/urmqtt-mirror/minisign.pub")
SYSTEM_KEYRING = Path("/etc/urmqtt-mirror/keys/release-keys.json")
KEYRING_SCHEMA = 1
KEY_PLACEHOLDER = "REPLACE-WITH-THE-NEW-PUBLIC-KEY"
KEYRING_MAX = 64 * 1024
API_VERSION = "2022-11-28"
USER_AGENT = "urmqtt-mirror/1 (+https://github.com/zeljan-alduk/urMQTT)"
HTTP_TIMEOUT = 60.0  # seconds, per connect or read: a stalled transfer fails
MAX_PAGES = 50  # 5000 releases; also a guard against a Link loop
MAX_LIST_BYTES = 64 * 1024 * 1024
SUMS_MAX = 1024 * 1024  # SHA256SUMS is a few hundred bytes; refuse nonsense
SIG_MAX = 16 * 1024  # a minisig is about 330 bytes
TEMPLATE_MAX = 512 * 1024 * 1024  # the real one is about 55 MB
SCHEMA = 1  # releases.json
META_SCHEMA = 1  # <tag>/meta.json

SUMS_NAME = "SHA256SUMS"
SIG_NAME = "SHA256SUMS.minisig"
RELEASES_JSON = "releases.json"
META_NAME = "meta.json"

# All patterns are used with fullmatch: with `^...$` a trailing newline would
# slip through ("v1\n"), and a tag or file name ends up as a path component.
TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
TEMPLATE_RE = re.compile(r"urmqtt-template-[A-Za-z0-9._-]+-universal\.iso")
# Release versions for the key ranges: v1.2.3, 1.2.3, v1.2.3-rc.1 (the suffix does not count).
VERSION_RE = re.compile(r"v?(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:[-+][0-9A-Za-z.+-]*)?")
KEY_ID_RE = re.compile(r"[0-9A-F]{16}")
# Assets that are only listed, never fetched, still must be harmless to print.
LISTED_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+@=,~-]{0,127}")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
TOKEN_RE = re.compile(r"[A-Za-z0-9_.=-]{8,512}")
URL_RE = re.compile(r"https://[\x21-\x7e]+")  # printable ASCII only, no spaces
SUMS_LINE_RE = re.compile(r"([0-9a-fA-F]{64}) [ *]([^\s].*)")
TIME_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

# The configuration slot (crates/cfg/src/blob.rs, ADR-215): a 256 KiB region
# at a 512-byte boundary that starts with the marker, then the blob magic and
# the little-endian u16 format version.
SLOT_MARKER = b"URMQTT-CFG-SLOT\0"
CFG_MAGIC = b"URMQCFG\0"
SLOT_SIZE = 256 * 1024
SECTOR = 512
SCAN_CHUNK = 4 * 1024 * 1024  # a multiple of SECTOR: no slot header straddles two chunks

# Reasons in releases.json that make the job exit 2 (a release with a template
# that must not be published). "download-failed" is exit 1.
ALERT_REASONS = frozenset({"verification-failed", "no-signature", "no-config-slot"})

LOG = logging.getLogger("urmqtt-mirror")


# ---------------------------------------------------------------------------
# Small helpers


class Fatal(Exception):
    """An error reported to the operator as one line (exit 1), no traceback."""


class ReleaseFailure(Exception):
    """One release could not be mirrored. `reason` is a releases.json reason;
    "download-failed" also covers local I/O errors while fetching or storing."""

    def __init__(self, reason: str, message: str, *, retry: bool = False) -> None:
        super().__init__(message)
        self.reason = reason
        self.retry = retry  # may heal by itself: try again on the next run


class HttpError(Exception):
    """A request failed. The text never contains the token or a signed URL's query."""

    def __init__(self, message: str, *, rate_limited: bool = False) -> None:
        super().__init__(message)
        self.rate_limited = rate_limited


def printable(value: object, limit: int = 300) -> str:
    """`value` as a single log-safe line: remote text must not forge log lines or
    journal priority prefixes, so every non-printable character becomes '?'."""
    text = "".join(c if c.isprintable() else "?" for c in str(value))
    return text if len(text) <= limit else text[: limit - 3] + "..."


def clean_text(value: object, limit: int) -> str | None:
    """A free-text field (release name) reduced to printable characters."""
    if not isinstance(value, str):
        return None
    text = "".join(c for c in value if c.isprintable()).strip()
    return text[:limit] or None


def human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def valid_time(value: object) -> str | None:
    """GitHub's `2026-11-05T10:00:00Z` as is, anything else as None."""
    if isinstance(value, str) and TIME_RE.fullmatch(value):
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return None
        return value
    return None


def valid_tag(tag: str) -> bool:
    # "releases.json" would collide with the output file.
    return bool(TAG_RE.fullmatch(tag)) and tag.lower() != RELEASES_JSON


def strip_query(url: str) -> str:
    """URL for logs: no query (a signed download URL is a credential), no userinfo."""
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc.rpartition('@')[2]}{parts.path}"


def fsync_dir(path: Path) -> None:
    """Make a rename durable; best effort (not every filesystem allows it)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_json_atomic(dest: Path, data: object, scratch: Path) -> None:
    """Write `data` as UTF-8 JSON (2-space indent) to `scratch`, then os.replace
    it onto `dest`. `scratch` must be on the same filesystem."""
    payload = (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with open(scratch, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(scratch, 0o644)
    os.replace(scratch, dest)
    fsync_dir(dest.parent)


def ensure_tag_dir(root: Path, tag: str) -> Path:
    """<root>/<tag>, created if missing. A symlink or file there is refused."""
    directory = root / tag
    try:
        st = os.lstat(directory)
    except FileNotFoundError:
        directory.mkdir(mode=0o755)
        os.chmod(directory, 0o755)  # readable by the web server whatever our umask
        return directory
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(errno.ENOTDIR, f"{directory} exists and is not a plain directory")
    return directory


def tree_usage(path: Path) -> int:
    """`du`-style size: allocated bytes of everything below `path`, links not followed."""
    total = 0
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    total += getattr(st, "st_blocks", 0) * 512 or st.st_size
    if stat.S_ISDIR(st.st_mode):
        try:
            with os.scandir(path) as it:
                for entry in it:
                    total += tree_usage(Path(entry.path))
        except OSError:
            pass
    return total


# ---------------------------------------------------------------------------
# Logging


class _Formatter(logging.Formatter):
    _PRIORITY = {
        logging.CRITICAL: 2,
        logging.ERROR: 3,
        logging.WARNING: 4,
        logging.INFO: 6,
        logging.DEBUG: 7,
    }

    def __init__(self, journal: bool) -> None:
        super().__init__()
        self._journal = journal

    def format(self, record: logging.LogRecord) -> str:
        text = printable(record.getMessage(), 2000)
        if self._journal:  # journald adds the time; the prefix sets the priority
            return f"<{self._PRIORITY.get(record.levelno, 6)}>{text}"
        return f"{iso_now()} {record.levelname:<7} {text}"


def setup_logging(verbose: bool, journal: bool) -> None:
    """Called from main(), never at import. Replaces handlers: main() can run twice in a process."""
    try:
        sys.stderr.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_Formatter(journal))
    LOG.handlers[:] = [handler]
    LOG.propagate = False
    LOG.setLevel(logging.DEBUG if verbose else logging.INFO)


# ---------------------------------------------------------------------------
# Public key and token


def tag_version(tag: str | None) -> tuple[int, int, int] | None:
    match = VERSION_RE.fullmatch(tag or "")
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


@dataclasses.dataclass(frozen=True)
class PubKey:
    path: Path
    key_id: str  # as minisign prints it: 16 hex digits, upper case
    fingerprint: str  # SHA-256 of the 42 key bytes, to notice a changed key
    name: str = "release"
    valid_from: str | None = None  # the first tag it may sign; None: no lower bound
    valid_to: str | None = None  # the last tag it may sign; None: no upper bound
    former_test_key: bool = False
    # Tag -> SHA-256 of its SHA256SUMS. A key with pins signs only those tags, and only those files.
    pinned: tuple[tuple[str, str], ...] = ()

    def pin(self, tag: str) -> str | None:
        return dict(self.pinned).get(tag)

    def covers(self, tag: str) -> bool:
        """May this key sign `tag`? A key with a range signs only tags that parse as versions inside it."""
        if self.valid_from is None and self.valid_to is None:
            return True
        version = tag_version(tag)
        if version is None:
            return False
        low, high = tag_version(self.valid_from), tag_version(self.valid_to)
        return (low is None or version >= low) and (high is None or version <= high)

    def range_text(self) -> str:
        if self.valid_from and self.valid_to:
            return f"{self.valid_from} to {self.valid_to}"
        if self.valid_from:
            return f"{self.valid_from} and later"
        if self.valid_to:
            return f"up to {self.valid_to}"
        return "any tag"

    def describe(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "name": self.name,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "former_test_key": self.former_test_key,
            "pinned": sorted(t for t, _ in self.pinned),
        }


@dataclasses.dataclass(frozen=True)
class Keyring:
    """The keys the job trusts. The first key is the current one (releases.json's key_id)."""

    keys: tuple[PubKey, ...]

    @property
    def fingerprint(self) -> str:
        """Changes when a key or its range does: a failure that a new key could heal is retried."""
        if len(self.keys) == 1 and self.keys[0].valid_from is None and self.keys[0].valid_to is None:
            return self.keys[0].fingerprint  # what a single --pubkey recorded before key rings existed
        items = [[k.fingerprint, k.valid_from, k.valid_to, list(k.pinned)] for k in self.keys]
        return hashlib.sha256(json.dumps(items, separators=(",", ":")).encode()).hexdigest()

    @property
    def primary(self) -> PubKey:
        return next((k for k in self.keys if not k.former_test_key), self.keys[0])

    def by_id(self, key_id: str) -> PubKey | None:
        return next((k for k in self.keys if k.key_id == key_id), None)

    def ids(self) -> str:
        return ", ".join(f"{k.key_id} ({k.name}, {k.range_text()})" for k in self.keys)


def load_pubkey(path: Path, **extra: Any) -> PubKey:
    """Parse a minisign public key file: an untrusted comment line, then base64 of
    "Ed" + 8 bytes key id (little endian) + the 32-byte Ed25519 key."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise Fatal(f"cannot read the public key {path}: {exc}") from None
    if KEY_PLACEHOLDER in text:
        raise Fatal(
            f"{path} is still the placeholder {KEY_PLACEHOLDER}: the release key has not been set "
            "(docs/release-key-rotation.md); install the real minisign.pub first"
        )
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    body = [ln for ln in lines if not ln.startswith("untrusted comment:")]
    try:
        if len(body) != 1:
            raise ValueError("expected one key line")
        raw = base64.b64decode(body[0], validate=True)
        if len(raw) != 42 or raw[:2] != b"Ed":
            raise ValueError("not an Ed25519 minisign public key")
    except ValueError as exc:
        raise Fatal(f"{path} is not a minisign public key: {exc}") from None
    return PubKey(path, raw[2:10][::-1].hex().upper(), hashlib.sha256(raw).hexdigest(), **extra)


def load_keyring(path: Path) -> Keyring:
    """keys/release-keys.json: {"schema": 1, "keys": [{"name", "file", "valid_from",
    "valid_to", "former_test_key", "key_id"?, "note"?}]}. Files are relative to the
    ring. Strict: anything unexpected stops the job (it is the trust anchor)."""
    try:
        raw = path.read_bytes()
        if len(raw) > KEYRING_MAX:
            raise ValueError("implausibly large")
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise Fatal(f"cannot read the key ring {path}: {printable(exc, 160)}") from None
    if not isinstance(doc, dict) or doc.get("schema") != KEYRING_SCHEMA or not isinstance(doc.get("keys"), list) or not doc["keys"]:
        raise Fatal(f"{path} is not a key ring of schema {KEYRING_SCHEMA} with at least one key")
    keys: list[PubKey] = []
    for number, entry in enumerate(doc["keys"], 1):
        where = f"{path}, key {number}"
        if not isinstance(entry, dict):
            raise Fatal(f"{where}: not an object")
        unknown = set(entry) - {"name", "file", "key_id", "valid_from", "valid_to", "former_test_key", "note", "pinned"}
        if unknown:
            raise Fatal(f"{where}: unknown field(s) {', '.join(sorted(unknown))}")
        name, file = entry.get("name"), entry.get("file")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", name):
            raise Fatal(f"{where}: name must be a short word")
        if not isinstance(file, str) or not file or "\0" in file:
            raise Fatal(f"{where}: file must name the key file")
        bounds: dict[str, str | None] = {}
        for field in ("valid_from", "valid_to"):
            value = entry.get(field)
            if value is not None and (not isinstance(value, str) or tag_version(value) is None):
                raise Fatal(f"{where}: {field} must be a version tag like v0.4.1, or null")
            bounds[field] = value
        low, high = tag_version(bounds["valid_from"]), tag_version(bounds["valid_to"])
        if low is not None and high is not None and low > high:
            raise Fatal(f"{where}: valid_from is after valid_to")
        test = entry.get("former_test_key", False)
        if not isinstance(test, bool):
            raise Fatal(f"{where}: former_test_key must be true or false")
        pins = entry.get("pinned") or {}
        if not isinstance(pins, dict) or any(
            not isinstance(t, str) or not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h) for t, h in pins.items()
        ):
            raise Fatal(f"{where}: pinned must map tags to the lower-case hex SHA-256 of their SHA256SUMS")
        key = load_pubkey(
            path.parent / file, name=name, former_test_key=test, pinned=tuple(sorted(pins.items())), **bounds
        )
        if any(not key.covers(t) for t in pins):
            raise Fatal(f"{where}: a pinned tag is outside the key's range")
        declared = entry.get("key_id")
        if declared is not None and declared != key.key_id:
            raise Fatal(f"{where}: {file} has key id {key.key_id}, the ring says {printable(declared, 40)}")
        if any(k.key_id == key.key_id for k in keys):
            raise Fatal(f"{where}: key {key.key_id} is listed twice")
        keys.append(key)
    return Keyring(tuple(keys))


def signature_key_id(path: Path) -> str | None:
    """The key id a .minisig file names (second line: base64 of "ED"/"Ed", 8-byte id, signature)."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        raw = base64.b64decode(lines[1].strip(), validate=True)
    except (OSError, UnicodeDecodeError, IndexError, ValueError):
        return None
    if len(raw) != 74 or raw[:2] not in (b"ED", b"Ed"):
        return None
    return raw[2:10][::-1].hex().upper()


def read_token(path: Path) -> str:
    try:
        token = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise Fatal(f"cannot read the token file {path}: {exc}") from None
    if not TOKEN_RE.fullmatch(token):  # never echo it
        raise Fatal(f"the token file {path} does not contain a single token")
    return token


# ---------------------------------------------------------------------------
# Rate limit


class RateLimiter:
    """Keeps the average rate of everything passed to consume() at `rate` bytes per
    second. Idle time earns no credit, so there are no bursts after a stall."""

    def __init__(
        self,
        rate: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rate = rate
        self._clock = clock
        self._sleep = sleep
        self._next = clock()

    @property
    def chunk(self) -> int:
        """Read size: small enough that a slow rate still paces smoothly."""
        if self.rate <= 0 or self.rate >= 512 * 1024:
            return 64 * 1024
        return max(4096, self.rate // 8)

    def consume(self, nbytes: int) -> None:
        if self.rate <= 0:
            return
        now = self._clock()
        self._next = max(self._next, now) + nbytes / self.rate
        if self._next > now:
            self._sleep(self._next - now)


# ---------------------------------------------------------------------------
# HTTP


def loopback_http(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "http" and (parts.hostname or "") in LOOPBACK_HOSTS


def url_allowed(url: str, insecure_loopback: bool) -> bool:
    """https always; plain http only to this machine, and only when the API base
    itself is such an address (the tests' fake server). Never anything else."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return bool(parts.hostname)
    return insecure_loopback and loopback_http(url)


class _RedirectPolicy(urllib.request.HTTPRedirectHandler):
    """Follows redirects only to allowed URLs. The Authorization header is added as
    an *unredirected* header, so urllib never carries it to the next URL."""

    def __init__(self, insecure_loopback: bool) -> None:
        self._insecure_loopback = insecure_loopback

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not url_allowed(newurl, self._insecure_loopback):
            fp.close()
            raise HttpError(f"refusing a redirect to {printable(strip_query(newurl), 120)}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(insecure_loopback: bool) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [_RedirectPolicy(insecure_loopback)]
    if insecure_loopback:  # a proxy from the environment must not catch our own test server
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


class GitHub:
    """The two calls the job needs: list the releases, download an asset."""

    def __init__(self, api_base: str, repo: str, token: str | None) -> None:
        self.api_base = api_base.rstrip("/")
        parts = urllib.parse.urlsplit(self.api_base)
        self._origin = (parts.scheme, parts.netloc.lower())
        self.repo = repo
        self._token = token
        self._opener = build_opener(loopback_http(self.api_base))
        self.rate_limited = False
        self.requests = 0
        self.bytes_downloaded = 0

    def _same_origin(self, url: str) -> bool:
        parts = urllib.parse.urlsplit(url)
        return (parts.scheme, parts.netloc.lower()) == self._origin

    def _request(self, url: str, accept: str) -> urllib.request.Request:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": accept,
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        if self._token and self._same_origin(url):
            req.add_unredirected_header("Authorization", f"Bearer {self._token}")
        return req

    def _open(self, req: urllib.request.Request) -> Any:
        if self.rate_limited:
            raise HttpError("skipped: the GitHub rate limit was hit earlier in this run", rate_limited=True)
        self.requests += 1
        LOG.debug("GET %s", strip_query(req.full_url))
        try:
            return self._opener.open(req, timeout=HTTP_TIMEOUT)
        except urllib.error.HTTPError as exc:
            raise self._status_error(exc) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else f"{type(exc).__name__}: {exc}"
            raise HttpError(f"{strip_query(req.full_url)}: {printable(reason, 160)}") from None

    def _status_error(self, exc: urllib.error.HTTPError) -> HttpError:
        try:
            body = exc.read(2048).decode("utf-8", "replace")
        except (OSError, http.client.HTTPException):
            body = ""
        finally:
            exc.close()
        remaining = exc.headers.get("X-RateLimit-Remaining")
        limited = exc.code == 429 or (
            exc.code == 403
            and (remaining == "0" or exc.headers.get("Retry-After") is not None or "rate limit" in body.lower())
        )
        text = f"HTTP {exc.code} {printable(exc.reason, 80)} for {printable(strip_query(exc.url), 160)}"
        if limited:
            self.rate_limited = True
            reset = exc.headers.get("X-RateLimit-Reset", "")
            if reset.isdigit():
                when = datetime.fromtimestamp(int(reset), timezone.utc).strftime("%H:%M:%SZ")
                text += f" (GitHub rate limit reached, it resets at {when})"
            else:
                text += " (GitHub rate limit reached)"
        return HttpError(text, rate_limited=limited)

    def _next_link(self, header: str | None, current: str) -> str | None:
        for target, rel in re.findall(r'<([^>]*)>\s*;\s*rel="?([A-Za-z]+)"?', header or ""):
            if rel.lower() == "next":
                url: str = urllib.parse.urljoin(current, target)
                if not self._same_origin(url):  # never leave the API host (nor take the token there)
                    raise HttpError(f"the next page is on another host: {printable(strip_query(url), 120)}")
                return url
        return None

    def list_releases(self) -> list[Any]:
        """Every page of GET /repos/{repo}/releases. Any failure fails the whole
        listing: a partial list would make later releases look removed."""
        url: str | None = f"{self.api_base}/repos/{self.repo}/releases?per_page=100"
        seen: set[str] = set()
        out: list[Any] = []
        while url is not None:
            if url in seen or len(seen) >= MAX_PAGES:
                raise HttpError("too many pages (or a pagination loop)")
            seen.add(url)
            with self._open(self._request(url, "application/vnd.github+json")) as resp:
                if resp.status != 200:
                    raise HttpError(f"HTTP {resp.status} for {strip_query(url)}")
                try:
                    body = resp.read(MAX_LIST_BYTES + 1)
                except (OSError, http.client.HTTPException) as exc:
                    raise HttpError(f"{strip_query(url)}: {printable(exc, 160)}") from None
                link = resp.headers.get("Link")
            if len(body) > MAX_LIST_BYTES:
                raise HttpError("the release list is implausibly large")
            try:
                page = json.loads(body)
            except ValueError:
                raise HttpError(f"{strip_query(url)}: the answer is not JSON") from None
            if not isinstance(page, list):
                raise HttpError(f"{strip_query(url)}: expected a JSON list")
            out.extend(page)
            url = self._next_link(link, url)
        return out

    def download(self, asset_id: int, dest: Path, expected_size: int, limiter: RateLimiter) -> tuple[int, str]:
        """Stream asset `asset_id` to the new file `dest` (throttled); returns
        (size, sha256). The size must be exactly `expected_size`, GitHub's own
        figure; the hash is computed here and compared by the caller."""
        url = f"{self.api_base}/repos/{self.repo}/releases/assets/{asset_id}"
        digest = hashlib.sha256()
        total = 0
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
        with os.fdopen(fd, "wb") as out, self._open(self._request(url, "application/octet-stream")) as resp:
            declared = resp.headers.get("Content-Length", "")
            if declared.isdigit() and int(declared) != expected_size:
                raise HttpError(f"the server announces {declared} bytes, GitHub's asset size is {expected_size}")
            while True:
                try:
                    block = resp.read(limiter.chunk)
                except (OSError, http.client.HTTPException) as exc:
                    raise HttpError(f"download interrupted after {total} bytes: {printable(exc, 160)}") from None
                if not block:
                    break
                total += len(block)
                self.bytes_downloaded += len(block)
                if total > expected_size:
                    raise HttpError(f"more than the {expected_size} bytes GitHub lists")
                out.write(block)
                digest.update(block)
                limiter.consume(len(block))
            out.flush()
            os.fsync(out.fileno())
        if total != expected_size:
            raise HttpError(f"download cut short: {total} of {expected_size} bytes")
        return total, digest.hexdigest()


# ---------------------------------------------------------------------------
# What GitHub says about a release


@dataclasses.dataclass(frozen=True)
class Asset:
    name: str
    id: int
    size: int
    digest: str | None  # GitHub's "sha256:<hex>" as lower-case hex
    updated_at: str | None
    github_url: str | None  # browser_download_url, only if it is a plain https URL


@dataclasses.dataclass(frozen=True)
class Release:
    tag: str
    name: str
    published: str | None
    prerelease: bool
    url: str
    assets: tuple[Asset, ...]
    duplicate_assets: bool = False


def as_int(value: object, minimum: int) -> int | None:
    """`value` if it is a real integer (not a bool) of at least `minimum`."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= minimum:
        return value
    return None


def parse_asset(raw: object) -> Asset | None:
    if not isinstance(raw, dict):
        return None
    name = raw.get("name")
    if not isinstance(name, str) or not LISTED_NAME_RE.fullmatch(name):
        LOG.warning("ignoring an asset with an unusable name: %s", printable(repr(name), 100))
        return None
    ident, size = as_int(raw.get("id"), 1), as_int(raw.get("size"), 0)
    if ident is None or size is None:
        LOG.warning("ignoring asset %s: no usable id or size", name)
        return None
    if raw.get("state", "uploaded") != "uploaded":  # still being uploaded: not there yet
        LOG.info("ignoring asset %s: its state is %s", name, printable(raw.get("state"), 40))
        return None
    digest = raw.get("digest")
    sha = digest[7:].lower() if isinstance(digest, str) and digest.startswith("sha256:") else None
    if sha is not None and not re.fullmatch(r"[0-9a-f]{64}", sha):
        sha = None
    url = raw.get("browser_download_url")
    return Asset(
        name,
        ident,
        size,
        sha,
        valid_time(raw.get("updated_at")),
        url if isinstance(url, str) and URL_RE.fullmatch(url) and not re.search(r"[<>\"']", url) else None,
    )


def parse_release(raw: object, repo: str) -> Release | None:
    """One element of GitHub's list as a Release; None to skip it (drafts, unusable tags)."""
    if not isinstance(raw, dict):
        LOG.warning("ignoring a list element that is not an object")
        return None
    if raw.get("draft") is True:
        return None
    tag = raw.get("tag_name")
    if not isinstance(tag, str) or not valid_tag(tag):
        LOG.warning("ignoring a release with an unusable tag: %s", printable(repr(tag), 100))
        return None
    assets: list[Asset] = []
    seen: set[str] = set()
    duplicate = False
    for item in raw.get("assets") or []:
        asset = parse_asset(item)
        if asset is None:
            continue
        if asset.name in seen:
            duplicate = True
            continue
        seen.add(asset.name)
        assets.append(asset)
    html_url = raw.get("html_url")
    return Release(
        tag=tag,
        name=clean_text(raw.get("name"), 200) or tag,
        published=valid_time(raw.get("published_at")) or valid_time(raw.get("created_at")),
        prerelease=raw.get("prerelease") is True,
        url=html_url
        if isinstance(html_url, str) and URL_RE.fullmatch(html_url) and not re.search(r"[<>\"']", html_url)
        else f"https://github.com/{repo}/releases/tag/{tag}",
        assets=tuple(assets),
        duplicate_assets=duplicate,
    )


def parse_releases(raw: list[Any], repo: str) -> tuple[list[Release], int]:
    """(releases newest first, number skipped for an unusable tag). A tag listed
    twice keeps its first (newest) entry."""
    releases: list[Release] = []
    seen: set[str] = set()
    skipped = 0
    for item in raw:
        rel = parse_release(item, repo)
        if rel is None:
            if isinstance(item, dict) and item.get("draft") is not True:
                skipped += 1
            continue
        if rel.tag in seen:
            LOG.warning("release %s is listed twice; using the first", rel.tag)
            continue
        seen.add(rel.tag)
        releases.append(rel)
    releases.sort(key=lambda r: (r.published or "", r.tag), reverse=True)
    return releases, skipped


def fingerprint(rel: Release) -> str:
    """Identity of the release's assets: a changed file has a new id, size, digest or
    updated_at, a new or missing one changes the set. Used to decide whether a
    release must be looked at again. The release's own updated_at is left out on
    purpose: editing the title or the notes must not download 55 MB again."""
    items = sorted(
        ([a.name, a.id, a.size, a.digest, a.updated_at] for a in rel.assets),
        key=lambda item: (item[0], item[1]),
    )
    return hashlib.sha256(json.dumps(items, separators=(",", ":")).encode()).hexdigest()


def describe(rel: Release) -> dict[str, Any]:
    return {"name": rel.name, "published": rel.published, "prerelease": rel.prerelease, "url": rel.url}


# ---------------------------------------------------------------------------
# Checks on the downloaded files


def parse_sums(text: str) -> dict[str, str]:
    """`sha256sum` / `shasum -a 256` output ("<hex>  <name>" or "<hex> *<name>") as
    {name: lower-case hex}. Strict: any other line, or one name with two
    different hashes, is an error (fail closed)."""
    sums: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = SUMS_LINE_RE.fullmatch(line.rstrip("\r"))
        if not match:
            raise ValueError(f"line {number} is not a sha256sum line")
        name = match.group(2)
        name = name[2:] if name.startswith("./") else name
        digest = match.group(1).lower()
        if sums.setdefault(name, digest) != digest:
            raise ValueError(f"{printable(name, 80)} is listed with two different hashes")
    return sums


def verify_signature(minisign: str, pubkey: Path, message: Path, signature: Path) -> str:
    """Run `minisign -V`; returns the trusted comment. Anything but exit 0 is a failure."""
    cmd = [minisign, "-V", "-p", str(pubkey), "-m", str(message), "-x", str(signature)]
    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseFailure("download-failed", f"cannot run minisign: {printable(exc, 160)}", retry=True) from None
    if proc.returncode != 0:
        lines = [ln for ln in (proc.stderr + proc.stdout).splitlines() if ln.strip()]
        raise ReleaseFailure(
            "verification-failed",
            f"minisign rejected {SUMS_NAME}: {printable(' / '.join(lines[:2]) or f'exit {proc.returncode}', 200)}",
        )
    for line in proc.stdout.splitlines():
        if line.startswith("Trusted comment:"):
            return printable(line.partition(":")[2].strip(), 200)
    return ""


def comment_tag(comment: str) -> str | None:
    """The tag a release's trusted comment names (`urMQTT v0.6.0 release <commit>` -> `v0.6.0`)."""
    m = re.match(r"urMQTT (\S+)", comment)
    return m.group(1) if m else None


def find_config_slot(path: Path) -> int | None:
    """Format version (u16, little endian) of the first configuration slot in the
    image, or None. A slot is the 16-byte marker at a 512-byte aligned offset,
    followed by the 8-byte blob magic, with room for all of its 256 KiB. The
    marker constant inside the kernel is neither aligned nor followed by the
    magic, so it is not mistaken for one."""
    size = path.stat().st_size
    base = 0  # offset of `chunk`; always a multiple of SECTOR
    with open(path, "rb") as f:
        while True:
            chunk = f.read(SCAN_CHUNK)
            if not chunk:
                return None
            pos = chunk.find(SLOT_MARKER)
            while pos != -1:
                head = chunk[pos + 16 : pos + 26]
                if (
                    pos % SECTOR == 0
                    and len(head) == 10
                    and head[:8] == CFG_MAGIC
                    and base + pos + SLOT_SIZE <= size
                ):
                    return int.from_bytes(head[8:10], "little")
                pos = chunk.find(SLOT_MARKER, pos + 1)
            base += len(chunk)


# ---------------------------------------------------------------------------
# Processing one release


@dataclasses.dataclass
class Counters:
    listed: int = 0
    new: int = 0
    updated: int = 0
    retried: int = 0
    failed: int = 0
    removed: int = 0
    skipped_invalid: int = 0
    op_errors: int = 0


@dataclasses.dataclass
class Context:
    root: Path
    tmp: Path
    keys: Keyring
    minisign: str
    client: GitHub
    limiter: RateLimiter
    min_free: int


@dataclasses.dataclass
class Checked:
    """What has been established about a release so far; kept when a later check fails."""

    sig_ok: bool = False
    trusted_comment: str = ""
    key_id: str = ""
    sums_map: dict[str, str] = dataclasses.field(default_factory=dict)
    size: int = 0
    sha256: str = ""
    config_format: int = 0
    retry: bool = False


@dataclasses.dataclass(frozen=True)
class Plan:
    template: Asset | None
    sums: Asset | None
    sig: Asset | None


def classify(rel: Release) -> Plan:
    """Pick the assets the job acts on. Names are compared exactly or with the strict
    template pattern; everything else is only ever listed."""
    if rel.duplicate_assets:
        raise ReleaseFailure("verification-failed", "the release lists one asset name twice")
    by_name = {a.name: a for a in rel.assets}
    templates = [a for a in rel.assets if TEMPLATE_RE.fullmatch(a.name)]
    if len(templates) > 1:
        exact = by_name.get(f"urmqtt-template-{rel.tag}-universal.iso")
        if exact is None:
            raise ReleaseFailure("verification-failed", f"{len(templates)} template assets and none is named for the tag")
        LOG.warning("release %s has %d template assets; using %s", rel.tag, len(templates), exact.name)
        templates = [exact]
    return Plan(templates[0] if templates else None, by_name.get(SUMS_NAME), by_name.get(SIG_NAME))


def download_asset(ctx: Context, asset: Asset, dest: Path) -> tuple[int, str]:
    try:
        return ctx.client.download(asset.id, dest, asset.size, ctx.limiter)
    except HttpError as exc:
        raise ReleaseFailure("download-failed", f"{asset.name}: {exc}", retry=True) from None


def pick_key(ctx: Context, sig: Path, tag: str) -> PubKey:
    """The key the signature names, if the ring has it and it may sign `tag`."""
    key_id = signature_key_id(sig)
    if key_id is None:
        raise ReleaseFailure("verification-failed", f"{SIG_NAME} is not a minisign signature")
    key = ctx.keys.by_id(key_id)
    if key is None:
        raise ReleaseFailure(
            "verification-failed", f"{SIG_NAME} was made with key {key_id}, which is not in the key ring ({ctx.keys.ids()})"
        )
    if not key.covers(tag):
        what = "the project's former test key" if key.former_test_key else f"the {key.name} key"
        raise ReleaseFailure(
            "verification-failed",
            f"{SIG_NAME} was made with key {key_id} ({what}), which may sign {key.range_text()} only, not {printable(tag, 64)}",
        )
    if key.pinned:
        wanted = key.pin(tag)
        if wanted is None:
            raise ReleaseFailure(
                "verification-failed", f"{SIG_NAME} was made with key {key_id}, which signs only its pinned releases, and {printable(tag, 64)} is not one"
            )
    return key


def check_pin(key: PubKey, tag: str, sums_path: Path) -> None:
    """For a pinned key: the downloaded SHA256SUMS must be the pinned file, whatever the signature says."""
    wanted = key.pin(tag)
    if wanted is None:
        return
    got = hashlib.sha256(sums_path.read_bytes()).hexdigest()
    if got != wanted:
        raise ReleaseFailure(
            "verification-failed",
            f"{SUMS_NAME} of {printable(tag, 64)} has SHA-256 {got}, but the key ring pins {wanted} for it "
            f"(signed with key {key.key_id}, not the published file)",
        )


def fetch_and_verify_sums(ctx: Context, plan: Plan, work: Path, checked: Checked, tag: str) -> None:
    """Download SHA256SUMS and its signature, verify the signature with the key it
    names (if that key may sign `tag`), parse the sums."""
    assert plan.sums is not None and plan.sig is not None
    parts = ((plan.sums, work / f"{SUMS_NAME}.part", SUMS_MAX), (plan.sig, work / f"{SIG_NAME}.part", SIG_MAX))
    for asset, dest, limit in parts:
        if asset.size > limit:
            raise ReleaseFailure("verification-failed", f"{asset.name} is {asset.size} bytes (limit {limit})")
        download_asset(ctx, asset, dest)
    key = pick_key(ctx, parts[1][1], tag)
    check_pin(key, tag, parts[0][1])
    comment = verify_signature(ctx.minisign, key.path, parts[0][1], parts[1][1])
    # The signature must be for this tag (trusted comment `urMQTT <tag> release <commit>`): the
    # signed SHA256SUMS of an older release under a newer tag is refused (security review of
    # v0.6.0, SUPPLY-2, ADR-381).
    signed_tag = comment_tag(comment)
    if signed_tag != tag:
        raise ReleaseFailure(
            "verification-failed",
            f"the signature is for {printable(signed_tag or 'no release tag', 64)}, not {printable(tag, 64)} "
            f"(trusted comment {printable(comment, 120)!r}): another release under this tag",
        )
    try:
        sums = parse_sums(parts[0][1].read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReleaseFailure("verification-failed", f"{SUMS_NAME} is not a sha256sum list: {exc}") from None
    checked.trusted_comment, checked.sums_map, checked.sig_ok, checked.key_id = comment, sums, True, key.key_id


def check_free_space(ctx: Context, need: int) -> None:
    free = shutil.disk_usage(ctx.root).free
    if free < need + ctx.min_free:
        raise ReleaseFailure(
            "download-failed",
            f"not enough free space: {human(free)} free, {human(need)} to download and {human(ctx.min_free)} to keep",
            retry=True,
        )


def check_with_template(ctx: Context, plan: Plan, work: Path, checked: Checked, tag: str) -> None:
    """Every check a template release must pass before anything is published."""
    template = plan.template
    assert template is not None
    if plan.sums is None or plan.sig is None:
        raise ReleaseFailure("no-signature", f"the release has a template but not both {SUMS_NAME} and {SIG_NAME}")
    fetch_and_verify_sums(ctx, plan, work, checked, tag)  # the cheap checks first: no big download for a bad signature
    wanted = checked.sums_map.get(template.name)
    if wanted is None:
        raise ReleaseFailure("verification-failed", f"the signed {SUMS_NAME} does not list {template.name}")
    if template.size > TEMPLATE_MAX:
        raise ReleaseFailure("verification-failed", f"{template.name} is {human(template.size)}, more than {human(TEMPLATE_MAX)}")
    check_free_space(ctx, template.size)
    part = work / f"{template.name}.part"
    size, digest = download_asset(ctx, template, part)
    if digest != wanted:
        raise ReleaseFailure("verification-failed", f"{template.name}: sha256 {digest} is not the signed {wanted}")
    version = find_config_slot(part)
    if version is None:
        raise ReleaseFailure("no-config-slot", f"{template.name} has no configuration slot")
    checked.size, checked.sha256, checked.config_format = size, digest, version


def check_without_template(ctx: Context, plan: Plan, work: Path, checked: Checked, tag: str) -> None:
    """A release without a template is only listed. The two tiny sums files are
    fetched to set `verified`; whatever goes wrong here is a warning, not an alert."""
    if plan.sums is None or plan.sig is None:
        LOG.warning("release %s: no template and no complete signature files; listed as unverified", tag)
        return
    try:
        fetch_and_verify_sums(ctx, plan, work, checked, tag)
    except ReleaseFailure as fail:
        checked.retry = fail.retry
        LOG.warning("release %s: no template; %s not verified: %s", tag, SUMS_NAME, fail)
        return
    LOG.info(
        "release %s: no template (built before the runtime configuration); signature ok (key %s, %s)",
        tag, checked.key_id, checked.trusted_comment,
    )  # fmt: skip


def render_assets(assets: Iterable[Asset], sums_map: dict[str, str], mirrored: set[str]) -> list[dict[str, Any]]:
    """All assets for releases.json: sha256 from the verified sums, else GitHub's digest, else null."""
    return [
        {
            "name": a.name,
            "size": a.size,
            "sha256": sums_map.get(a.name) or a.digest,
            "mirrored": a.name in mirrored,
            "github_url": a.github_url,
        }
        for a in sorted(assets, key=lambda a: a.name)
    ]


def publish(ctx: Context, rel: Release, plan: Plan, work: Path, checked: Checked, fp: str, now: str) -> dict[str, Any]:
    """Move the verified files into <root>/<tag>/: sums, signature, then the ISO."""
    template = plan.template
    assert template is not None
    tag_dir = ensure_tag_dir(ctx.root, rel.tag)
    for source, target in (
        (f"{SUMS_NAME}.part", SUMS_NAME),
        (f"{SIG_NAME}.part", SIG_NAME),
        (f"{template.name}.part", template.name),  # last: the file the page offers
    ):
        os.chmod(work / source, 0o644)  # the web server's user must be able to read it
        os.replace(work / source, tag_dir / target)
    fsync_dir(tag_dir)
    return {
        "fingerprint": fp,
        "mirrored_at": now,
        "template": {
            "file": template.name,
            "path": f"{rel.tag}/{template.name}",
            "size": checked.size,
            "sha256": checked.sha256,
            "config_format": checked.config_format,
        },
        "sums": {"path": f"{rel.tag}/{SUMS_NAME}", "sig_path": f"{rel.tag}/{SIG_NAME}"},
        "assets": render_assets(rel.assets, checked.sums_map, {SUMS_NAME, SIG_NAME, template.name}),
        "trusted_comment": checked.trusted_comment,
        "key_id": checked.key_id,
    }


def prune_superseded(tag_dir: Path, keep: set[str]) -> None:
    """After an edited release was re-mirrored under another template name, drop the
    old ISO. Only files that look like a template are ever removed."""
    with os.scandir(tag_dir) as it:
        for entry in list(it):
            if entry.name not in keep and TEMPLATE_RE.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                os.unlink(entry.path)
                LOG.info("removed %s/%s (superseded by the re-mirrored template)", tag_dir.name, entry.name)


def process_release(ctx: Context, rel: Release, prev: dict[str, Any] | None) -> dict[str, Any]:
    """Look at one release, publish it if everything checks out, and return its new
    state (meta.json). Expected failures become a state, not an exception."""
    now = iso_now()
    tag = rel.tag
    fp = fingerprint(rel)
    old_pub = prev.get("published") if prev else None
    state: dict[str, Any] = {
        "meta_schema": META_SCHEMA,
        "tag": tag,
        "fingerprint": fp,
        "key_fp": ctx.keys.fingerprint,
        "result": "",
        "retry": False,
        "verified": False,
        "sums_map": {},
        "key_id": None,
        "attempted_at": now,
        "descr": describe(rel),
        "published": old_pub,  # an earlier good edition stays on disk whatever happens now
        "edited": bool(prev and prev.get("edited")),
        "edited_at": prev.get("edited_at") if prev else None,
        "removed_at": prev.get("removed_at") if prev else None,
    }
    work = ctx.tmp / tag
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, mode=0o700)
    checked = Checked()
    try:
        plan = classify(rel)
        if plan.template is None:
            check_without_template(ctx, plan, work, checked, tag)
            state.update(result="no-template", verified=checked.sig_ok, retry=checked.retry)
        else:
            check_with_template(ctx, plan, work, checked, tag)
            state["published"] = publish(ctx, rel, plan, work, checked, fp, now)
            state.update(result="ok", verified=True, removed_at=None)
            if old_pub is not None and old_pub.get("fingerprint") != fp:
                state.update(edited=True, edited_at=now)
                LOG.warning("release %s: its assets changed after it was mirrored; re-mirrored, flagged as edited", tag)
            LOG.info(
                "release %s: mirrored %s (%s, sha256 %s, config format %d); signature ok (key %s, %s)",
                tag, plan.template.name, human(checked.size), checked.sha256[:16], checked.config_format, checked.key_id,
                checked.trusted_comment,
            )
        state["sums_map"] = checked.sums_map
        state["key_id"] = checked.key_id or None
    except ReleaseFailure as fail:
        state.update(result=fail.reason, retry=fail.retry, verified=False, sums_map=checked.sums_map)
        LOG.error("release %s: NOT published (%s): %s", tag, fail.reason, fail)
    except OSError as exc:  # disk full, permissions: nothing was half-published (os.replace is atomic)
        state.update(result="download-failed", retry=True, verified=False, sums_map=checked.sums_map)
        LOG.error("release %s: NOT published (local I/O error): %s", tag, printable(exc, 200))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return state


# ---------------------------------------------------------------------------
# State and releases.json


def load_states(root: Path) -> tuple[dict[str, dict[str, Any]], int]:
    """The meta.json of every tag directory, and how many could not be read."""
    states: dict[str, dict[str, Any]] = {}
    unreadable = 0
    with os.scandir(root) as it:
        entries = sorted(it, key=lambda e: e.name)
    for entry in entries:
        if not valid_tag(entry.name) or not entry.is_dir(follow_symlinks=False):
            continue
        meta = Path(entry.path) / META_NAME
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            LOG.error("cannot read %s: %s", meta, printable(exc, 160))
            unreadable += 1
            continue
        needed = ("fingerprint", "key_fp", "result", "descr")
        if (
            not isinstance(data, dict)
            or data.get("meta_schema") != META_SCHEMA
            or data.get("tag") != entry.name
            or any(k not in data for k in needed)
        ):
            LOG.error("%s is not a state file of this version; ignoring it", meta)
            unreadable += 1
            continue
        states[entry.name] = data
    return states, unreadable


def save_state(ctx: Context, state: dict[str, Any]) -> None:
    tag_dir = ensure_tag_dir(ctx.root, state["tag"])
    write_json_atomic(tag_dir / META_NAME, state, ctx.tmp / f"{state['tag']}.meta.json.new")


def published_intact(root: Path, tag: str, published: object) -> bool:
    """The three published files exist as plain files of the recorded size."""
    try:
        assert isinstance(published, dict)
        sizes = {a["name"]: a["size"] for a in published["assets"]}
        wanted = {
            published["template"]["file"]: published["template"]["size"],
            SUMS_NAME: sizes[SUMS_NAME],
            SIG_NAME: sizes[SIG_NAME],
        }
        for name, size in wanted.items():
            st = os.lstat(root / tag / name)
            if not stat.S_ISREG(st.st_mode) or st.st_size != size:
                return False
    except (AssertionError, KeyError, TypeError, OSError):
        return False
    return True


def decide(rel: Release, prev: dict[str, Any] | None, key: Keyring, root: Path) -> str | None:
    """Why this release must be processed now, or None when nothing needs doing."""
    if prev is None:
        return "new"
    if prev.get("fingerprint") != fingerprint(rel):
        return "changed"
    if prev.get("retry"):
        return "retry"
    result = prev.get("result")
    # A corrected key is the one outside change that can turn a failure into a success.
    key_sensitive = result == "verification-failed" or (result == "no-template" and not prev.get("verified"))
    if key_sensitive and prev.get("key_fp") != key.fingerprint:
        return "key"
    if result == "ok" and not published_intact(root, rel.tag, prev.get("published")):
        return "files"
    return None


def update_removed(state: dict[str, Any], removed: bool, now: str) -> bool:
    """Keep `removed_at` in step with reality; True if the state changed."""
    if removed and not state.get("removed_at"):
        state["removed_at"] = now
        return True
    if not removed and state.get("removed_at"):
        state["removed_at"] = None
        return True
    return False


def signer_of(state: dict[str, Any], root: Path) -> str | None:
    """The key id that signed what is on disk (or, with nothing mirrored, the last
    verified SHA256SUMS). Editions mirrored before key rings existed did not record
    it: their signature file on disk says."""
    published = state.get("published")
    if isinstance(published, dict):
        if isinstance(published.get("key_id"), str) and published["key_id"]:
            return str(published["key_id"])
        return signature_key_id(root / state["tag"] / SIG_NAME)
    key_id = state.get("key_id")
    return key_id if isinstance(key_id, str) and KEY_ID_RE.fullmatch(key_id) and state.get("verified") else None


def build_entry(
    repo: str, state: dict[str, Any], rel: Release | None, now: str, keys: Keyring | None = None, root: Path | None = None
) -> dict[str, Any]:
    """One element of releases.json. Descriptive fields come from the fresh
    listing (or the stored copy when the release is gone), the rest from the state."""
    published = state.get("published")
    result = state["result"]
    removed = bool(state.get("removed_at"))
    descr = describe(rel) if rel is not None else state["descr"]
    if removed:
        status, reason, verified = "removed", "removed-upstream", published is not None
    elif result == "ok":
        status, reason, verified = "ok", None, True
    elif result == "no-template":
        verified = bool(state.get("verified"))
        status, reason = ("ok" if verified else "unverified"), "no-template"
    else:
        status, reason, verified = "unverified", result, False
    if published is not None:  # describes the files on disk, whatever the verdict on GitHub's current state
        template, sums, mirrored_at, assets = (published[k] for k in ("template", "sums", "mirrored_at", "assets"))
    else:
        template = sums = mirrored_at = None
        assets = render_assets(rel.assets if rel is not None else (), state.get("sums_map") or {}, set())
    entry: dict[str, Any] = {
        "tag": state["tag"],
        "name": descr["name"],
        "published": descr["published"],
        "prerelease": descr["prerelease"],
        "url": descr["url"],
        "attestations": f"https://github.com/{repo}/attestations",
        "status": status,
        "edited": bool(state.get("edited")),
    }
    if state.get("edited") and state.get("edited_at"):
        entry["edited_at"] = state["edited_at"]
    entry.update(template=template, sums=sums, verified=verified, reason=reason)
    # Which key signed it (informative: the page checks the signature itself, with its own keys).
    signer = signer_of(state, root) if root is not None else None
    known = keys.by_id(signer) if keys is not None and signer else None
    entry["signed_by"] = (known.describe() if known else {"key_id": signer, "name": None}) if signer else None
    if removed:
        entry["removed_at"] = state["removed_at"]
    entry.update(assets=assets, mirrored_at=mirrored_at, checked_at=now)
    return entry


def build_document(repo: str, keys: Keyring, entries: list[dict[str, Any]], now: str) -> dict[str, Any]:
    entries.sort(key=lambda e: (e["published"] or "", e["tag"]), reverse=True)
    return {
        "schema": SCHEMA,
        "generated": now,
        "repo": repo,
        "source": f"https://github.com/{repo}/releases",
        "key_id": keys.primary.key_id,
        "keys": [k.describe() for k in keys.keys],
        "releases": entries,
        # what the page can offer: a mirrored template that is current and verified
        "templates": sum(1 for e in entries if e["template"] is not None and e["status"] == "ok"),
    }


# ---------------------------------------------------------------------------
# The run


@dataclasses.dataclass(frozen=True)
class Config:
    root: Path
    repo: str
    api_base: str
    pubkeys: tuple[Path, ...]  # --pubkey: each key for every tag
    keyring: Path | None  # --keyring (wins over pubkeys)
    minisign: str | None
    limit_rate: int
    min_free: int
    token_file: Path | None
    dry_run: bool
    verbose: bool


def acquire_lock(root: Path) -> int | None:
    """Exclusive flock on <root>/.lock; None if another instance holds it."""
    fd = os.open(root / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
            return None
        raise
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode())  # for the operator: who holds it
    return fd


def prepare_tmp(root: Path) -> Path:
    """An empty <root>/.tmp. Whatever is there is left over from a run that was killed."""
    tmp = root / ".tmp"
    if tmp.is_symlink() or tmp.is_file():
        tmp.unlink()
    elif tmp.is_dir():
        stale = sum(1 for _ in os.scandir(tmp))
        shutil.rmtree(tmp)
        if stale:
            LOG.info("removed %d stale entries from %s (an interrupted earlier run)", stale, tmp)
    tmp.mkdir(mode=0o700)
    os.chmod(tmp, 0o700)
    return tmp


def run(cfg: Config, summary: dict[str, Any]) -> int:
    if not cfg.root.is_dir():
        raise Fatal(f"{cfg.root} is not a directory (scripts/mirror/install.sh creates it)")
    if cfg.keyring is not None:
        key = load_keyring(cfg.keyring)
    else:
        loaded = [load_pubkey(p) for p in cfg.pubkeys]
        if len({k.key_id for k in loaded}) != len(loaded):
            raise Fatal("one key is given twice with --pubkey")
        key = Keyring(tuple(loaded))
    token = read_token(cfg.token_file) if cfg.token_file else None
    if cfg.minisign is None and not cfg.dry_run:  # fail now, not once per release
        raise Fatal("minisign not found; install it (Debian/Ubuntu: apt install minisign) or pass --minisign")
    lock = None
    if not cfg.dry_run:
        lock = acquire_lock(cfg.root)
        if lock is None:
            LOG.info("already running (%s is locked); exiting", cfg.root / ".lock")
            summary["already_running"] = True
            return 0
    try:
        return run_locked(cfg, key, token, summary)
    finally:
        if lock is not None:
            os.close(lock)


def report_unexpected(what: str, exc: Exception) -> None:
    """Log an error that is not a verdict on a release (disk, permissions, or a bug)."""
    LOG.error("%s: %s: %s", what, type(exc).__name__, printable(exc, 200))
    if not isinstance(exc, OSError):  # a bug: say where
        for line in traceback.format_exc().splitlines():
            LOG.error("  %s", line)


def is_failure(state: dict[str, Any]) -> bool:
    """The last attempt ended in a failure (as opposed to ok / no-template)."""
    return state["result"] in ALERT_REASONS or state["result"] == "download-failed"


def reconcile(state: dict[str, Any], rel: Release, now: str) -> bool:
    """Bring the stored state in line with the fresh listing; True if it changed."""
    changed = False
    # No template any more after one was mirrored: it was withdrawn upstream.
    withdrawn = state["result"] == "no-template" and state.get("published") is not None
    if update_removed(state, withdrawn, now):
        changed = True
        if withdrawn:
            LOG.warning("release %s: its template was withdrawn upstream; the mirror copy is kept and flagged", rel.tag)
    if state["descr"] != describe(rel):
        state["descr"] = describe(rel)
        changed = True
    return changed


def sync_listed(
    ctx: Context, releases: list[Release], states: dict[str, dict[str, Any]], counters: Counters, now: str, dry_run: bool
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    """Process every listed release that needs it. Returns the final state of each
    and (dry run) what would have been processed."""
    final: dict[str, dict[str, Any]] = {}
    would: list[dict[str, str]] = []
    for rel in releases:
        prev = states.get(rel.tag)
        why = decide(rel, prev, ctx.keys, ctx.root)
        if why is None:
            assert prev is not None
            state, dirty = prev, False
            LOG.debug("release %s: unchanged", rel.tag)
            if is_failure(state):
                LOG.error(
                    "release %s: still flagged %s since %s (nothing changed upstream, not downloaded again)",
                    rel.tag, state["result"], state.get("attempted_at"),
                )  # fmt: skip
        else:
            if prev is None:
                counters.new += 1
            elif why == "changed":
                counters.updated += 1
            else:
                counters.retried += 1
            if dry_run:
                LOG.info("[dry run] would process release %s (%s)", rel.tag, why)
                would.append({"tag": rel.tag, "why": why})
                continue
            LOG.info("release %s: processing (%s)", rel.tag, why)
            try:
                state, dirty = process_release(ctx, rel, prev), True
            except Exception as exc:  # no verdict on this release; it must not stop the others
                report_unexpected(f"release {rel.tag}", exc)
                counters.op_errors += 1
                if prev is None:
                    continue
                state, dirty = prev, False
        final[rel.tag] = state
        if dry_run:
            continue
        dirty = reconcile(state, rel, now) or dirty
        if dirty:
            try:
                save_state(ctx, state)
                if why is not None and state["result"] == "ok":  # an edit may have renamed the template
                    keep = {SUMS_NAME, SIG_NAME, META_NAME, state["published"]["template"]["file"]}
                    prune_superseded(ctx.root / rel.tag, keep)
            except OSError as exc:
                LOG.error("release %s: cannot save its state: %s", rel.tag, printable(exc, 200))
                counters.op_errors += 1
    return final, would


def sync_unlisted(
    ctx: Context, states: dict[str, dict[str, Any]], listed: set[str], counters: Counters, now: str, dry_run: bool
) -> dict[str, dict[str, Any]]:
    """Releases we hold state for that GitHub no longer lists: a mirrored one is
    kept and flagged "removed"; one that never had anything mirrored is forgotten."""
    final: dict[str, dict[str, Any]] = {}
    for tag, state in states.items():
        if tag in listed:
            continue
        if state.get("published") is None:
            if dry_run:
                LOG.info("[dry run] release %s is gone upstream and was never mirrored; would forget it", tag)
                continue
            try:
                (ctx.root / tag / META_NAME).unlink()
                (ctx.root / tag).rmdir()
            except OSError:
                pass  # something else is in there: leave it
            continue
        first = not state.get("removed_at")
        counters.removed += 1
        if dry_run:
            LOG.info("[dry run] release %s is no longer on GitHub; would %s", tag, "flag it as removed" if first else "keep it flagged")
            continue
        if update_removed(state, True, now):
            try:
                save_state(ctx, state)
            except OSError as exc:
                LOG.error("release %s: cannot save its state: %s", tag, printable(exc, 200))
                counters.op_errors += 1
        if first:
            LOG.warning("release %s: no longer on GitHub; the mirror copy is kept and flagged as removed", tag)
        else:
            LOG.info("release %s: still gone from GitHub (kept, flagged as removed)", tag)
        final[tag] = state
    return final


def run_locked(cfg: Config, key: Keyring, token: str | None, summary: dict[str, Any]) -> int:
    root, repo = cfg.root, cfg.repo
    LOG.info(
        "mirroring %s into %s%s (keys %s; %s)",
        repo,
        root,
        " [dry run]" if cfg.dry_run else "",
        key.ids(),
        "unlimited rate" if cfg.limit_rate <= 0 else f"{human(cfg.limit_rate)}/s",
    )
    client = GitHub(cfg.api_base, repo, token)
    try:
        raw = client.list_releases()
    except HttpError as exc:  # before anything on disk is touched
        raise Fatal(f"cannot list the releases: {exc}; nothing was changed") from None
    releases, skipped = parse_releases(raw, repo)
    counters = Counters(listed=len(releases), skipped_invalid=skipped)
    if skipped:
        LOG.warning("%d release(s) with an unusable tag were ignored", skipped)
    states, unreadable = load_states(root)
    counters.op_errors += unreadable
    tmp = root / ".tmp" if cfg.dry_run else prepare_tmp(root)
    ctx = Context(root, tmp, key, cfg.minisign or "minisign", client, RateLimiter(cfg.limit_rate), cfg.min_free)
    now = iso_now()

    final, would = sync_listed(ctx, releases, states, counters, now, cfg.dry_run)
    final.update(sync_unlisted(ctx, states, {r.tag for r in releases}, counters, now, cfg.dry_run))

    alerts = sum(1 for s in final.values() if s["result"] in ALERT_REASONS and not s.get("removed_at"))
    errors = sum(1 for s in final.values() if s["result"] == "download-failed" and not s.get("removed_at"))
    counters.failed = alerts + errors
    document: dict[str, Any] | None = None
    if not cfg.dry_run:
        stamp = iso_now()  # one instant for "generated" and every "checked_at": never before a "mirrored_at"
        by_tag = {r.tag: r for r in releases}
        entries = [build_entry(repo, state, by_tag.get(tag), stamp, key, root) for tag, state in final.items()]
        document = build_document(repo, key, entries, stamp)
        try:
            write_json_atomic(root / RELEASES_JSON, document, ctx.tmp / f"{RELEASES_JSON}.new")
        except OSError as exc:  # the previous releases.json is still there
            raise Fatal(f"cannot write {RELEASES_JSON}: {exc}") from None

    du = tree_usage(root)
    try:
        usage = shutil.disk_usage(root)
        free, total = usage.free, usage.total
    except OSError:  # statistics only: not worth failing a run that has done its work
        free = total = 0
    LOG.info(
        "releases: %d listed, %d new, %d updated, %d retried, %d failed, %d removed upstream",
        counters.listed, counters.new, counters.updated, counters.retried, counters.failed, counters.removed,
    )  # fmt: skip
    LOG.info("downloaded: %s (%d bytes)", human(client.bytes_downloaded), client.bytes_downloaded)
    LOG.info("mirror size on disk: %s (du, %s)", human(du), root)
    LOG.info("filesystem free: %s of %s", human(free), human(total))
    summary.update(
        {
            "repo": repo,
            "dry_run": cfg.dry_run,
            "listed": counters.listed,
            "new": counters.new,
            "updated": counters.updated,
            "retried": counters.retried,
            "failed": counters.failed,
            "removed": counters.removed,
            "skipped_invalid": counters.skipped_invalid,
            "templates": document["templates"] if document else None,
            "bytes_downloaded": client.bytes_downloaded,
            "du_bytes": du,
            "free_bytes": free,
            "api_requests": client.requests,
        }
    )
    if cfg.dry_run:
        summary["would_process"] = would
    if alerts:
        return 2
    return 1 if errors or counters.op_errors else 0


# ---------------------------------------------------------------------------
# Command line


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:  # exit 1, not argparse's 2: 2 means "verification failed"
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(1)


def parse_args(argv: list[str] | None) -> Config:
    script_dir = Path(__file__).resolve().parent
    repo_ring = script_dir.parent / "keys" / "release-keys.json"
    parser = _Parser(description="Mirror the urMQTT GitHub releases into a web directory.")
    parser.add_argument("--root", required=True, type=Path, help="directory that holds releases.json and <tag>/")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="OWNER/REPO (default %(default)s)")
    parser.add_argument("--api-base", default=DEFAULT_API, help="GitHub API base URL (default %(default)s)")
    keys = parser.add_mutually_exclusive_group()
    keys.add_argument(
        "--keyring",
        type=Path,
        help="key ring (keys/release-keys.json): each key with the tags it may sign (default: ../keys/release-keys.json "
        "next to this script if present, else %s if present, else --pubkey %s)" % (SYSTEM_KEYRING, SYSTEM_PUBKEY),
    )
    keys.add_argument(
        "--pubkey",
        type=Path,
        action="append",
        help="a minisign public key trusted for every tag (repeatable); instead of --keyring",
    )
    parser.add_argument("--minisign", default="minisign", help="minisign binary, a name or a path (default: %(default)s from PATH)")
    parser.add_argument(
        "--limit-rate",
        type=int,
        default=DEFAULT_RATE,
        metavar="BYTES_PER_SECOND",
        help="download rate cap, 0 = unlimited (default %(default)s)",
    )
    parser.add_argument(
        "--min-free",
        type=int,
        default=DEFAULT_MIN_FREE,
        metavar="BYTES",
        help="refuse a download that would leave less free space, 0 = no check (default %(default)s)",
    )
    parser.add_argument("--token-file", type=Path, help="file with a GitHub token (raises the API rate limit)")
    parser.add_argument("--dry-run", action="store_true", help="list and decide, write nothing, download nothing")
    parser.add_argument("--verbose", action="store_true", help="log every request and decision")
    args = parser.parse_args(argv)
    if not REPO_RE.fullmatch(args.repo):
        parser.error("--repo must look like OWNER/REPO")
    parts = urllib.parse.urlsplit(args.api_base)
    if not url_allowed(args.api_base, loopback_http(args.api_base)) or parts.username or parts.query or parts.fragment:
        parser.error("--api-base must be an https URL (plain http only for localhost), without credentials or query")
    if args.limit_rate < 0 or args.min_free < 0:
        parser.error("--limit-rate and --min-free must not be negative")
    keyring: Path | None = args.keyring
    if keyring is None and not args.pubkey:
        keyring = next((p for p in (repo_ring, SYSTEM_KEYRING) if p.is_file()), None)
    return Config(
        root=args.root.resolve(),
        repo=args.repo,
        api_base=args.api_base.rstrip("/"),
        pubkeys=tuple(args.pubkey or ([] if keyring is not None else [SYSTEM_PUBKEY])),
        keyring=keyring,
        minisign=shutil.which(args.minisign),  # None if it is not there or not executable
        limit_rate=args.limit_rate,
        min_free=args.min_free,
        token_file=args.token_file,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )


def main(argv: list[str] | None = None) -> int:
    cfg = parse_args(argv)
    setup_logging(cfg.verbose, journal=bool(os.environ.get("JOURNAL_STREAM")))
    summary: dict[str, Any] = {}
    try:
        code = run(cfg, summary)
    except Fatal as exc:
        LOG.error("%s", exc)
        summary["error"] = printable(exc, 300)
        code = 1
    except KeyboardInterrupt:
        LOG.error("interrupted")
        code = 1
    except Exception:  # a bug or an unexpected OS error: say where, but still end in the contract's exit code
        for line in traceback.format_exc().splitlines():
            LOG.error("%s", line)
        summary["error"] = "unexpected error (see the log)"
        code = 1
    summary.update(ok=code == 0, exit_code=code)
    try:
        print(json.dumps(summary, sort_keys=True), flush=True)
    except BrokenPipeError:
        pass
    return code


if __name__ == "__main__":
    sys.exit(main())
