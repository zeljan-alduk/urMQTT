#!/usr/bin/env python3
"""Tests for scripts/mirror-releases.py (the aldo.tech release mirror, C1e).

    python3 -I scripts/test-mirror-releases.py [-v] [TestCase.test_name ...]

The job runs as a subprocess against a fake GitHub API (http.server in a
thread, with the fields the real API has, pagination by Link header, a
redirect for asset downloads, and switches to fail in the ways GitHub or the
network can). Releases are signed with THROWAWAY minisign keys generated in a
temp directory (`minisign -G -W`); the real release key is never used. Template
ISOs are small synthetic images: random bytes with a 256 KiB configuration
slot at a 512-byte aligned offset.

Scenarios (the letters are the C1e contract's)
  a  release without a template: listed, nothing big downloaded
  b  valid signed template: mirrored, hashes, slot format, file modes
  c  ISO that does not match SHA256SUMS: not published, exit 2
  d  SHA256SUMS signed by another key: not published, exit 2, ISO never fetched
  e  nothing changed: only the list request, same releases.json
  f  release deleted upstream: kept, flagged "removed"
  g  release edited upstream: re-mirrored, "edited"; a bad edit keeps the old files
  h  interrupted download (connection dropped, process killed): nothing under
     the final name, stale .tmp cleaned on the next run
  i  hostile tags and names: rejected, nothing written outside the root
  j  --limit-rate holds
  k  --dry-run writes nothing
plus drafts, pagination, API errors, rate limit, token handling, redirects,
the lock, free-space guard, journald prefixes, and unit tests of the parsers.

Exits 0 with a message when `minisign` is not installed.
"""

from __future__ import annotations

import copy
import dataclasses
import fcntl
import hashlib
import http.server
import importlib.util
import itertools
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple
from unittest import mock

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "mirror-releases.py"
REPO_PUBKEY = HERE.parent / "minisign.pub"
REPO_TEST_KEY = HERE.parent / "keys" / "minisign-test-9229E05252D01F8E.pub"
REPO_KEYRING = HERE.parent / "keys" / "release-keys.json"
OWNER, REPO = "zeljan-alduk", "urMQTT"
MINISIGN = shutil.which("minisign")

SLOT_MARKER = b"URMQTT-CFG-SLOT\0"
CFG_MAGIC = b"URMQCFG\0"
SLOT_SIZE = 256 * 1024


def load_script() -> Any:
    """The script as a module (its file name has a dash, and -I keeps the script
    directory off sys.path)."""
    spec = importlib.util.spec_from_file_location("mirror_releases", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["mirror_releases"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Test data: keys, ISOs, sums


class KeyPair:
    """A throwaway passwordless minisign key pair in a temp directory."""

    def __init__(self, directory: Path, name: str, home: Path) -> None:
        self.pub = directory / f"{name}.pub"
        self.sec = directory / f"{name}.key"
        self._dir = directory
        self._home = home
        self._minisign(["-G", "-W", "-p", str(self.pub), "-s", str(self.sec)])
        line = self.pub.read_text().splitlines()[0]
        self.key_id = line.rsplit(" ", 1)[1]

    def _minisign(self, args: list[str]) -> None:
        assert MINISIGN is not None
        # HOME points at an empty directory: minisign must never find a real key.
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self._home)}
        proc = subprocess.run([MINISIGN, *args], stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"minisign {args[0]} failed: {proc.stderr.decode(errors='replace')}")

    def sign(self, data: bytes, comment: str) -> bytes:
        message = self._dir / "message.tmp"
        sig = self._dir / "message.minisig"
        message.write_bytes(data)
        sig.unlink(missing_ok=True)
        self._minisign(["-S", "-s", str(self.sec), "-m", str(message), "-x", str(sig), "-t", comment])
        return sig.read_bytes()


def make_iso(size: int = 1 << 20, *, seed: int = 1, version: int | None = 1, slot_at: int = 512 * 40) -> bytes:
    """A synthetic template ISO: random bytes, the kernel's copy of the marker
    constant (unaligned), an aligned marker that is not a slot, and, unless
    `version` is None, a slot (marker, blob magic, u16 version, zeros)."""
    data = bytearray(random.Random(seed).randbytes(size))
    data[1000:1016] = SLOT_MARKER  # unaligned decoy, as inside a kernel
    data[2048:2064] = SLOT_MARKER  # aligned but followed by random bytes, not by the magic
    if version is not None:
        slot = SLOT_MARKER + CFG_MAGIC + struct.pack("<H", version) + bytes(SLOT_SIZE - 26)
        data[slot_at : slot_at + SLOT_SIZE] = slot
    return bytes(data)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sums_text(files: dict[str, bytes]) -> bytes:
    """What `shasum -a 256 *` writes in build/dist."""
    return "".join(f"{sha(data)}  {name}\n" for name, data in sorted(files.items())).encode()


# ---------------------------------------------------------------------------
# The fake GitHub


class Req(NamedTuple):
    path: str
    query: str
    host: str
    auth: str | None
    accept: str | None


class FakeAsset:
    def __init__(self, fake: FakeGitHub, name: str, data: bytes, size: int | None = None, state: str = "uploaded") -> None:
        self.id = fake.new_id(name)
        self.name, self.data, self.state, self.size_override = name, data, state, size
        self.created = self.updated = fake.tick()

    def to_json(self, fake: FakeGitHub, tag: str) -> dict[str, Any]:
        return {
            "url": f"{fake.base}/repos/{OWNER}/{REPO}/releases/assets/{self.id}",
            "id": self.id,
            "node_id": f"RA_{self.id}",
            "name": self.name,
            "label": "",
            "content_type": "application/octet-stream",
            "state": self.state,
            "size": len(self.data) if self.size_override is None else self.size_override,
            "digest": f"sha256:{sha(self.data)}",
            "download_count": 0,
            "created_at": self.created,
            "updated_at": self.updated,
            "browser_download_url": f"https://github.com/{OWNER}/{REPO}/releases/download/{tag}/{self.name}",
        }


class FakeRelease:
    def __init__(self, fake: FakeGitHub, tag: str, name: str, published: str, prerelease: bool, draft: bool) -> None:
        self.fake = fake
        self.id = fake.new_id(tag)
        self.tag, self.name, self.published = tag, name, published
        self.prerelease, self.draft = prerelease, draft
        self.updated = fake.tick()
        self.assets: list[FakeAsset] = []

    def add_asset(self, name: str, data: bytes, **kw: Any) -> FakeAsset:
        asset = FakeAsset(self.fake, name, data, **kw)
        self.assets.append(asset)
        self.updated = self.fake.tick()
        return asset

    def replace_asset(self, name: str, data: bytes) -> FakeAsset:
        """Delete and upload again under the same name: a new id and new timestamps."""
        self.assets = [a for a in self.assets if a.name != name]
        return self.add_asset(name, data)

    def to_json(self) -> dict[str, Any]:
        base = f"{self.fake.base}/repos/{OWNER}/{REPO}"
        return {
            "url": f"{base}/releases/{self.id}",
            "assets_url": f"{base}/releases/{self.id}/assets",
            "upload_url": f"https://uploads.github.com/repos/{OWNER}/{REPO}/releases/{self.id}/assets{{?name,label}}",
            "html_url": f"https://github.com/{OWNER}/{REPO}/releases/tag/{self.tag}",
            "id": self.id,
            "node_id": f"RE_{self.id}",
            "tag_name": self.tag,
            "target_commitish": "main",
            "name": self.name,
            "draft": self.draft,
            "immutable": False,
            "prerelease": self.prerelease,
            "created_at": self.published,
            "updated_at": self.updated,
            "published_at": self.published,
            "assets": [a.to_json(self.fake, self.tag) for a in self.assets],
            "tarball_url": f"{base}/tarball/{self.tag}",
            "zipball_url": f"{base}/zipball/{self.tag}",
            "body": "**Full Changelog**",
        }


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # a client that was killed or gave up is part of the scenarios


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 (http.server's name)
        self.server.fake.handle(self)  # type: ignore[attr-defined]


class FakeGitHub:
    """The parts of the GitHub REST API the mirror uses, on 127.0.0.1."""

    def __init__(self) -> None:
        self.releases: list[FakeRelease] = []
        self.log: list[Req] = []
        self.names: dict[int, str] = {}
        self.page_size: int | None = None  # force pagination whatever per_page says
        self.list_error: tuple[int, dict[str, str], bytes] | None = None
        self.asset_error: tuple[int, dict[str, str], bytes] | None = None  # for the asset endpoint
        self.next_link_host: str | None = None  # make the Link header point to another host name
        self.truncate: dict[str, int] = {}  # asset name -> bytes sent before the connection is dropped
        self.stall: dict[str, tuple[int, threading.Event]] = {}  # asset name -> (bytes, release event)
        self.redirect_host = "localhost"  # another name for the same machine: a different "host"
        self.redirect_to: str | None = None
        self._ids = itertools.count(5000)
        self._clock = itertools.count(0)
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.fake = self  # type: ignore[attr-defined]
        self.port = self._server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    # -- state ----------------------------------------------------------
    def new_id(self, name: str) -> int:
        ident = next(self._ids)
        self.names[ident] = name
        return ident

    def tick(self) -> str:
        t = datetime(2026, 11, 5, 10, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=next(self._clock))
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    def add_release(
        self,
        tag: str,
        *,
        name: str | None = None,
        published: str = "2026-11-05T10:00:00Z",
        prerelease: bool = False,
        draft: bool = False,
    ) -> FakeRelease:
        rel = FakeRelease(self, tag, name or tag, published, prerelease, draft)
        self.releases.append(rel)
        return rel

    def downloads(self) -> list[str]:
        """Names of the assets fetched through the API's asset endpoint, in order."""
        return [self.names[int(r.path.rsplit("/", 1)[1])] for r in self.log if "/releases/assets/" in r.path]

    def list_requests(self) -> int:
        return sum(1 for r in self.log if r.path == f"/repos/{OWNER}/{REPO}/releases")

    def reset_log(self) -> None:
        self.log.clear()

    def close(self) -> None:
        for _, event in self.stall.values():
            event.set()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    # -- HTTP -----------------------------------------------------------
    def handle(self, h: http.server.BaseHTTPRequestHandler) -> None:
        parts = urllib.parse.urlsplit(h.path)
        self.log.append(Req(parts.path, parts.query, h.headers.get("Host", ""), h.headers.get("Authorization"), h.headers.get("Accept")))
        prefix = f"/repos/{OWNER}/{REPO}"
        try:
            if parts.path == f"{prefix}/releases":
                self._list(h, parts)
            elif parts.path.startswith(f"{prefix}/releases/assets/"):
                self._asset(h, parts)
            elif parts.path.startswith("/blob/"):
                self._blob(h, parts)
            else:
                self._send(h, 404, b'{"message":"Not Found"}', "application/json")
        except (BrokenPipeError, ConnectionResetError):
            pass

    @staticmethod
    def _send(h: Any, status: int, body: bytes, ctype: str, headers: dict[str, str] | None = None) -> None:
        h.send_response(status)
        h.send_header("Content-Type", ctype)
        h.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            h.send_header(key, value)
        h.end_headers()
        h.wfile.write(body)

    def _list(self, h: Any, parts: urllib.parse.SplitResult) -> None:
        if self.list_error is not None:
            status, error_headers, error_body = self.list_error
            self._send(h, status, error_body, "application/json", error_headers)
            return
        query = urllib.parse.parse_qs(parts.query)
        per_page = self.page_size or int(query.get("per_page", ["30"])[0])
        page = int(query.get("page", ["1"])[0])
        ordered = sorted(self.releases, key=lambda r: r.published, reverse=True)  # newest first, drafts too
        chunk = ordered[(page - 1) * per_page : page * per_page]
        headers: dict[str, str] = {"X-RateLimit-Remaining": "50"}
        if page * per_page < len(ordered):
            host = self.next_link_host or f"127.0.0.1:{self.port}"
            headers["Link"] = f'<http://{host}{parts.path}?per_page={per_page}&page={page + 1}>; rel="next"'
        self._send(h, 200, json.dumps([r.to_json() for r in chunk]).encode(), "application/json; charset=utf-8", headers)

    def _find_asset(self, ident: int) -> FakeAsset | None:
        return next((a for r in self.releases for a in r.assets if a.id == ident), None)

    def _asset(self, h: Any, parts: urllib.parse.SplitResult) -> None:
        asset = self._find_asset(int(parts.path.rsplit("/", 1)[1]))
        if self.asset_error is not None:
            status, error_headers, error_body = self.asset_error
            self._send(h, status, error_body, "application/json", error_headers)
        elif asset is None:
            self._send(h, 404, b'{"message":"Not Found"}', "application/json")
        elif "application/octet-stream" not in (h.headers.get("Accept") or ""):
            self._send(h, 200, b'{"note":"asset metadata"}', "application/json")
        else:  # like GitHub: a redirect to a signed URL on another host
            where = self.redirect_to or f"http://{self.redirect_host}:{self.port}/blob/{asset.id}/{urllib.parse.quote(asset.name)}?sig=SECRET-SIGNATURE"
            h.send_response(302)
            h.send_header("Location", where)
            h.send_header("Content-Length", "0")
            h.end_headers()

    def _blob(self, h: Any, parts: urllib.parse.SplitResult) -> None:
        asset = self._find_asset(int(parts.path.split("/")[2]))
        if asset is None:
            self._send(h, 404, b"", "text/plain")
            return
        h.send_response(200)
        h.send_header("Content-Type", "application/octet-stream")
        h.send_header("Content-Length", str(len(asset.data)))
        h.end_headers()
        if asset.name in self.truncate:  # drop the connection half way
            h.wfile.write(asset.data[: self.truncate[asset.name]])
            h.wfile.flush()
            return
        if asset.name in self.stall:  # send some, then hang until the test lets go
            count, event = self.stall[asset.name]
            h.wfile.write(asset.data[:count])
            h.wfile.flush()
            event.wait(30)
            return
        h.wfile.write(asset.data)


# ---------------------------------------------------------------------------
# Running the job


@dataclasses.dataclass
class Job:
    code: int
    out: str
    err: str

    @property
    def summary(self) -> dict[str, Any]:
        return json.loads(self.out.strip().splitlines()[-1])


def snapshot(root: Path) -> dict[str, tuple[Any, ...]]:
    """Everything below `root`: kind, size, mtime and content hash."""
    snap: dict[str, tuple[Any, ...]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            st = path.lstat()
            kind = "link" if path.is_symlink() else "dir" if path.is_dir() else "file"
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if kind == "file" else ""
            snap[str(path.relative_to(root))] = (kind, st.st_size, st.st_mtime_ns, digest)
    return snap


def volatile_removed(doc: dict[str, Any]) -> dict[str, Any]:
    """releases.json without the two fields that change on every run."""
    doc = copy.deepcopy(doc)
    doc.pop("generated")
    for rel in doc["releases"]:
        rel.pop("checked_at")
    return doc


@unittest.skipUnless(MINISIGN, "minisign is not installed")
class MirrorCase(unittest.TestCase):
    keys: dict[str, KeyPair]
    _keydir: tempfile.TemporaryDirectory[str]
    _home: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls._keydir = tempfile.TemporaryDirectory(prefix="mirror-keys-")
        cls._home = tempfile.TemporaryDirectory(prefix="mirror-home-")
        keydir, home = Path(cls._keydir.name), Path(cls._home.name)
        cls.keys = {name: KeyPair(keydir, name, home) for name in ("good", "other", "stranger")}

    @classmethod
    def tearDownClass(cls) -> None:
        cls._keydir.cleanup()
        cls._home.cleanup()

    def setUp(self) -> None:
        # world/ holds the mirror root and a canary: nothing may appear next to the root.
        self.world = Path(tempfile.mkdtemp(prefix="mirror-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.world, ignore_errors=True)
        self.root = self.world / "root"
        self.root.mkdir()
        (self.world / "canary.txt").write_text("keep")
        self.fake = FakeGitHub()
        self.addCleanup(self.fake.close)

    # -- building releases ----------------------------------------------
    def add_release(
        self,
        tag: str,
        *,
        template: bool = True,
        iso: bytes | None = None,
        served_iso: bytes | None = None,
        key: str = "good",
        sign: bool = True,
        sums: bytes | None = None,
        published: str = "2026-11-05T10:00:00Z",
        prerelease: bool = False,
        draft: bool = False,
        name: str | None = None,
        version: int | None = 1,
    ) -> FakeRelease:
        """A release as the workflow makes it: the template, a dev image, SHA256SUMS
        over both, and its minisign signature. `served_iso` is what GitHub serves
        when that differs from the ISO the sums describe."""
        seed = zlib.crc32(tag.encode())
        files: dict[str, bytes] = {f"urmqtt-dev-{tag}.iso": random.Random(seed).randbytes(4096)}
        iso_name = f"urmqtt-template-{tag}-universal.iso"
        if template:
            files[iso_name] = iso if iso is not None else make_iso(seed=seed, version=version)
        signed = sums if sums is not None else sums_text(files)
        rel = self.fake.add_release(tag, name=name, published=published, prerelease=prerelease, draft=draft)
        for fname, data in files.items():
            rel.add_asset(fname, served_iso if (fname == iso_name and served_iso is not None) else data)
        rel.add_asset("SHA256SUMS", signed)
        if sign:  # (minisign takes the comment as an argument: hostile tags must not break that)
            comment = "".join(c for c in tag if c.isprintable() and c.isascii())
            rel.add_asset("SHA256SUMS.minisig", self.keys[key].sign(signed, f"urMQTT {comment} dev test"))
        return rel

    def reissue(self, rel: FakeRelease, iso: bytes, key: str = "good", sums_for: bytes | None = None) -> None:
        """The maintainers replace the template and re-sign: new asset ids, new sums."""
        iso_name = f"urmqtt-template-{rel.tag}-universal.iso"
        dev = next(a.data for a in rel.assets if a.name == f"urmqtt-dev-{rel.tag}.iso")
        signed = sums_text({iso_name: sums_for if sums_for is not None else iso, f"urmqtt-dev-{rel.tag}.iso": dev})
        rel.replace_asset(iso_name, iso)
        rel.replace_asset("SHA256SUMS", signed)
        rel.replace_asset("SHA256SUMS.minisig", self.keys[key].sign(signed, f"urMQTT {rel.tag} edited"))

    # -- running -----------------------------------------------------------
    def command(
        self, *args: str, root: Path | None = None, pubkey: Path | None = None, rate: str = "0", keyring: Path | None = None
    ) -> list[str]:
        assert MINISIGN is not None
        keys = ["--keyring", str(keyring)] if keyring is not None else ["--pubkey", str(pubkey or self.keys["good"].pub)]
        return [
            sys.executable, "-I", str(SCRIPT),
            "--root", str(root or self.root),
            "--api-base", self.fake.base,
            *keys,
            "--minisign", MINISIGN,
            "--limit-rate", rate,
            *args,
        ]  # fmt: skip

    def env(self, **extra: str) -> dict[str, str]:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": self._home.name}  # no proxies, no JOURNAL_STREAM
        env.update(extra)
        return env

    def run_job(
        self, *args: str, rate: str = "0", pubkey: Path | None = None, umask: int | None = None, keyring: Path | None = None, **env: str
    ) -> Job:
        def preexec() -> None:
            os.umask(umask if umask is not None else 0o022)

        proc = subprocess.run(
            self.command(*args, rate=rate, pubkey=pubkey, keyring=keyring),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
            env=self.env(**env),
            preexec_fn=preexec,
        )
        return Job(proc.returncode, proc.stdout, proc.stderr)

    def document(self) -> dict[str, Any]:
        return json.loads((self.root / "releases.json").read_text(encoding="utf-8"))

    def entry(self, tag: str) -> dict[str, Any]:
        found = [r for r in self.document()["releases"] if r["tag"] == tag]
        self.assertEqual(len(found), 1, f"{tag} should be listed exactly once")
        return found[0]

    def tag_files(self, tag: str) -> list[str]:
        return sorted(p.name for p in (self.root / tag).iterdir()) if (self.root / tag).is_dir() else []

    def assertPublished(self, tag: str, iso: bytes) -> None:
        name = f"urmqtt-template-{tag}-universal.iso"
        self.assertEqual((self.root / tag / name).read_bytes(), iso)
        self.assertEqual(self.tag_files(tag), sorted([name, "SHA256SUMS", "SHA256SUMS.minisig", "meta.json"]))

    def assertNothingPublished(self, tag: str) -> None:
        self.assertEqual([f for f in self.tag_files(tag) if f != "meta.json"], [], f"{tag} must have no mirrored files")


# ---------------------------------------------------------------------------
# The scenarios


class Scenarios(MirrorCase):
    def test_a_release_without_template_is_listed_and_nothing_big_is_fetched(self) -> None:
        rel = self.add_release("v0.1.0", template=False, prerelease=True)
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        e = self.entry("v0.1.0")
        self.assertIsNone(e["template"])
        self.assertEqual(e["reason"], "no-template")
        self.assertIs(e["verified"], True)  # the signature of its SHA256SUMS is good
        self.assertEqual(e["status"], "ok")
        self.assertIsNone(e["sums"])
        self.assertIsNone(e["mirrored_at"])
        self.assertIs(e["prerelease"], True)
        self.assertEqual([a["mirrored"] for a in e["assets"]], [False] * len(rel.assets))
        dev = next(a for a in e["assets"] if a["name"] == "urmqtt-dev-v0.1.0.iso")
        self.assertEqual(dev["sha256"], sha(next(a.data for a in rel.assets if a.name == dev["name"])))  # from the verified sums
        self.assertCountEqual(self.fake.downloads(), ["SHA256SUMS", "SHA256SUMS.minisig"])  # no ISO
        self.assertNothingPublished("v0.1.0")
        self.assertEqual(self.document()["templates"], 0)

    def test_b_valid_template_is_mirrored_and_described(self) -> None:
        iso = make_iso(seed=7, version=1)
        self.add_release("v0.2.0", iso=iso, name="urMQTT 0.2.0", published="2026-11-05T10:00:00Z")
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        self.assertPublished("v0.2.0", iso)
        raw = (self.root / "releases.json").read_text(encoding="utf-8")
        self.assertTrue(raw.startswith('{\n  "schema": 1,\n  "generated": "'), raw[:60])
        self.assertTrue(raw.endswith("}\n"))
        doc = json.loads(raw)
        self.assertEqual(list(doc), ["schema", "generated", "repo", "source", "key_id", "keys", "releases", "templates"])
        self.assertEqual(
            doc["keys"],
            [{"key_id": self.keys["good"].key_id, "name": "release", "valid_from": None, "valid_to": None, "former_test_key": False}],
        )
        self.assertEqual(doc["repo"], f"{OWNER}/{REPO}")
        self.assertEqual(doc["source"], f"https://github.com/{OWNER}/{REPO}/releases")
        self.assertEqual(doc["key_id"], self.keys["good"].key_id)
        self.assertEqual(doc["templates"], 1)
        e = self.entry("v0.2.0")
        self.assertEqual(
            list(e),
            ["tag", "name", "published", "prerelease", "url", "attestations", "status", "edited",
             "template", "sums", "verified", "reason", "signed_by", "assets", "mirrored_at", "checked_at"],
        )  # fmt: skip
        self.assertEqual(e["signed_by"]["key_id"], self.keys["good"].key_id)
        self.assertEqual(e["name"], "urMQTT 0.2.0")
        self.assertEqual(e["published"], "2026-11-05T10:00:00Z")
        self.assertEqual(e["url"], f"https://github.com/{OWNER}/{REPO}/releases/tag/v0.2.0")
        self.assertEqual(e["attestations"], f"https://github.com/{OWNER}/{REPO}/attestations")
        self.assertEqual((e["status"], e["verified"], e["reason"], e["edited"]), ("ok", True, None, False))
        self.assertEqual(list(e["template"]), ["file", "path", "size", "sha256", "config_format"])
        self.assertEqual(
            e["template"],
            {
                "file": "urmqtt-template-v0.2.0-universal.iso",
                "path": "v0.2.0/urmqtt-template-v0.2.0-universal.iso",
                "size": len(iso),
                "sha256": sha(iso),
                "config_format": 1,
            },
        )
        self.assertEqual(e["sums"], {"path": "v0.2.0/SHA256SUMS", "sig_path": "v0.2.0/SHA256SUMS.minisig"})
        self.assertRegex(e["mirrored_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(e["checked_at"], doc["generated"])  # one instant, and never before the mirroring
        self.assertLessEqual(e["mirrored_at"], e["checked_at"])
        self.assertEqual(list(e["assets"][0]), ["name", "size", "sha256", "mirrored", "github_url"])
        by_name = {a["name"]: a for a in e["assets"]}
        self.assertCountEqual(by_name, ["SHA256SUMS", "SHA256SUMS.minisig", "urmqtt-dev-v0.2.0.iso", "urmqtt-template-v0.2.0-universal.iso"])
        self.assertEqual({n for n, a in by_name.items() if a["mirrored"]}, {"SHA256SUMS", "SHA256SUMS.minisig", "urmqtt-template-v0.2.0-universal.iso"})
        self.assertEqual(by_name["urmqtt-template-v0.2.0-universal.iso"]["sha256"], sha(iso))
        self.assertEqual(by_name["SHA256SUMS"]["size"], len((self.root / "v0.2.0" / "SHA256SUMS").read_bytes()))
        self.assertEqual(by_name["SHA256SUMS"]["github_url"], f"https://github.com/{OWNER}/{REPO}/releases/download/v0.2.0/SHA256SUMS")
        s = job.summary
        self.assertEqual((s["ok"], s["exit_code"], s["listed"], s["new"], s["failed"]), (True, 0, 1, 1, 0))
        self.assertGreaterEqual(s["bytes_downloaded"], len(iso))
        self.assertGreater(s["du_bytes"], len(iso))
        for line in ("releases: 1 listed, 1 new", "downloaded:", "mirror size on disk:", "filesystem free:"):
            self.assertIn(line, job.err)
        self.assertEqual(os.listdir(self.root / ".tmp"), [])  # no work left behind
        self.assertTrue((self.root / ".lock").exists())

    def test_b_files_are_world_readable_whatever_the_umask(self) -> None:
        self.add_release("v0.2.0")
        self.assertEqual(self.run_job(umask=0o077).code, 0)
        for rel_path in ("releases.json", "v0.2.0/SHA256SUMS", "v0.2.0/SHA256SUMS.minisig", "v0.2.0/urmqtt-template-v0.2.0-universal.iso", "v0.2.0/meta.json"):
            self.assertEqual((self.root / rel_path).stat().st_mode & 0o777, 0o644, rel_path)
        self.assertEqual((self.root / "v0.2.0").stat().st_mode & 0o777, 0o755)

    def test_b_releases_are_sorted_newest_first_and_prereleases_marked(self) -> None:
        self.add_release("v0.1.0", published="2026-10-30T00:50:09Z", prerelease=True)
        self.add_release("v0.3.0", published="2026-11-09T09:00:00Z")
        self.add_release("v0.2.0", published="2026-11-05T10:00:00Z")
        self.assertEqual(self.run_job().code, 0)
        doc = self.document()
        self.assertEqual([r["tag"] for r in doc["releases"]], ["v0.3.0", "v0.2.0", "v0.1.0"])
        self.assertEqual([r["prerelease"] for r in doc["releases"]], [False, False, True])
        self.assertEqual(doc["templates"], 3)

    def test_c_iso_that_does_not_match_the_signed_sums_is_not_published(self) -> None:
        good, evil = make_iso(seed=1), make_iso(seed=2)
        self.add_release("v0.3.0", iso=good, served_iso=evil)
        job = self.run_job()
        self.assertEqual(job.code, 2, job.err)
        self.assertNothingPublished("v0.3.0")  # not even the sums
        self.assertEqual(os.listdir(self.root / ".tmp"), [])
        e = self.entry("v0.3.0")
        self.assertEqual((e["status"], e["verified"], e["reason"]), ("unverified", False, "verification-failed"))
        self.assertIsNone(e["template"])
        self.assertIsNone(e["sums"])
        self.assertIsNone(e["mirrored_at"])
        self.assertEqual(self.document()["templates"], 0)
        self.assertIn("NOT published (verification-failed)", job.err)
        self.assertEqual((job.summary["ok"], job.summary["exit_code"], job.summary["failed"]), (False, 2, 1))
        # The failure is remembered: the next run does not download the ISO again, but still alerts.
        self.fake.reset_log()
        again = self.run_job()
        self.assertEqual(again.code, 2, again.err)
        self.assertEqual(self.fake.downloads(), [])
        self.assertIn("still flagged verification-failed", again.err)
        # Fixed upstream (the right ISO is served): the release heals by itself.
        self.fake.releases[0].replace_asset("urmqtt-template-v0.3.0-universal.iso", good)
        fixed = self.run_job()
        self.assertEqual(fixed.code, 0, fixed.err)
        self.assertPublished("v0.3.0", good)
        self.assertEqual(self.entry("v0.3.0")["status"], "ok")

    def test_d_sums_signed_by_another_key_are_not_published_and_the_iso_is_never_fetched(self) -> None:
        iso = make_iso(seed=3)
        self.add_release("v0.4.0", iso=iso, key="other")
        job = self.run_job()
        self.assertEqual(job.code, 2, job.err)
        self.assertCountEqual(self.fake.downloads(), ["SHA256SUMS", "SHA256SUMS.minisig"])  # verify first, then fetch
        self.assertNothingPublished("v0.4.0")
        e = self.entry("v0.4.0")
        self.assertEqual((e["status"], e["verified"], e["reason"], e["template"]), ("unverified", False, "verification-failed", None))
        self.assertIn(f"made with key {self.keys['other'].key_id}, which is not in the key ring", job.err)
        # The operator installs the right key: the failed release is checked again without any upstream change.
        self.fake.reset_log()
        healed = self.run_job(pubkey=self.keys["other"].pub)
        self.assertEqual(healed.code, 0, healed.err)
        self.assertPublished("v0.4.0", iso)
        self.assertEqual(self.document()["key_id"], self.keys["other"].key_id)

    def test_d_tampered_sums_fail_the_signature(self) -> None:
        iso = make_iso(seed=3)
        rel = self.add_release("v0.4.0", iso=iso)
        rel.replace_asset("SHA256SUMS", sums_text({"urmqtt-template-v0.4.0-universal.iso": iso, "evil": b"x"}))  # signature no longer matches
        self.assertEqual(self.run_job().code, 2)
        self.assertNothingPublished("v0.4.0")
        self.assertEqual(self.entry("v0.4.0")["reason"], "verification-failed")

    def test_e_nothing_changed_means_one_list_request_and_the_same_document(self) -> None:
        self.add_release("v0.1.0", template=False, prerelease=True, published="2026-10-30T00:50:09Z")
        self.add_release("v0.2.0", published="2026-11-05T10:00:00Z")
        first = self.run_job()
        self.assertEqual(first.code, 0, first.err)
        doc1 = self.document()
        meta1 = (self.root / "v0.2.0" / "meta.json").read_bytes()
        files1 = {p: v for p, v in snapshot(self.root).items() if p.startswith("v0.2.0/")}
        self.fake.reset_log()
        time.sleep(1.1)  # so that generated/checked_at differ
        second = self.run_job()
        self.assertEqual(second.code, 0, second.err)
        self.assertEqual(self.fake.downloads(), [])  # no asset at all
        self.assertEqual(self.fake.list_requests(), 1)
        self.assertEqual(len(self.fake.log), 1)
        doc2 = self.document()
        self.assertNotEqual(doc1["generated"], doc2["generated"])
        self.assertNotEqual(doc1["releases"][0]["checked_at"], doc2["releases"][0]["checked_at"])
        self.assertEqual(volatile_removed(doc1), volatile_removed(doc2))
        self.assertEqual(meta1, (self.root / "v0.2.0" / "meta.json").read_bytes())  # state untouched
        self.assertEqual(files1, {p: v for p, v in snapshot(self.root).items() if p.startswith("v0.2.0/")})  # not rewritten
        self.assertEqual((second.summary["new"], second.summary["updated"], second.summary["retried"]), (0, 0, 0))

    def test_e_editing_title_or_notes_does_not_download_again(self) -> None:
        rel = self.add_release("v0.2.0")
        self.assertEqual(self.run_job().code, 0)
        rel.name, rel.updated, rel.prerelease = "urMQTT 0.2.0 (renamed)", self.fake.tick(), True
        self.fake.reset_log()
        self.assertEqual(self.run_job().code, 0)
        self.assertEqual(self.fake.downloads(), [])
        e = self.entry("v0.2.0")
        self.assertEqual((e["name"], e["prerelease"], e["edited"]), ("urMQTT 0.2.0 (renamed)", True, False))

    def test_f_release_deleted_upstream_is_kept_and_flagged(self) -> None:
        iso = make_iso(seed=5)
        rel = self.add_release("v0.2.0", iso=iso, name="urMQTT 0.2.0")
        self.assertEqual(self.run_job().code, 0)
        before = self.entry("v0.2.0")
        self.fake.releases.remove(rel)
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        self.assertPublished("v0.2.0", iso)  # files stay
        e = self.entry("v0.2.0")
        self.assertEqual((e["status"], e["reason"]), ("removed", "removed-upstream"))
        self.assertRegex(e["removed_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(e["name"], "urMQTT 0.2.0")  # descriptive fields come from the stored copy
        self.assertEqual(e["template"], before["template"])  # the files on disk are still described
        self.assertEqual(e["mirrored_at"], before["mirrored_at"])
        self.assertEqual(self.document()["templates"], 0)  # a removed release is not offered
        self.assertIn("no longer on GitHub", job.err)
        self.assertEqual(job.summary["removed"], 1)
        # and it stays that way, with the first removal time
        again = self.run_job()
        self.assertEqual(again.code, 0, again.err)
        self.assertEqual(self.entry("v0.2.0")["removed_at"], e["removed_at"])
        # back upstream with the same files: current again
        self.fake.releases.append(rel)
        back = self.run_job()
        self.assertEqual(back.code, 0, back.err)
        e = self.entry("v0.2.0")
        self.assertEqual((e["status"], e["reason"]), ("ok", None))
        self.assertNotIn("removed_at", e)

    def test_f_a_release_that_was_never_mirrored_is_simply_forgotten(self) -> None:
        rel = self.add_release("v0.1.0", template=False)
        self.assertEqual(self.run_job().code, 0)
        self.assertTrue((self.root / "v0.1.0" / "meta.json").exists())
        self.fake.releases.remove(rel)
        self.assertEqual(self.run_job().code, 0)
        self.assertFalse((self.root / "v0.1.0").exists())
        self.assertEqual(self.document()["releases"], [])

    def test_f_a_template_withdrawn_from_a_release_is_flagged_not_offered(self) -> None:
        iso = make_iso(seed=5)
        rel = self.add_release("v0.2.0", iso=iso)
        self.assertEqual(self.run_job().code, 0)
        rel.replace_asset("SHA256SUMS", sums_text({"urmqtt-dev-v0.2.0.iso": b"x"}))
        rel.assets = [a for a in rel.assets if not a.name.startswith("urmqtt-template-")]
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        e = self.entry("v0.2.0")
        self.assertEqual((e["status"], e["reason"]), ("removed", "removed-upstream"))
        self.assertPublished("v0.2.0", iso)
        self.assertEqual(self.document()["templates"], 0)

    def test_g_release_edited_upstream_is_mirrored_again_and_flagged(self) -> None:
        old, new = make_iso(seed=1, version=1), make_iso(seed=2, version=2, size=(3 << 19))
        rel = self.add_release("v0.2.0", iso=old)
        self.assertEqual(self.run_job().code, 0)
        first = self.entry("v0.2.0")
        self.assertIs(first["edited"], False)
        self.assertNotIn("edited_at", first)
        time.sleep(1.1)
        self.reissue(rel, new)
        self.fake.reset_log()
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        self.assertPublished("v0.2.0", new)
        e = self.entry("v0.2.0")
        self.assertIs(e["edited"], True)
        self.assertRegex(e["edited_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(e["status"], "ok")
        self.assertEqual((e["template"]["sha256"], e["template"]["size"], e["template"]["config_format"]), (sha(new), len(new), 2))
        self.assertGreater(e["mirrored_at"], first["mirrored_at"])
        self.assertIn("flagged as edited", job.err)
        self.assertEqual(job.summary["updated"], 1)
        self.assertEqual(self.run_job().code, 0)  # and the flag is sticky
        self.assertIs(self.entry("v0.2.0")["edited"], True)

    def test_g_an_edit_that_does_not_verify_leaves_the_old_files_and_flags_the_release(self) -> None:
        old, evil = make_iso(seed=1), make_iso(seed=2)
        rel = self.add_release("v0.2.0", iso=old)
        self.assertEqual(self.run_job().code, 0)
        before = self.entry("v0.2.0")
        old_files = {p: v for p, v in snapshot(self.root).items() if p.startswith("v0.2.0/") and not p.endswith("meta.json")}
        self.reissue(rel, evil, sums_for=old)  # signed sums describe `old`, GitHub serves `evil`
        job = self.run_job()
        self.assertEqual(job.code, 2, job.err)
        self.assertEqual(old_files, {p: v for p, v in snapshot(self.root).items() if p.startswith("v0.2.0/") and not p.endswith("meta.json")})
        self.assertPublished("v0.2.0", old)
        e = self.entry("v0.2.0")
        self.assertEqual((e["status"], e["verified"], e["reason"], e["edited"]), ("unverified", False, "verification-failed", False))
        self.assertEqual(e["template"], before["template"])  # describes what is on disk
        self.assertEqual(self.document()["templates"], 0)  # not offered while flagged

    def test_g_any_change_to_the_asset_set_counts_as_an_edit(self) -> None:
        iso = make_iso(seed=1)
        rel = self.add_release("v0.2.0", iso=iso)
        self.assertEqual(self.run_job().code, 0)
        rel.add_asset("urmqtt-dev-v0.2.0.cdx.json", b"{}")  # an SBOM attached later
        self.fake.reset_log()
        self.assertEqual(self.run_job().code, 0)
        self.assertIs(self.entry("v0.2.0")["edited"], True)
        self.assertIn("urmqtt-template-v0.2.0-universal.iso", self.fake.downloads())

    def test_h_dropped_connection_publishes_nothing_and_the_next_run_recovers(self) -> None:
        iso = make_iso(seed=1)
        name = "urmqtt-template-v0.4.0-universal.iso"
        self.add_release("v0.4.0", iso=iso)
        self.fake.truncate[name] = len(iso) // 2
        job = self.run_job()
        self.assertEqual(job.code, 1, job.err)
        self.assertFalse((self.root / "v0.4.0" / name).exists())
        self.assertNothingPublished("v0.4.0")
        self.assertEqual(os.listdir(self.root / ".tmp"), [])  # the partial file is deleted at once
        e = self.entry("v0.4.0")
        self.assertEqual((e["status"], e["verified"], e["reason"], e["template"]), ("unverified", False, "download-failed", None))
        self.assertIn("cut short", job.err)
        # A previous run that was killed leaves files in .tmp; the next run removes them.
        stale = self.root / ".tmp" / "v9.9.9"
        stale.mkdir()
        (stale / "urmqtt-template-v9.9.9-universal.iso.part").write_bytes(b"x" * 1000)
        (self.root / ".tmp" / "orphan.part").write_bytes(b"y")
        self.fake.truncate.clear()
        healed = self.run_job()
        self.assertEqual(healed.code, 0, healed.err)  # download-failed is retried although nothing changed upstream
        self.assertIn("stale entries", healed.err)
        self.assertEqual(os.listdir(self.root / ".tmp"), [])
        self.assertPublished("v0.4.0", iso)

    def test_h_killed_mid_download_leaves_no_final_file_and_the_next_run_cleans_up(self) -> None:
        iso = make_iso(seed=1)
        name = "urmqtt-template-v0.4.0-universal.iso"
        self.add_release("v0.4.0", iso=iso)
        release_event = threading.Event()
        self.fake.stall[name] = (300_000, release_event)
        proc = subprocess.Popen(
            self.command(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env()
        )
        part = self.root / ".tmp" / "v0.4.0" / f"{name}.part"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (part.exists() and part.stat().st_size >= 100_000):
            time.sleep(0.02)
        self.assertTrue(part.exists() and part.stat().st_size >= 100_000, "the download never started")
        proc.kill()
        proc.communicate()
        release_event.set()
        self.assertFalse((self.root / "v0.4.0" / name).exists())
        self.assertNothingPublished("v0.4.0")
        self.assertTrue(part.exists(), "a killed job leaves its partial file in .tmp, and nowhere else")
        self.assertFalse((self.root / "releases.json").exists())
        self.fake.stall.clear()
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)  # the killed job's lock died with it
        self.assertFalse(part.exists())
        self.assertIn("stale entries", job.err)
        self.assertPublished("v0.4.0", iso)

    def test_i_hostile_tags_and_names_never_leave_the_root(self) -> None:
        hostile_tags = ["../x", "/etc/evil", "a/b", "..", ".hidden", "-rf", "v1\n", "x" * 65, "v\u00e91", "releases.json", "", "a b", "v1;rm -rf", "t\x00x", "..\\x", "v1.0/../../y"]
        hostile_ids: set[int] = set()
        for tag in hostile_tags:
            rel = self.add_release(tag, published="2026-11-06T00:00:00Z")
            hostile_ids.update(a.id for a in rel.assets)
        good = self.add_release("v1.0.0", published="2026-11-05T00:00:00Z")
        for bad in (
            "../../evil", "/abs/SHA256SUMS", "SHA256SUMS\n", "urmqtt-template-../../evil-universal.iso",
            "urmqtt-template-v1.0.0-universal.iso.evil", "urmqtt-template-v1.0.0-universal.iso\n", "sub/dir.iso", "a b.iso", "<script>.iso",
        ):  # fmt: skip
            hostile_ids.add(good.add_asset(bad, b"evil").id)
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        self.assertEqual(sorted(p.name for p in self.world.iterdir()), ["canary.txt", "root"])
        self.assertEqual((self.world / "canary.txt").read_text(), "keep")
        self.assertFalse(Path("/etc/evil").exists())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [".lock", ".tmp", "releases.json", "v1.0.0"])
        self.assertEqual([r["tag"] for r in self.document()["releases"]], ["v1.0.0"])
        # Only harmless names are listed at all; of those only the three the job acts on are mirrored.
        listed = {a["name"]: a["mirrored"] for a in self.entry("v1.0.0")["assets"]}
        self.assertEqual(
            listed,
            {
                "SHA256SUMS": True,
                "SHA256SUMS.minisig": True,
                "urmqtt-dev-v1.0.0.iso": False,
                "urmqtt-template-v1.0.0-universal.iso": True,
                "urmqtt-template-v1.0.0-universal.iso.evil": False,  # looks like the template but is not one
            },
        )
        fetched = {int(r.path.rsplit("/", 1)[1]) for r in self.fake.log if "/releases/assets/" in r.path}
        self.assertEqual(fetched & hostile_ids, set())
        self.assertEqual(job.summary["skipped_invalid"], len(hostile_tags))
        self.assertEqual(self.entry("v1.0.0")["status"], "ok")

    def test_i_a_symlinked_tag_directory_is_refused_and_the_other_releases_go_on(self) -> None:
        self.add_release("v0.2.0", published="2026-11-02T00:00:00Z")
        self.add_release("v0.3.0", published="2026-11-03T00:00:00Z")
        outside = self.world / "outside"
        outside.mkdir()
        (self.root / "v0.2.0").symlink_to(outside)
        job = self.run_job()
        self.assertEqual(job.code, 1, job.err)
        self.assertEqual(list(outside.iterdir()), [])  # nothing was written through the link
        self.assertEqual(self.entry("v0.3.0")["status"], "ok")
        self.assertEqual(self.entry("v0.2.0")["status"], "unverified")
        self.assertEqual(self.entry("v0.2.0")["reason"], "download-failed")

    def test_j_limit_rate_holds(self) -> None:
        iso = make_iso(1 << 20, seed=1)
        self.add_release("v0.5.0", iso=iso)
        started = time.monotonic()
        job = self.run_job(rate="524288")
        elapsed = time.monotonic() - started
        self.assertEqual(job.code, 0, job.err)
        self.assertGreaterEqual(elapsed, 1.5, "1 MiB at 512 KiB/s takes about 2 s")
        self.assertLess(elapsed, 30)
        self.assertPublished("v0.5.0", iso)

    def test_k_dry_run_writes_nothing_and_downloads_nothing(self) -> None:
        self.add_release("v0.6.0")
        before = snapshot(self.root)
        job = self.run_job("--dry-run")
        self.assertEqual(job.code, 0, job.err)
        self.assertEqual(before, {})
        self.assertEqual(snapshot(self.root), before)  # not even .lock or .tmp
        self.assertEqual(self.fake.downloads(), [])
        self.assertEqual(self.fake.list_requests(), 1)
        self.assertIs(job.summary["dry_run"], True)
        self.assertEqual(job.summary["would_process"], [{"tag": "v0.6.0", "why": "new"}])
        self.assertIn("would process release v0.6.0", job.err)
        # and with a mirror that has content (a new release and a removed one)
        self.assertEqual(self.run_job().code, 0)
        self.fake.releases.clear()
        self.add_release("v0.7.0")
        state = snapshot(self.root)
        job = self.run_job("--dry-run")
        self.assertEqual(job.code, 0, job.err)
        self.assertEqual(snapshot(self.root), state)

    def test_k_dry_run_reports_what_a_real_run_would_do(self) -> None:
        good, evil = make_iso(seed=1), make_iso(seed=2)
        self.add_release("v0.1.0", published="2026-10-01T00:00:00Z")
        gone = self.add_release("v0.2.0", published="2026-10-02T00:00:00Z")
        self.add_release("v0.3.0", iso=good, served_iso=evil, published="2026-10-03T00:00:00Z")
        self.assertEqual(self.run_job().code, 2)
        self.fake.releases.remove(gone)
        self.add_release("v0.4.0", published="2026-10-04T00:00:00Z")
        before = snapshot(self.root)
        job = self.run_job("--dry-run")
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(job.code, 2, job.err)  # the remembered failure still counts
        self.assertEqual((job.summary["failed"], job.summary["removed"], job.summary["new"]), (1, 1, 1))
        self.assertEqual(job.summary["would_process"], [{"tag": "v0.4.0", "why": "new"}])
        self.assertIn("v0.2.0 is no longer on GitHub; would flag it as removed", job.err)
        self.assertIn("still flagged verification-failed", job.err)

    def test_k_dry_run_does_not_need_minisign_or_a_lock(self) -> None:
        self.add_release("v0.6.0")
        (self.root / ".lock").write_text("")
        handle = os.open(self.root / ".lock", os.O_RDWR)
        self.addCleanup(os.close, handle)
        fcntl.flock(handle, fcntl.LOCK_EX)
        cmd = self.command("--dry-run")
        cmd[cmd.index("--minisign") + 1] = "no-such-minisign"
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=self.env(), timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("would process", proc.stderr)


class Behaviour(MirrorCase):
    def test_drafts_are_ignored(self) -> None:
        draft = self.add_release("v0.9.0", draft=True, published="2026-11-09T00:00:00Z")
        self.add_release("v0.2.0")
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        self.assertEqual([r["tag"] for r in self.document()["releases"]], ["v0.2.0"])
        self.assertFalse((self.root / "v0.9.0").exists())
        self.assertFalse(set(a.id for a in draft.assets) & {int(r.path.rsplit("/", 1)[1]) for r in self.fake.log if "/assets/" in r.path})
        self.assertEqual(job.summary["skipped_invalid"], 0)

    def test_pagination_is_followed(self) -> None:
        self.fake.page_size = 1
        self.add_release("v0.1.0", published="2026-10-01T00:00:00Z", template=False)
        self.add_release("v0.2.0", published="2026-11-01T00:00:00Z")
        self.add_release("v0.3.0", published="2026-11-02T00:00:00Z")
        self.add_release("v0.9.0", published="2026-11-09T00:00:00Z", draft=True)
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        self.assertEqual(self.fake.list_requests(), 4)
        self.assertEqual([r["tag"] for r in self.document()["releases"]], ["v0.3.0", "v0.2.0", "v0.1.0"])
        self.assertEqual(self.document()["templates"], 2)

    def test_a_next_page_on_another_host_is_refused(self) -> None:
        self.fake.page_size = 1
        self.fake.next_link_host = f"localhost:{self.fake.port}"
        self.add_release("v0.2.0", published="2026-11-01T00:00:00Z")
        self.add_release("v0.3.0", published="2026-11-02T00:00:00Z")
        job = self.run_job()
        self.assertEqual(job.code, 1, job.err)
        self.assertIn("another host", job.err)
        self.assertFalse((self.root / "releases.json").exists())
        self.assertEqual(self.fake.downloads(), [])

    def prepare_mirrored_root(self) -> dict[str, tuple[Any, ...]]:
        self.add_release("v0.2.0", published="2026-11-05T00:00:00Z")
        self.add_release("v0.1.0", template=False, published="2026-10-01T00:00:00Z")
        self.assertEqual(self.run_job().code, 0)
        return {p: v for p, v in snapshot(self.root).items() if not p.startswith(".")}

    def test_an_api_error_changes_nothing(self) -> None:
        mirrored = self.prepare_mirrored_root()
        self.fake.list_error = (503, {}, b'{"message":"Service Unavailable"}')
        job = self.run_job()
        self.assertEqual(job.code, 1, job.err)
        self.assertIn("HTTP 503", job.err)
        self.assertIn("nothing was changed", job.err)
        self.assertEqual({p: v for p, v in snapshot(self.root).items() if not p.startswith(".")}, mirrored)  # releases.json too
        self.assertEqual(job.summary["exit_code"], 1)
        self.assertIn("error", job.summary)

    def test_the_rate_limit_is_reported_and_changes_nothing(self) -> None:
        mirrored = self.prepare_mirrored_root()
        self.fake.releases.clear()  # an answer that would have removed everything, had it come through
        body = b'{"message":"API rate limit exceeded for 203.0.113.9."}'
        for status in (403, 429):
            self.fake.list_error = (status, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1793543874"}, body)
            job = self.run_job()
            self.assertEqual(job.code, 1, job.err)
            self.assertIn("rate limit", job.err)
            self.assertIn("resets at", job.err)
            self.assertEqual({p: v for p, v in snapshot(self.root).items() if not p.startswith(".")}, mirrored)

    def test_an_unreachable_api_is_an_operational_error(self) -> None:
        self.fake.close()
        job = self.run_job()
        self.assertEqual(job.code, 1, job.err)
        self.assertIn("cannot list the releases", job.err)
        self.assertFalse((self.root / "releases.json").exists())

    def test_a_release_with_a_template_but_no_signature_is_not_published(self) -> None:
        self.add_release("v0.2.0", sign=False)
        job = self.run_job()
        self.assertEqual(job.code, 2, job.err)
        e = self.entry("v0.2.0")
        self.assertEqual((e["status"], e["reason"], e["verified"], e["template"]), ("unverified", "no-signature", False, None))
        self.assertNothingPublished("v0.2.0")
        self.assertEqual(self.fake.downloads(), [])  # nothing is fetched for a release that cannot be verified

    def test_a_template_without_a_configuration_slot_is_not_published(self) -> None:
        iso = make_iso(seed=4, version=None)
        self.add_release("v0.2.0", iso=iso)
        job = self.run_job()
        self.assertEqual(job.code, 2, job.err)
        e = self.entry("v0.2.0")
        self.assertEqual((e["status"], e["reason"], e["verified"], e["template"]), ("unverified", "no-config-slot", False, None))
        self.assertNothingPublished("v0.2.0")
        by_name = {a["name"]: a for a in e["assets"]}
        self.assertEqual(by_name["urmqtt-template-v0.2.0-universal.iso"]["sha256"], sha(iso))  # the sums were verified
        self.assertFalse(any(a["mirrored"] for a in e["assets"]))

    def test_an_unsigned_release_without_template_is_listed_unverified_without_an_alert(self) -> None:
        self.add_release("v0.0.1", template=False, sign=False)
        self.add_release("v0.0.2", template=False, key="other")  # a signature by another key
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        for tag in ("v0.0.1", "v0.0.2"):
            e = self.entry(tag)
            self.assertEqual((e["status"], e["reason"], e["verified"], e["template"]), ("unverified", "no-template", False, None))
        self.assertIn("v0.0.2: no template; SHA256SUMS not verified", job.err)

    def test_a_download_with_a_wrong_size_is_rejected(self) -> None:
        iso = make_iso(seed=4)
        rel = self.add_release("v0.2.0", iso=iso)
        next(a for a in rel.assets if a.name.startswith("urmqtt-template-")).size_override = len(iso) + 10
        job = self.run_job()
        self.assertEqual(job.code, 1, job.err)
        self.assertEqual(self.entry("v0.2.0")["reason"], "download-failed")
        self.assertNothingPublished("v0.2.0")

    def test_an_asset_still_being_uploaded_does_not_count(self) -> None:
        iso = make_iso(seed=4)
        rel = self.add_release("v0.2.0", iso=iso)
        next(a for a in rel.assets if a.name.startswith("urmqtt-template-")).state = "starter"
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        self.assertEqual(self.entry("v0.2.0")["reason"], "no-template")

    def test_two_templates_prefer_the_one_named_for_the_tag(self) -> None:
        iso = make_iso(seed=4)
        rel = self.add_release("v0.2.0", iso=iso)
        rel.add_asset("urmqtt-template-v0.1.9-universal.iso", make_iso(seed=9))
        self.assertEqual(self.run_job().code, 0)
        self.assertEqual(self.entry("v0.2.0")["template"]["file"], "urmqtt-template-v0.2.0-universal.iso")
        rel2 = self.add_release("v0.3.0", iso=iso)
        rel2.add_asset("urmqtt-template-v0.3.1-universal.iso", make_iso(seed=9))
        rel2.add_asset("urmqtt-template-v0.3.2-universal.iso", make_iso(seed=8))
        rel2.assets = [a for a in rel2.assets if a.name != "urmqtt-template-v0.3.0-universal.iso"]
        self.assertEqual(self.run_job().code, 2)
        self.assertEqual(self.entry("v0.3.0")["reason"], "verification-failed")

    def test_the_token_goes_to_the_api_only_and_is_never_logged(self) -> None:
        token = "ghp_" + "a1B2c3D4" * 4
        token_file = self.world / "token"
        token_file.write_text(token + "\n")
        self.add_release("v0.2.0")
        job = self.run_job("--token-file", str(token_file), "--verbose")
        self.assertEqual(job.code, 0, job.err)
        api = [r for r in self.fake.log if not r.path.startswith("/blob/")]
        blobs = [r for r in self.fake.log if r.path.startswith("/blob/")]
        self.assertTrue(api and blobs)
        self.assertTrue(all(r.auth == f"Bearer {token}" for r in api), api)
        self.assertTrue(all(r.host.startswith("localhost:") and r.auth is None for r in blobs), blobs)  # other host: no token
        self.assertTrue(all(r.accept == "application/octet-stream" for r in api if "/assets/" in r.path))
        for text in (job.out, job.err, (self.root / "releases.json").read_text(), (self.root / "v0.2.0" / "meta.json").read_text()):
            self.assertNotIn(token, text)
            self.assertNotIn("SECRET-SIGNATURE", text)  # the query of a signed URL is never printed either

    def test_a_bad_token_file_is_refused_without_echoing_it(self) -> None:
        token_file = self.world / "token"
        token_file.write_text("two words\nand more\n")
        job = self.run_job("--token-file", str(token_file))
        self.assertEqual(job.code, 1)
        self.assertNotIn("two words", job.err)
        self.assertEqual(self.fake.log, [])

    def test_a_redirect_to_plain_http_elsewhere_is_refused(self) -> None:
        self.fake.redirect_to = "http://192.0.2.1:9/blob/1/x"  # TEST-NET: must not even be tried
        self.add_release("v0.2.0")
        started = time.monotonic()
        job = self.run_job()
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(job.code, 1, job.err)
        self.assertIn("refusing a redirect to http://192.0.2.1:9/blob/1/x", job.err)
        self.assertEqual(self.entry("v0.2.0")["reason"], "download-failed")
        self.assertEqual(self.fake.downloads()[0:1], ["SHA256SUMS"])

    def test_a_rate_limit_during_downloads_stops_the_requests_and_heals_later(self) -> None:
        self.add_release("v0.2.0", published="2026-11-02T00:00:00Z")
        self.add_release("v0.3.0", published="2026-11-03T00:00:00Z")
        limited = b'{"message":"API rate limit exceeded"}'
        self.fake.asset_error = (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1793543874"}, limited)
        job = self.run_job()
        self.assertEqual(job.code, 1, job.err)
        self.assertEqual(len(self.fake.downloads()), 1, "after the first 403 the job must not ask again")
        self.assertIn("rate limit", job.err)
        for tag in ("v0.2.0", "v0.3.0"):
            self.assertEqual(self.entry(tag)["reason"], "download-failed")
            self.assertNothingPublished(tag)
        self.fake.asset_error = None  # the limit resets: both are retried although nothing changed upstream
        healed = self.run_job()
        self.assertEqual(healed.code, 0, healed.err)
        self.assertEqual(self.document()["templates"], 2)

    def test_release_names_with_non_ascii_text_are_written_as_utf8(self) -> None:
        nice = "urMQTT 0.2.0 – première 日本"
        self.add_release("v0.2.0", name=nice, published="2026-11-02T00:00:00Z")
        self.add_release("v0.3.0", name="lone \ud800 surrogate‮", published="2026-11-03T00:00:00Z")
        self.assertEqual(self.run_job().code, 0)
        raw = (self.root / "releases.json").read_bytes()
        self.assertIn(nice.encode("utf-8"), raw)  # plain UTF-8, not \\u escapes
        self.assertEqual(self.entry("v0.2.0")["name"], nice)
        name = self.entry("v0.3.0")["name"]
        self.assertTrue(name.startswith("lone ") and name.endswith("surrogate"), name)  # surrogate and bidi override dropped

    def test_a_download_failure_does_not_stop_the_other_releases(self) -> None:
        iso = make_iso(seed=1)
        self.add_release("v0.2.0", published="2026-11-02T00:00:00Z")
        self.add_release("v0.3.0", iso=iso, published="2026-11-03T00:00:00Z")
        self.fake.truncate["urmqtt-template-v0.3.0-universal.iso"] = 1000
        job = self.run_job()
        self.assertEqual(job.code, 1, job.err)
        self.assertEqual(self.entry("v0.3.0")["reason"], "download-failed")
        self.assertEqual(self.entry("v0.2.0")["status"], "ok")

    def test_exit_two_wins_over_exit_one(self) -> None:
        self.add_release("v0.2.0", published="2026-11-02T00:00:00Z", key="other")
        self.add_release("v0.3.0", published="2026-11-03T00:00:00Z")
        self.fake.truncate["urmqtt-template-v0.3.0-universal.iso"] = 1000
        self.assertEqual(self.run_job().code, 2)

    def test_the_lock_keeps_a_second_instance_out(self) -> None:
        self.add_release("v0.2.0")
        handle = os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT, 0o644)
        self.addCleanup(os.close, handle)
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        self.assertIn("already running", job.err)
        self.assertIs(job.summary["already_running"], True)
        self.assertEqual(self.fake.log, [])
        self.assertFalse((self.root / "releases.json").exists())
        fcntl.flock(handle, fcntl.LOCK_UN)
        self.assertEqual(self.run_job().code, 0)
        self.assertTrue((self.root / "releases.json").exists())

    def test_the_free_space_guard_refuses_a_download_that_would_not_fit(self) -> None:
        iso = make_iso(seed=1)
        self.add_release("v0.2.0", iso=iso)
        job = self.run_job("--min-free", str(10**15))
        self.assertEqual(job.code, 1, job.err)
        self.assertIn("not enough free space", job.err)
        self.assertNothingPublished("v0.2.0")
        self.assertNotIn("urmqtt-template-v0.2.0-universal.iso", self.fake.downloads())
        self.assertEqual(self.entry("v0.2.0")["reason"], "download-failed")
        self.assertEqual(self.run_job("--min-free", "0").code, 0)  # retried although nothing changed upstream
        self.assertPublished("v0.2.0", iso)

    def test_journald_priorities(self) -> None:
        self.add_release("v0.2.0", iso=make_iso(seed=1), served_iso=make_iso(seed=2))
        job = self.run_job(JOURNAL_STREAM="8:1234567")
        self.assertEqual(job.code, 2)
        lines = job.err.splitlines()
        self.assertTrue(lines and all(len(ln) > 3 and ln[0] == "<" and ln[2] == ">" for ln in lines), lines)
        self.assertTrue(any(ln.startswith("<3>release v0.2.0: NOT published") for ln in lines))
        self.assertTrue(any(ln.startswith("<6>releases: 1 listed") for ln in lines))
        plain = self.run_job()
        self.assertTrue(all(ln[:4].isdigit() for ln in plain.err.splitlines()), plain.err)  # a timestamp, no <n> prefix

    def test_remote_text_cannot_forge_log_lines(self) -> None:
        self.add_release("v0.2.0", template=False, name="evil\n<3>forged line", sign=False)
        job = self.run_job(JOURNAL_STREAM="8:1")
        self.assertEqual(job.code, 0, job.err)
        self.assertEqual([ln for ln in job.err.splitlines() if "forged" in ln], [])  # the name is not logged, and stays one line anyway
        self.assertEqual(self.entry("v0.2.0")["name"], "evil<3>forged line")  # control characters are dropped from the name

    def test_usage_errors_exit_one_not_two(self) -> None:
        for args in (["--limit-rate", "-5"], ["--api-base", "http://example.com"], ["--repo", "no-slash"], ["--bogus"]):
            proc = subprocess.run(self.command(*args), capture_output=True, text=True, env=self.env(), timeout=30)
            self.assertEqual(proc.returncode, 1, (args, proc.stderr))
        proc = subprocess.run(self.command(root=self.world / "missing"), capture_output=True, text=True, env=self.env(), timeout=30)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("is not a directory", proc.stderr)
        proc = subprocess.run(self.command(pubkey=self.world / "nokey.pub"), capture_output=True, text=True, env=self.env(), timeout=30)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("public key", proc.stderr)

    def test_a_corrupt_state_file_is_an_error_but_the_release_is_redone(self) -> None:
        self.add_release("v0.2.0")
        self.assertEqual(self.run_job().code, 0)
        (self.root / "v0.2.0" / "meta.json").write_text("{not json")
        job = self.run_job()
        self.assertEqual(job.code, 1, job.err)
        self.assertIn("cannot read", job.err)
        self.assertEqual(self.entry("v0.2.0")["status"], "ok")  # processed again, state rewritten
        self.assertEqual(self.run_job().code, 0)

    def test_a_missing_published_file_is_fetched_again(self) -> None:
        iso = make_iso(seed=1)
        self.add_release("v0.2.0", iso=iso)
        self.assertEqual(self.run_job().code, 0)
        (self.root / "v0.2.0" / "urmqtt-template-v0.2.0-universal.iso").unlink()
        self.fake.reset_log()
        job = self.run_job()
        self.assertEqual(job.code, 0, job.err)
        self.assertPublished("v0.2.0", iso)
        self.assertIn("urmqtt-template-v0.2.0-universal.iso", self.fake.downloads())
        self.assertIs(self.entry("v0.2.0")["edited"], False)

    def test_a_renamed_template_replaces_the_old_file_in_the_tag_directory(self) -> None:
        old, new = make_iso(seed=1), make_iso(seed=2)
        rel = self.add_release("v0.2.0", iso=old)
        self.assertEqual(self.run_job().code, 0)
        rel.assets = [a for a in rel.assets if not a.name.startswith("urmqtt-template-") and not a.name.startswith("SHA256SUMS")]
        rel.add_asset("urmqtt-template-v0.2.0b-universal.iso", new)
        signed = sums_text({"urmqtt-template-v0.2.0b-universal.iso": new})
        rel.add_asset("SHA256SUMS", signed)
        rel.add_asset("SHA256SUMS.minisig", self.keys["good"].sign(signed, "renamed"))
        self.assertEqual(self.run_job().code, 0)
        self.assertEqual(self.tag_files("v0.2.0"), ["SHA256SUMS", "SHA256SUMS.minisig", "meta.json", "urmqtt-template-v0.2.0b-universal.iso"])
        self.assertEqual(self.entry("v0.2.0")["template"]["file"], "urmqtt-template-v0.2.0b-universal.iso")


# ---------------------------------------------------------------------------
# Key rotation: a key ring with the former test key and the release key


class KeyRotation(MirrorCase):
    """keys/release-keys.json on the mirror (docs/release-key-rotation.md): "other" plays
    the former test key (v0.1.0 to v0.4.1 only), "good" the release key (v0.4.2 on),
    "stranger" a key nobody trusts."""

    def keyring(self, *, release: bool = True) -> Path:
        directory = self.world / "etc"
        directory.mkdir(exist_ok=True)
        keys = []
        if release:
            shutil.copy(self.keys["good"].pub, directory / "minisign.pub")
            keys.append({"name": "release", "file": "minisign.pub", "valid_from": "v0.4.2", "valid_to": None, "former_test_key": False})
        shutil.copy(self.keys["other"].pub, directory / "minisign-test.pub")
        keys.append(
            {"name": "test", "file": "minisign-test.pub", "key_id": self.keys["other"].key_id,
             "valid_from": "v0.1.0", "valid_to": "v0.4.1", "former_test_key": True, "note": "former test key"}
        )  # fmt: skip
        path = directory / "release-keys.json"
        path.write_text(json.dumps({"schema": 1, "keys": keys}, indent=2))
        return path

    def add_named_release(self, tag: str, key: str, *, new_names: bool, published: str) -> bytes:
        """A release as the workflow makes it: up to v0.4.1 the dev assets (urmqtt-dev-<tag>.*),
        from the rotation on the release assets (urmqtt-<tag>.elf/.iso/.img), the template,
        the SBOM, SHA256SUMS over all of them and its signature."""
        seed = zlib.crc32(tag.encode())
        template = make_iso(seed=seed)
        stem = f"urmqtt-{tag}" if new_names else f"urmqtt-dev-{tag}"
        files = {
            f"{stem}.elf": random.Random(seed).randbytes(2048),
            f"{stem}.img": random.Random(seed + 1).randbytes(4096),
            f"{stem}.iso": template if new_names else random.Random(seed + 2).randbytes(4096),
            f"{stem}.cdx.json": b"{}",
            f"urmqtt-template-{tag}-universal.iso": template,
        }
        signed = sums_text(files)
        rel = self.fake.add_release(tag, name=tag, published=published, prerelease=True, draft=False)
        for name, data in files.items():
            rel.add_asset(name, data)
        rel.add_asset("SHA256SUMS", signed)
        rel.add_asset("SHA256SUMS.minisig", self.keys[key].sign(signed, f"urMQTT {tag} {'release' if new_names else 'dev'} test"))
        return template

    def test_old_releases_verify_with_the_test_key_and_new_ones_with_the_release_key(self) -> None:
        old = self.add_named_release("v0.4.1", "other", new_names=False, published="2026-11-05T10:00:00Z")
        new = self.add_named_release("v0.5.0", "good", new_names=True, published="2026-11-10T10:00:00Z")
        job = self.run_job(keyring=self.keyring())
        self.assertEqual(job.code, 0, job.err)
        self.assertPublished("v0.4.1", old)
        self.assertPublished("v0.5.0", new)
        doc = self.document()
        self.assertEqual(doc["key_id"], self.keys["good"].key_id, "the current key is the release key")
        self.assertEqual([(k["name"], k["valid_from"], k["valid_to"], k["former_test_key"]) for k in doc["keys"]],
                         [("release", "v0.4.2", None, False), ("test", "v0.1.0", "v0.4.1", True)])  # fmt: skip
        self.assertEqual(self.entry("v0.4.1")["signed_by"], {"key_id": self.keys["other"].key_id, "name": "test", "valid_from": "v0.1.0", "valid_to": "v0.4.1", "former_test_key": True})
        self.assertEqual(self.entry("v0.5.0")["signed_by"]["former_test_key"], False)
        # Both naming schemes are listed in full; only the template and the sums are mirrored.
        for tag, stem in (("v0.4.1", "urmqtt-dev-v0.4.1"), ("v0.5.0", "urmqtt-v0.5.0")):
            assets = {a["name"]: a["mirrored"] for a in self.entry(tag)["assets"]}
            self.assertEqual(set(assets), {f"{stem}.elf", f"{stem}.img", f"{stem}.iso", f"{stem}.cdx.json",
                                           f"urmqtt-template-{tag}-universal.iso", "SHA256SUMS", "SHA256SUMS.minisig"})  # fmt: skip
            self.assertEqual({n for n, mirrored in assets.items() if mirrored}, {f"urmqtt-template-{tag}-universal.iso", "SHA256SUMS", "SHA256SUMS.minisig"})
        self.assertIn(f"signature ok (key {self.keys['other'].key_id}", job.err)

    def test_the_test_key_is_refused_for_a_newer_tag_and_the_iso_is_never_fetched(self) -> None:
        self.add_named_release("v0.6.0", "other", new_names=True, published="2026-11-12T10:00:00Z")
        job = self.run_job(keyring=self.keyring())
        self.assertEqual(job.code, 2, job.err)
        self.assertCountEqual(self.fake.downloads(), ["SHA256SUMS", "SHA256SUMS.minisig"])
        self.assertNothingPublished("v0.6.0")
        e = self.entry("v0.6.0")
        self.assertEqual((e["status"], e["verified"], e["reason"], e["signed_by"]), ("unverified", False, "verification-failed", None))
        self.assertIn(f"made with key {self.keys['other'].key_id} (the project's former test key), which may sign v0.1.0 to v0.4.1 only, not v0.6.0", job.err)

    def test_a_signature_by_an_unknown_key_id_is_refused(self) -> None:
        self.add_named_release("v0.5.0", "stranger", new_names=True, published="2026-11-10T10:00:00Z")
        job = self.run_job(keyring=self.keyring())
        self.assertEqual(job.code, 2, job.err)
        self.assertCountEqual(self.fake.downloads(), ["SHA256SUMS", "SHA256SUMS.minisig"])
        self.assertNothingPublished("v0.5.0")
        self.assertIn(f"made with key {self.keys['stranger'].key_id}, which is not in the key ring", job.err)
        # An unknown key is not trusted for "any tag" by accident when the ring has only the test key.
        ring = self.keyring(release=False)
        self.fake.reset_log()
        again = self.run_job(keyring=ring)
        self.assertEqual(again.code, 2, again.err)
        self.assertNothingPublished("v0.5.0")

    def test_a_placeholder_release_key_stops_the_job_before_anything_is_written(self) -> None:
        ring = self.keyring()
        (ring.parent / "minisign.pub").write_text("untrusted comment: minisign public key REPLACE-WITH-THE-NEW-PUBLIC-KEY\nREPLACE-WITH-THE-NEW-PUBLIC-KEY\n")
        self.add_named_release("v0.4.1", "other", new_names=False, published="2026-11-05T10:00:00Z")
        before = snapshot(self.root)
        job = self.run_job(keyring=ring)
        self.assertEqual(job.code, 1, job.err)
        self.assertIn("placeholder", job.err)
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(self.fake.log, [], "GitHub was not even asked")

    def test_switching_from_one_pubkey_to_the_key_ring_downloads_nothing_again(self) -> None:
        """The server today: --pubkey /etc/urmqtt-mirror/minisign.pub (the test key). After the
        rotation it runs with --keyring; what it mirrored stays as it is, and the signer of the
        editions mirrored before (no key_id recorded) is read from the signature on disk."""
        old = self.add_named_release("v0.4.1", "other", new_names=False, published="2026-11-05T10:00:00Z")
        first = self.run_job(pubkey=self.keys["other"].pub)
        self.assertEqual(first.code, 0, first.err)
        meta = self.root / "v0.4.1" / "meta.json"
        state = json.loads(meta.read_text())
        del state["published"]["key_id"], state["key_id"]  # as written by the version before key rings
        meta.write_text(json.dumps(state))
        self.fake.reset_log()
        self.add_named_release("v0.5.0", "good", new_names=True, published="2026-11-10T10:00:00Z")
        job = self.run_job(keyring=self.keyring())
        self.assertEqual(job.code, 0, job.err)
        self.assertNotIn("urmqtt-template-v0.4.1-universal.iso", self.fake.downloads())
        self.assertPublished("v0.4.1", old)
        self.assertEqual(self.entry("v0.4.1")["signed_by"]["name"], "test")
        self.assertEqual(self.entry("v0.5.0")["signed_by"]["name"], "release")

    def test_dry_run_over_a_listing_with_both_naming_schemes(self) -> None:
        self.add_named_release("v0.4.1", "other", new_names=False, published="2026-11-05T10:00:00Z")
        self.add_named_release("v0.5.0", "good", new_names=True, published="2026-11-10T10:00:00Z")
        job = self.run_job("--dry-run", keyring=self.keyring())
        self.assertEqual(job.code, 0, job.err)
        self.assertEqual(sorted(w["tag"] for w in job.summary["would_process"]), ["v0.4.1", "v0.5.0"])
        self.assertEqual(self.fake.downloads(), [])
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [])


# ---------------------------------------------------------------------------
# Unit tests of the pieces (no minisign, no network)


class Units(unittest.TestCase):
    m: Any  # the script as a module

    @classmethod
    def setUpClass(cls) -> None:
        cls.m = load_script()

    def test_tags_are_matched_whole(self) -> None:
        m = self.m
        for good in ("v0.2.0", "v1", "0", "a.b-c_d", "x" * 64, "V1.0.0-rc.1"):
            self.assertTrue(m.valid_tag(good), good)
        for bad in ("", "../x", "/x", "a/b", ".x", "-x", "_x", "v1\n", "v1 ", "x" * 65, "v\u00e9", "releases.json", "RELEASES.JSON", "a\x00b", "v\u0661"):
            self.assertFalse(m.valid_tag(bad), repr(bad))

    def test_sums_parsing(self) -> None:
        m = self.m
        h1, h2 = "a" * 64, "B" * 64
        parsed = m.parse_sums(f"{h1}  one.iso\n{h2} *two.img\r\n\n{h1}  ./three\n")
        self.assertEqual(parsed, {"one.iso": h1, "two.img": h2.lower(), "three": h1})
        self.assertEqual(m.parse_sums(f"{h1}  x\n{h1}  x\n"), {"x": h1})  # repeated, same hash
        for bad in (f"{h1} x\n", f"{h1[:-1]}  x\n", "not a sums file\n", f"{h1}  x\n{h2}  x\n", f"{h1}  x\n# comment\n", f"{h1}   \n"):
            with self.assertRaises(ValueError, msg=bad):
                m.parse_sums(bad)

    def test_the_real_release_sums_format_is_understood(self) -> None:
        text = "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}\n" for n in ("urmqtt-dev-v0.1.0.elf", "urmqtt-dev-v0.1.0.img", "urmqtt-dev-v0.1.0.iso"))
        self.assertEqual(len(text), 264)  # the size of the real v0.1.0 SHA256SUMS
        self.assertEqual(sorted(self.m.parse_sums(text)), ["urmqtt-dev-v0.1.0.elf", "urmqtt-dev-v0.1.0.img", "urmqtt-dev-v0.1.0.iso"])

    def write(self, data: bytes) -> Path:
        tmp = tempfile.NamedTemporaryFile(prefix="slot-", delete=False)
        self.addCleanup(os.unlink, tmp.name)
        tmp.write(data)
        tmp.close()
        return Path(tmp.name)

    def test_slot_search(self) -> None:
        m = self.m
        self.assertEqual(m.find_config_slot(self.write(make_iso(1 << 20, version=1))), 1)
        self.assertEqual(m.find_config_slot(self.write(make_iso(1 << 20, version=513))), 513)  # little endian u16
        self.assertIsNone(m.find_config_slot(self.write(make_iso(1 << 20, version=None))))  # only decoys
        self.assertIsNone(m.find_config_slot(self.write(b"")))
        # Not 512-aligned: not a slot, even with the magic behind it.
        data = bytearray(random.Random(1).randbytes(1 << 20))
        data[3000:3000 + 26] = SLOT_MARKER + CFG_MAGIC + struct.pack("<H", 1)
        self.assertIsNone(m.find_config_slot(self.write(bytes(data))))
        # Aligned, but the 256 KiB do not fit in the image: not a slot.
        data = bytearray(random.Random(1).randbytes(1 << 20))
        data[(1 << 20) - 512:(1 << 20) - 512 + 26] = SLOT_MARKER + CFG_MAGIC + struct.pack("<H", 1)
        self.assertIsNone(m.find_config_slot(self.write(bytes(data))))
        # The first slot wins (the real ISO has two copies).
        data = bytearray(make_iso(1 << 20, version=3, slot_at=512 * 8))
        data[512 * 700:512 * 700 + 26] = SLOT_MARKER + CFG_MAGIC + struct.pack("<H", 9)
        self.assertEqual(m.find_config_slot(self.write(bytes(data))), 3)
        # Slots beyond the first read chunk (4 MiB), and one starting right at a chunk boundary.
        for offset in (m.SCAN_CHUNK - 512, m.SCAN_CHUNK, m.SCAN_CHUNK + 512 * 5, 2 * m.SCAN_CHUNK + 512):
            big = bytearray(random.Random(2).randbytes(3 * m.SCAN_CHUNK))
            big[offset:offset + SLOT_SIZE] = SLOT_MARKER + CFG_MAGIC + struct.pack("<H", 4) + bytes(SLOT_SIZE - 26)
            self.assertEqual(m.find_config_slot(self.write(bytes(big))), 4, offset)

    def test_rate_limiter_paces_with_a_fake_clock(self) -> None:
        now = [100.0]
        slept: list[float] = []

        def sleep(seconds: float) -> None:
            slept.append(seconds)
            now[0] += seconds

        limiter = self.m.RateLimiter(1000, clock=lambda: now[0], sleep=sleep)
        for _ in range(4):
            limiter.consume(500)
        self.assertAlmostEqual(sum(slept), 2.0)  # 2000 bytes at 1000 B/s
        now[0] += 60  # idle time earns no credit: no burst afterwards
        slept.clear()
        limiter.consume(1000)
        self.assertAlmostEqual(sum(slept), 1.0)
        unlimited = self.m.RateLimiter(0, clock=lambda: now[0], sleep=sleep)
        slept.clear()
        unlimited.consume(10**9)
        self.assertEqual(slept, [])
        self.assertLessEqual(self.m.RateLimiter(1000).chunk, 4096)
        self.assertEqual(self.m.RateLimiter(2 << 20).chunk, 64 * 1024)

    def test_the_repository_key_id_is_read_from_the_key_file(self) -> None:
        if not REPO_TEST_KEY.is_file():
            self.skipTest("keys/ is not next to the scripts directory")
        key = self.m.load_pubkey(REPO_TEST_KEY)
        self.assertEqual(key.key_id, "9229E05252D01F8E")  # as SECURITY.md and the file's own comment say
        self.assertIn("9229E05252D01F8E", REPO_TEST_KEY.read_text().splitlines()[0])

    def test_the_repository_key_ring_is_the_test_key_and_the_release_key(self) -> None:
        """keys/release-keys.json: the former test key for v0.1.0 to v0.4.1, the release key
        from v0.4.2 on. Until the owner commits the real minisign.pub it is the placeholder,
        and the ring refuses to load (loudly, naming the placeholder)."""
        if not REPO_KEYRING.is_file():
            self.skipTest("keys/ is not next to the scripts directory")
        doc = json.loads(REPO_KEYRING.read_text(encoding="utf-8"))
        by_name = {k["name"]: k for k in doc["keys"]}
        self.assertEqual((by_name["test"]["valid_from"], by_name["test"]["valid_to"], by_name["test"]["former_test_key"]), ("v0.1.0", "v0.4.1", True))
        self.assertEqual((by_name["release"]["valid_from"], by_name["release"]["valid_to"], by_name["release"]["file"]), ("v0.4.2", None, "../minisign.pub"))
        if "REPLACE-WITH-THE-NEW-PUBLIC-KEY" in REPO_PUBKEY.read_text(encoding="utf-8"):
            with self.assertRaisesRegex(self.m.Fatal, "placeholder"):
                self.m.load_keyring(REPO_KEYRING)
            return
        ring = self.m.load_keyring(REPO_KEYRING)
        self.assertEqual([k.name for k in ring.keys], ["release", "test"])
        self.assertNotEqual(ring.primary.key_id, "9229E05252D01F8E", "the release key must not be the test key")
        self.assertTrue(ring.by_id("9229E05252D01F8E").former_test_key)

    def test_key_ranges(self) -> None:
        m = self.m
        test = m.PubKey(Path("t.pub"), "A" * 16, "0" * 64, name="test", valid_from="v0.1.0", valid_to="v0.4.1", former_test_key=True)
        release = m.PubKey(Path("r.pub"), "B" * 16, "1" * 64, valid_from="v0.4.2")
        anything = m.PubKey(Path("a.pub"), "C" * 16, "2" * 64)
        for tag, t, r in [
            ("v0.1.0", True, False), ("v0.4.1", True, False), ("v0.4.1-rc.1", True, False), ("0.3.0", True, False),
            ("v0.4.2", False, True), ("v0.5.0", False, True), ("v1.0.0", False, True), ("v0.10.0", False, True),
            ("v0.0.9", False, False), ("nightly", False, False), ("v0.4", False, False), ("v0.4.1x", False, False),
        ]:  # fmt: skip
            self.assertEqual((test.covers(tag), release.covers(tag)), (t, r), tag)
            self.assertTrue(anything.covers(tag), tag)
        ring = m.Keyring((test, release))
        self.assertIs(ring.primary, release)
        self.assertIsNone(ring.by_id("D" * 16))
        self.assertNotEqual(ring.fingerprint, m.Keyring((test, dataclasses.replace(release, valid_from="v0.5.0"))).fingerprint)
        self.assertEqual(m.Keyring((anything,)).fingerprint, anything.fingerprint, "a single --pubkey keeps its old fingerprint")

    def test_a_bad_key_ring_is_refused(self) -> None:
        m = self.m
        directory = Path(tempfile.mkdtemp(prefix="mirror-ring-"))
        self.addCleanup(shutil.rmtree, directory, True)
        (directory / "test.pub").write_bytes(REPO_TEST_KEY.read_bytes())
        (directory / "placeholder.pub").write_text("untrusted comment: minisign public key REPLACE-WITH-THE-NEW-PUBLIC-KEY\nREPLACE-WITH-THE-NEW-PUBLIC-KEY\n")
        good = {"name": "test", "file": "test.pub", "key_id": "9229E05252D01F8E", "valid_from": "v0.1.0", "valid_to": "v0.4.1", "former_test_key": True}

        rings = itertools.count()

        def ring(*keys: Any, schema: int = 1) -> Path:
            path = directory / f"ring-{next(rings)}.json"
            path.write_text(json.dumps({"schema": schema, "keys": list(keys)}))
            return path

        loaded = m.load_keyring(ring(good))
        self.assertEqual((loaded.keys[0].key_id, loaded.keys[0].valid_to, loaded.keys[0].former_test_key), ("9229E05252D01F8E", "v0.4.1", True))
        for bad, why in [
            (ring(good, schema=2), "schema"),
            (ring(), "at least one key"),
            (ring({**good, "key_id": "0000000000000000"}), "has key id 9229E05252D01F8E"),
            (ring(good, {**good, "name": "again"}), "listed twice"),
            (ring({**good, "valid_from": "v0.5.0"}), "after valid_to"),
            (ring({**good, "valid_to": "latest"}), "version tag"),
            (ring({**good, "former_test_key": "yes"}), "true or false"),
            (ring({**good, "extra": 1}), "unknown field"),
            (ring({**good, "file": "missing.pub"}), "cannot read"),
            (ring({**good, "name": "release", "file": "placeholder.pub", "key_id": None}), "placeholder"),
        ]:
            with self.assertRaisesRegex(m.Fatal, why, msg=why):
                m.load_keyring(bad)
        (directory / "ring.json").write_text("{not json")
        with self.assertRaisesRegex(m.Fatal, "cannot read the key ring"):
            m.load_keyring(directory / "ring.json")

    def test_old_and_new_asset_names_are_classified_alike(self) -> None:
        """Releases up to v0.4.1 carry urmqtt-dev-<tag>.* next to the template; from the
        rotation on, urmqtt-<tag>.elf/.iso/.img. Only the template is ever fetched: the
        new urmqtt-<tag>.iso (the same bytes) must not be mistaken for it."""
        m = self.m
        old = ["SHA256SUMS", "SHA256SUMS.minisig", "urmqtt-dev-v0.4.1.cdx.json", "urmqtt-dev-v0.4.1.elf",
               "urmqtt-dev-v0.4.1.img", "urmqtt-dev-v0.4.1.iso", "urmqtt-template-v0.4.1-universal.iso"]  # fmt: skip
        new = ["SHA256SUMS", "SHA256SUMS.minisig", "urmqtt-v0.5.0.cdx.json", "urmqtt-v0.5.0.elf",
               "urmqtt-v0.5.0.img", "urmqtt-v0.5.0.iso", "urmqtt-template-v0.5.0-universal.iso"]  # fmt: skip
        for tag, names in (("v0.4.1", old), ("v0.5.0", new)):
            assets = tuple(m.Asset(n, i + 1, 10, None, None, None) for i, n in enumerate(names))
            for n in names:
                self.assertIsNotNone(m.LISTED_NAME_RE.fullmatch(n), n)
            plan = m.classify(m.Release(tag, tag, None, True, "https://example.org", assets))
            self.assertEqual(plan.template.name, f"urmqtt-template-{tag}-universal.iso")
            self.assertEqual((plan.sums.name, plan.sig.name), ("SHA256SUMS", "SHA256SUMS.minisig"))

    def test_a_bad_key_file_is_refused(self) -> None:
        m = self.m
        for text in ("", "untrusted comment: x\n", "untrusted comment: x\nnot base64!!\n", "untrusted comment: x\nAAAA\n", "a\nb\nc\n"):
            path = self.write(text.encode())
            with self.assertRaises(m.Fatal, msg=text):
                m.load_pubkey(path)

    def test_url_policy(self) -> None:
        m = self.m
        self.assertTrue(m.url_allowed("https://api.github.com/x", False))
        self.assertFalse(m.url_allowed("http://api.github.com/x", False))
        self.assertFalse(m.url_allowed("http://127.0.0.1:1/x", False))  # plain http only when the API base itself is local
        self.assertTrue(m.url_allowed("http://127.0.0.1:1/x", True))
        self.assertTrue(m.url_allowed("http://localhost:1/x", True))
        self.assertFalse(m.url_allowed("http://192.0.2.1/x", True))
        self.assertFalse(m.url_allowed("ftp://example.com/x", True))
        self.assertFalse(m.url_allowed("file:///etc/passwd", True))
        self.assertFalse(m.url_allowed("https:///nohost", False))
        self.assertEqual(m.strip_query("https://u:p@host.example/a/b?sig=SECRET#frag"), "https://host.example/a/b")

    def test_the_fingerprint_follows_the_assets_only(self) -> None:
        m = self.m
        a = m.Asset("SHA256SUMS", 1, 264, "0" * 64, "2026-10-30T00:50:10Z", None)
        base = m.Release("v1", "n", "2026-10-30T00:50:09Z", True, "https://x", (a,))
        same = dataclasses.replace(base, name="renamed", prerelease=False, published="2027-01-01T00:00:00Z")
        self.assertEqual(m.fingerprint(base), m.fingerprint(same))
        for change in (
            dataclasses.replace(a, id=2), dataclasses.replace(a, size=265), dataclasses.replace(a, digest="1" * 64),
            dataclasses.replace(a, updated_at="2026-10-31T00:00:00Z"), dataclasses.replace(a, name="SHA256SUMS2"),
        ):  # fmt: skip
            self.assertNotEqual(m.fingerprint(base), m.fingerprint(dataclasses.replace(base, assets=(change,))))
        self.assertNotEqual(m.fingerprint(base), m.fingerprint(dataclasses.replace(base, assets=(a, dataclasses.replace(a, name="b", id=3)))))

    def test_publish_moves_the_iso_last_and_only_by_rename(self) -> None:
        m = self.m
        root = Path(tempfile.mkdtemp(prefix="mirror-publish-"))
        self.addCleanup(shutil.rmtree, root, True)
        work = root / ".tmp" / "v1"
        work.mkdir(parents=True)
        iso = "urmqtt-template-v1-universal.iso"
        for name in ("SHA256SUMS.part", "SHA256SUMS.minisig.part", f"{iso}.part"):
            (work / name).write_bytes(b"x")
        key = m.PubKey(Path("k.pub"), "AABBCCDD00112233", "0" * 64)
        ctx = m.Context(root, root / ".tmp", m.Keyring((key,)), "minisign", None, None, 0)
        template = m.Asset(iso, 1, 1, None, None, None)
        rel = m.Release("v1", "v1", None, False, "https://example.org/v1", (template,))
        moves: list[tuple[str, str]] = []
        real_replace = os.replace

        def recording_replace(src: Any, dst: Any) -> None:
            moves.append((Path(src).name, Path(dst).name))
            real_replace(src, dst)

        with mock.patch.object(os, "replace", recording_replace):
            m.publish(ctx, rel, m.Plan(template, None, None), work, m.Checked(size=1, sha256="a" * 64, config_format=1), "fp", "now")
        self.assertEqual(
            moves,
            [("SHA256SUMS.part", "SHA256SUMS"), ("SHA256SUMS.minisig.part", "SHA256SUMS.minisig"), (f"{iso}.part", iso)],
        )
        self.assertEqual(sorted(p.name for p in (root / "v1").iterdir()), ["SHA256SUMS", "SHA256SUMS.minisig", iso])

    def test_an_unexpected_error_in_one_release_does_not_stop_the_others(self) -> None:
        m = self.m
        root = Path(tempfile.mkdtemp(prefix="mirror-isolation-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / ".tmp").mkdir()
        key = m.PubKey(Path("k.pub"), "AABBCCDD00112233", "0" * 64)
        ctx = m.Context(root, root / ".tmp", m.Keyring((key,)), "minisign", None, None, 0)
        releases = [
            m.Release("v2", "v2", "2026-11-02T00:00:00Z", False, "https://example.org/v2", ()),
            m.Release("v1", "v1", "2026-11-01T00:00:00Z", False, "https://example.org/v1", ()),
        ]

        def fake_process(_ctx: Any, rel: Any, _prev: Any) -> dict[str, Any]:
            if rel.tag == "v2":
                raise RuntimeError("boom")
            return {
                "meta_schema": 1, "tag": rel.tag, "fingerprint": m.fingerprint(rel), "key_fp": key.fingerprint,
                "result": "no-template", "retry": False, "verified": True, "sums_map": {},
                "attempted_at": "2026-11-01T00:00:00Z", "descr": m.describe(rel), "published": None,
                "edited": False, "edited_at": None, "removed_at": None,
            }  # fmt: skip

        original = m.process_release
        m.process_release = fake_process
        self.addCleanup(setattr, m, "process_release", original)
        counters = m.Counters()
        with self.assertLogs("urmqtt-mirror", level="ERROR") as logs:
            final, _ = m.sync_listed(ctx, releases, {}, counters, "2026-11-01T00:00:00Z", False)
        self.assertEqual(list(final), ["v1"])
        self.assertEqual(counters.op_errors, 1)
        self.assertTrue(any("RuntimeError: boom" in line for line in logs.output))
        self.assertTrue((root / "v1" / "meta.json").exists())

    def test_import_has_no_side_effects(self) -> None:
        self.assertEqual(self.m.LOG.handlers, [])
        self.assertEqual(self.m.LOG.level, 0)


if __name__ == "__main__":
    if MINISIGN is None:
        print("SKIP: minisign is not installed (apt install minisign / brew install minisign); only the unit tests run", file=sys.stderr)
    unittest.main(verbosity=1)
