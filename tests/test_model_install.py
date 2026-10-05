"""Pinned, transactional model setup using tiny archives and a deterministic peer."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

from datafog_mcp import model_install as install


@pytest.fixture
def release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    selected = install.host_platform()
    files: dict[str, bytes] = {
        install.executable_name(): (
            f"#!{sys.executable}\nimport json,sys\n"
            "for line in sys.stdin:\n"
            ' text=json.loads(line)["text"]; findings=[]\n'
            ' for word,label in [("Jane","first_name"),("Doe","last_name"),\n'
            '                    ("42 Sample Road","street_address")]:\n'
            "  start=text.find(word)\n"
            '  if start>=0: findings.append({"label":label,"start":len(text[:start].encode()),\n'
            '       "end":len(text[:start+len(word)].encode()),"confidence":0.9})\n'
            ' print(json.dumps({"findings":findings}),flush=True)\n'
        ).encode(),
        "model.onnx": b"synthetic-weights",
        "tokenizer.json": b"{}",
        "config.json": b"{}",
        "calibration.json": b"{}",
    }
    manifest = {
        "platform": selected,
        "files": {
            name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in files.items()
        },
    }
    raw = json.dumps(manifest).encode()
    monkeypatch.setitem(install.MANIFEST_HASHES, selected, hashlib.sha256(raw).hexdigest())
    files["bundle-manifest.json"] = raw
    archive = tmp_path / "release.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            handle.addfile(member, io.BytesIO(data))
    monkeypatch.setitem(
        install.ARCHIVES, selected, (install.digest(archive), archive.stat().st_size)
    )
    return archive


def test_offline_install_verified_and_never_overwritten(tmp_path: Path, release: Path) -> None:
    destination = tmp_path / "installed"
    assert install.install_model(destination, release) == destination
    install.verify_bundle(destination)
    original = (destination / "model.onnx").read_bytes()
    with pytest.raises(install.ModelInstallError, match="already exists"):
        install.install_model(destination, release)
    assert (destination / "model.onnx").read_bytes() == original
    assert (destination / install.executable_name()).stat().st_mode & 0o111


@pytest.mark.parametrize("target", ["model.onnx", "bundle-manifest.json", install.RECEIPT])
def test_tampering_is_detected(tmp_path: Path, release: Path, target: str) -> None:
    destination = install.install_model(tmp_path / "installed", release)
    (destination / target).write_text("PRIVATE_SENTINEL")
    with pytest.raises(install.ModelInstallError) as error:
        install.verify_bundle(destination)
    assert "PRIVATE_SENTINEL" not in str(error.value)


def test_modified_manifest_and_matching_receipt_are_still_refused(
    tmp_path: Path, release: Path
) -> None:
    destination = install.install_model(tmp_path / "installed", release)
    manifest_path = destination / "bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["model.onnx"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    receipt_path = destination / install.RECEIPT
    receipt = json.loads(receipt_path.read_text())
    receipt["manifest_sha256"] = install.digest(manifest_path)
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(install.ModelInstallError, match="pinned release"):
        install.verify_bundle(destination)


def test_bad_archive_never_executes_or_publishes(
    tmp_path: Path, release: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release.write_bytes(b"not the model")

    def unexpected(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Unverified archive was executed")

    monkeypatch.setattr(install.subprocess, "run", unexpected)
    with pytest.raises(install.ModelInstallError, match="checksum"):
        install.install_model(tmp_path / "installed", release)
    assert not (tmp_path / "installed").exists()
    assert not list(tmp_path.glob(".datafog-model-*"))


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../escape", tarfile.REGTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("C:/escape", tarfile.REGTYPE),
        ("a\\escape", tarfile.REGTYPE),
        ("link", tarfile.SYMTYPE),
        ("hard", tarfile.LNKTYPE),
        ("fifo", tarfile.FIFOTYPE),
    ],
)
def test_unsafe_archive_entries_are_refused(tmp_path: Path, name: str, kind: bytes) -> None:
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = "../escape"
        stream.addfile(member)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    with pytest.raises(install.ModelInstallError):
        install._extract(archive, bundle)
    assert not (tmp_path / "escape").exists()


def test_duplicate_archive_entries_are_refused(tmp_path: Path) -> None:
    archive = tmp_path / "duplicate.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        for _ in range(2):
            stream.addfile(tarfile.TarInfo("same"))
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    with pytest.raises(install.ModelInstallError, match="duplicate"):
        install._extract(archive, bundle)


@pytest.mark.parametrize("phase", ["download", "probe", "copy"])
def test_failed_install_leaves_no_complete_or_partial_install(
    tmp_path: Path, release: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise OSError("PRIVATE_SENTINEL")

    source: Path | None = release
    if phase == "download":
        monkeypatch.setattr(install, "_download", fail)
        source = None
    elif phase == "probe":
        monkeypatch.setattr(install.subprocess, "run", fail)
    else:
        monkeypatch.setattr(install.shutil, "copytree", fail)
    with pytest.raises(install.ModelInstallError) as error:
        install.install_model(tmp_path / "installed", source)
    assert "PRIVATE_SENTINEL" not in str(error.value)
    assert not (tmp_path / "installed").exists()
    assert not list(tmp_path.glob(".datafog-model-*"))


def test_unqualified_core_version_fails_before_download(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(install, "version", lambda name: "0.4.3")
    with pytest.raises(install.ModelInstallError, match="qualified"):
        install.check_pairing()


@pytest.mark.parametrize(
    "system,machine,expected",
    [
        ("Windows", "AMD64", "windows-x86_64"),
        ("Darwin", "arm64", "macos-arm64"),
        ("Darwin", "x86_64", "macos-x86_64"),
        ("Linux", "aarch64", "linux-aarch64"),
        ("Linux", "x86_64", "linux-x86_64"),
    ],
)
def test_platform_selection(
    monkeypatch: pytest.MonkeyPatch, system: str, machine: str, expected: str
) -> None:
    monkeypatch.setattr(install.platform, "system", lambda: system)
    monkeypatch.setattr(install.platform, "machine", lambda: machine)
    monkeypatch.setattr(install.platform, "mac_ver", lambda: ("15.0", (), ""))
    monkeypatch.setattr(install.platform, "libc_ver", lambda: ("glibc", "2.28"))
    assert install.host_platform() == expected


@pytest.mark.parametrize(
    "system,machine,os_version,libc",
    [
        ("Darwin", "arm64", "13.0", ("", "")),
        ("Darwin", "x86_64", "14.0", ("", "")),
        ("Linux", "armv7", "", ("glibc", "2.39")),
        ("Linux", "x86_64", "", ("musl", "1.2")),
        ("Linux", "x86_64", "", ("glibc", "2.27")),
        ("Windows", "arm64", "", ("", "")),
    ],
)
def test_incompatible_platform_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    system: str,
    machine: str,
    os_version: str,
    libc: tuple[str, str],
) -> None:
    monkeypatch.setattr(install.platform, "system", lambda: system)
    monkeypatch.setattr(install.platform, "machine", lambda: machine)
    monkeypatch.setattr(install.platform, "mac_ver", lambda: (os_version, (), ""))
    monkeypatch.setattr(install.platform, "libc_ver", lambda: libc)
    with pytest.raises(install.ModelInstallError):
        install.host_platform()


@pytest.mark.parametrize("free", [0, install.MAX_EXPANDED_BYTES + 1])
def test_insufficient_space_refuses_before_publication(
    tmp_path: Path, release: Path, monkeypatch: pytest.MonkeyPatch, free: int
) -> None:
    from collections import namedtuple

    Usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(install.shutil, "disk_usage", lambda path: Usage(2 * free, free, free))
    with pytest.raises(install.ModelInstallError, match="free space"):
        install.install_model(tmp_path / "installed", release)
    assert not (tmp_path / "installed").exists()


@pytest.mark.parametrize("kind", ["valid", "oversize", "http"])
def test_download_is_pinned_https_and_bounded(
    tmp_path: Path, release: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    selected = install.host_platform()
    contents = release.read_bytes()
    urls: list[str] = []

    class Response(io.BytesIO):
        def geturl(self) -> str:
            return "http://invalid" if kind == "http" else "https://cdn.huggingface.co/archive"

    def open_url(url: str, timeout: int) -> Response:
        urls.append(url)
        return Response(contents + (b"extra" if kind == "oversize" else b""))

    monkeypatch.setattr(install.urllib.request, "urlopen", open_url)
    destination = tmp_path / "download.tar.gz"
    if kind == "valid":
        install._download(destination, selected)
        assert destination.read_bytes() == contents
    else:
        with pytest.raises(install.ModelInstallError):
            install._download(destination, selected)
    assert len(urls) == 1
    assert f"/{install.REPOSITORY}/resolve/{install.REVISION}/" in urls[0]


@pytest.mark.parametrize("changed", ["platform", "revision", "runtime_version"])
def test_altered_receipt_pairing_is_refused(tmp_path: Path, release: Path, changed: str) -> None:
    destination = install.install_model(tmp_path / "installed", release)
    receipt = destination / install.RECEIPT
    data = json.loads(receipt.read_text())
    data[changed] = "not-qualified"
    receipt.write_text(json.dumps(data))
    with pytest.raises(install.ModelInstallError, match="incompatible"):
        install.verify_bundle(destination)
