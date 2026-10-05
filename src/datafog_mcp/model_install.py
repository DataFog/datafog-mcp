"""Explicit, pinned model setup. Network access is confined to this CLI operation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from importlib.metadata import version
from pathlib import Path, PurePosixPath
from typing import Any, cast

from . import __version__

REPOSITORY = "DataFog/pii-en-65m"
REVISION = "555c45f524125c4e097c360ea203f62b2496c30a"
MODEL_VERSION = "0.1.0"
RUNTIME_VERSION = "0.2.0"
RECEIPT = ".datafog-install.json"
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_FILES = 2048
# Reviewed release-index.json at REVISION; never read a moving Hub branch.
ARCHIVES = {
    "linux-x86_64": ("355f54837d3f4ff0aebc72700cb38591176b29e0f75c63c66e04d874df4eb713", 265799226),
    "linux-aarch64": (
        "c22fd91dd601e22ccb13d074a555e58a6926e7b57adb5234171261763fa5b203",
        263744529,
    ),
    "macos-arm64": ("b2980aa1de1702957da3182a0aee3ac3fed2686cf146f52eb037256936b04e37", 262335474),
    "macos-x86_64": ("47ae14fe1a37704672c2e6ebcad5e428b4cef9b3c538f092fa9789975199a53a", 262222950),
    "windows-x86_64": (
        "cd4738fcff9f440fa80ce6a71be8c71719e2137d7fd35a8c099f42238740a8f3",
        249849360,
    ),
}


MANIFEST_HASHES = {
    "linux-x86_64": "74826064ef0467bbe0ee7688ae452bcfa02bfa5a5b88673778736cb52d86cc9e",
    "linux-aarch64": "ec2137c737eb25518c5b0d1dc46843b386f8da1fe970070881e6a11dad19c4d5",
    "macos-arm64": "1eeb425f598be602e1ecc14da9ead498dd82eb7bbb8a2a6f510eca24a7fff5fe",
    "macos-x86_64": "584cb2c91c92d8121710725339e2aae0cd998c53becea57c5c2952a4a11c3edb",
    "windows-x86_64": "491adaedef3b7af4c2053c46006d28de67a4167fc48fada1afad86db1d8e780d",
}


class ModelInstallError(ValueError):
    """A setup/integrity failure whose message contains no remote output or file contents."""


def host_platform() -> str:
    system = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}.get(platform.system())
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(
        machine
    )
    if system == "linux" and arch == "arm64":
        arch = "aarch64"
    key = f"{system}-{arch}"
    if key not in ARCHIVES:
        raise ModelInstallError("No qualified native model release is available for this platform.")
    if system == "macos":
        minimum = 14 if arch == "arm64" else 15
        try:
            major = int(platform.mac_ver()[0].split(".")[0])
        except ValueError:
            raise ModelInstallError("Cannot determine macOS model compatibility.") from None
        if major < minimum:
            raise ModelInstallError(f"This model runtime requires macOS {minimum} or newer.")
    if system == "linux":
        libc, release = platform.libc_ver()
        try:
            parts = tuple(int(part) for part in release.split(".")[:2])
        except ValueError:
            parts = ()
        if libc != "glibc" or parts < (2, 28):
            raise ModelInstallError("This native model runtime requires Linux glibc 2.28 or newer.")
    return key


def check_pairing() -> None:
    if __version__ != "0.1.0" or version("datafog-core") not in {"0.4.1", "0.4.2"}:
        raise ModelInstallError(
            "This MCP/Core version has not been qualified with the pinned model release."
        )


def executable_name() -> str:
    return "datafog-pii.exe" if os.name == "nt" else "datafog-pii"


def default_directory() -> Path:
    return (
        Path.home()
        / ".local/share/datafog/models"
        / f"pii-en-65m-{MODEL_VERSION}-runtime-{RUNTIME_VERSION}-{host_platform()}"
    )


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def _relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or ".." in path.parts
        or str(path) != name
    ):
        raise ModelInstallError("Model archive contains an unsafe path.")
    return path


def _json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ModelInstallError("Model release metadata is missing or invalid.")
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ModelInstallError("Model release metadata is invalid.")
    return cast(dict[str, Any], value)


def _verify_files(bundle: Path, manifest: dict[str, Any]) -> None:
    files = manifest.get("files")
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise ModelInstallError("Model file manifest is invalid.")
    required = {
        executable_name(),
        "model.onnx",
        "tokenizer.json",
        "config.json",
        "calibration.json",
    }
    if not required <= set(files):
        raise ModelInstallError("Model bundle is missing required files.")
    for name, expected in files.items():
        relative = _relative(name)
        path = bundle.joinpath(*relative.parts)
        if not isinstance(expected, dict):
            raise ModelInstallError("Model file identity is invalid.")
        expected = cast(dict[str, Any], expected)
        if (
            any(
                (bundle.joinpath(*relative.parts[:i])).is_symlink()
                for i in range(1, len(relative.parts) + 1)
            )
            or not path.is_file()
            or path.stat().st_nlink != 1
            or path.stat().st_size != expected.get("bytes")
            or digest(path) != expected.get("sha256")
        ):
            raise ModelInstallError("Installed model integrity verification failed.")
    actual = {
        path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if not path.is_dir()
    }
    if actual != set(files) | {"bundle-manifest.json", RECEIPT} and actual != set(files) | {
        "bundle-manifest.json"
    }:
        raise ModelInstallError("Model bundle contains unexpected files.")


def _manifest(bundle: Path, selected: str) -> dict[str, Any]:
    if digest(bundle / "bundle-manifest.json") != MANIFEST_HASHES[selected]:
        raise ModelInstallError("Model manifest does not match the pinned release.")
    manifest = _json(bundle / "bundle-manifest.json")
    if manifest.get("platform") != selected:
        raise ModelInstallError("Model bundle platform is incompatible.")
    _verify_files(bundle, manifest)
    return manifest


def verify_bundle(bundle: Path) -> None:
    """Verify installation receipt and every manifested file before runtime startup."""
    try:
        check_pairing()
        selected = host_platform()
        receipt = _json(bundle / RECEIPT)
        expected = {
            "schema": 1,
            "repository": REPOSITORY,
            "revision": REVISION,
            "model_version": MODEL_VERSION,
            "runtime_version": RUNTIME_VERSION,
            "platform": selected,
            "archive_sha256": ARCHIVES[selected][0],
        }
        if any(receipt.get(k) != v for k, v in expected.items()):
            raise ModelInstallError(
                "Model installation receipt is incompatible; reinstall explicitly."
            )
        if digest(bundle / "bundle-manifest.json") != receipt.get("manifest_sha256"):
            raise ModelInstallError("Installed model manifest changed; reinstall explicitly.")
        _manifest(bundle, selected)
    except ModelInstallError:
        raise
    except Exception:
        raise ModelInstallError("Cannot verify the installed model release.") from None


def _extract(archive: Path, bundle: Path) -> None:
    total = count = 0
    names: set[str] = set()
    with tarfile.open(archive, "r:gz") as stream:
        for member in stream:
            count += 1
            total += member.size
            relative = _relative(member.name)
            if count > MAX_FILES or total > MAX_EXPANDED_BYTES:
                raise ModelInstallError("Model archive exceeds supported installation bounds.")
            if member.name in names or not (member.isdir() or member.isfile()):
                raise ModelInstallError(
                    "Model archive contains duplicate, linked, or special entries."
                )
            names.add(member.name)
            target = bundle.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                source = stream.extractfile(member)
                if source is None:
                    raise ModelInstallError("Model archive entry cannot be read.")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o600)


def _download(target: Path, selected: str) -> None:
    filename = f"datafog-pii-{MODEL_VERSION}-runtime-{RUNTIME_VERSION}-{selected}.tar.gz"
    url = f"https://huggingface.co/{REPOSITORY}/resolve/{REVISION}/runtimes/v{RUNTIME_VERSION}/{filename}"
    total = 0
    with urllib.request.urlopen(url, timeout=30) as response, target.open("xb") as output:
        if not response.geturl().startswith("https://"):
            raise ModelInstallError("Model downloads require HTTPS.")
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > ARCHIVES[selected][1]:
                raise ModelInstallError("Downloaded model archive has an unexpected size.")
            output.write(chunk)


def install_model(destination: Path, archive: Path | None = None) -> Path:
    """Verify a pinned archive and create a fresh installation without overwriting."""
    created = False
    try:
        check_pairing()
        selected = host_platform()
        destination = destination.expanduser()
        if not destination.is_absolute():
            raise ModelInstallError(
                "Model installation directory must be absolute or start with ~."
            )
        if os.path.lexists(destination):
            raise ModelInstallError(
                "Model installation directory already exists; refusing replacement."
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination = destination.parent.resolve(strict=True) / destination.name
        required_space = 2 * MAX_EXPANDED_BYTES + (ARCHIVES[selected][1] if archive is None else 0)
        if shutil.disk_usage(destination.parent).free < required_space:
            raise ModelInstallError("Insufficient free space for verified model installation.")
        with tempfile.TemporaryDirectory(
            prefix=".datafog-model-", dir=destination.parent
        ) as temporary:
            staging = Path(temporary)
            source = archive
            if source is None:
                source = staging / "release.tar.gz"
                _download(source, selected)
            if (
                source.stat().st_size != ARCHIVES[selected][1]
                or digest(source) != ARCHIVES[selected][0]
            ):
                raise ModelInstallError(
                    "Model archive checksum or size does not match the pinned release."
                )
            bundle = staging / "bundle"
            bundle.mkdir(mode=0o700)
            _extract(source, bundle)
            _manifest(bundle, selected)
            (bundle / executable_name()).chmod(0o700)
            # Probe only verified binaries, discard every output except the schema check.
            probe = subprocess.run(
                [str(bundle / executable_name()), str(bundle)],
                input=b'{"text":""}\n',
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=True,
            )
            from .model_runtime import _convert

            if _convert("", json.loads(probe.stdout)):
                raise ModelInstallError("Model runtime startup probe failed.")
            receipt = {
                "schema": 1,
                "repository": REPOSITORY,
                "revision": REVISION,
                "model_version": MODEL_VERSION,
                "runtime_version": RUNTIME_VERSION,
                "platform": selected,
                "archive_sha256": ARCHIVES[selected][0],
                "manifest_sha256": digest(bundle / "bundle-manifest.json"),
            }
            destination.mkdir(
                mode=0o700
            )  # Exclusive reservation; never replace an existing directory.
            created = True
            shutil.copytree(bundle, destination, dirs_exist_ok=True)
            with (destination / RECEIPT).open("x", encoding="utf-8") as handle:
                os.chmod(destination / RECEIPT, 0o600)
                json.dump(receipt, handle)
            verify_bundle(destination)
        return destination
    except BaseException as error:
        if created:
            shutil.rmtree(destination)
        if isinstance(error, (KeyboardInterrupt, SystemExit, ModelInstallError)):
            raise
        raise ModelInstallError(
            "Model installation failed; no complete installation was published."
        ) from None
