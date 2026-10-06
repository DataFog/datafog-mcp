"""Fresh public Hub download, with pinned archive and installer hashes."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1048576), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    machine = platform.machine().lower()
    arch = "aarch64" if machine in ("arm64", "aarch64") else "x86_64"
    system = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}[platform.system()]
    target = system + "-" + ("arm64" if system == "macos" and arch == "aarch64" else arch)
    assert target == args.platform
    lock = json.loads(Path(__file__).with_name("native-test-runtime.json").read_text())
    archive = lock["platforms"][target]
    assert not args.destination.exists()
    os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
    from huggingface_hub import hf_hub_download

    downloads = args.destination.parent / "downloads"

    def get(name: str) -> Path:
        return Path(
            hf_hub_download(
                lock["repo"],
                filename="runtimes/v0.2.0/" + name,
                revision=lock["revision"],
                token=False,
                local_dir=downloads,
                force_download=True,
            )
        )

    package = get(archive["filename"])
    assert package.stat().st_size == archive["bytes"] and sha(package) == archive["sha256"]
    installer = get("tools/install_bundle.py")
    common = get("tools/common.py")
    for name, path in (("tools/install_bundle.py", installer), ("tools/common.py", common)):
        assert sha(path) == lock["tool_sha256"][name]
    env = dict(os.environ)
    env.pop("HF_TOKEN", None)
    subprocess.run(
        [
            sys.executable,
            str(installer),
            "--archive",
            str(package),
            "--sha256",
            archive["sha256"],
            "--destination",
            str(args.destination),
        ],
        check=True,
        env=env,
    )
    proof = {
        "platform": target,
        "tested_host": platform.platform(),
        "hf_repo": lock["repo"],
        "hf_revision": lock["revision"],
        "archive_sha256": archive["sha256"],
        "fresh_download": True,
        "bundle_manifest_sha256": sha(args.destination / "bundle-manifest.json"),
        "authentication_used": False,
    }
    (args.destination.parent / "download-proof.json").write_text(json.dumps(proof, indent=2) + "\n")


if __name__ == "__main__":
    main()
