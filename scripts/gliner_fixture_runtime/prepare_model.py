"""Prepare pinned GLiNER weights/tokenizer for a separate CI comparison job."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

MODEL_ID = "urchade/gliner_small-v2.1"
MODEL_REVISION = "4e091416cf7c3481db542c2a3d26156916f3a47f"
BACKBONE_ID = "microsoft/deberta-v3-small"
BACKBONE_REVISION = "a36c739020e01763fe789b4b85e2df55d6180012"


def prepare(output: Path) -> None:
    from huggingface_hub import snapshot_download

    # Fetch immutable revisions; cached files are copied, never edited in place.
    source = Path(snapshot_download(MODEL_ID, revision=MODEL_REVISION))
    backbone_source = Path(
        snapshot_download(
            BACKBONE_ID,
            revision=BACKBONE_REVISION,
            allow_patterns=["*.json", "*.model", "*.txt"],
        )
    )
    output.mkdir(parents=True, exist_ok=True)
    backbone = output / "backbone"
    shutil.copytree(backbone_source, backbone, dirs_exist_ok=True)
    for filename in ("gliner_config.json", "pytorch_model.bin"):
        shutil.copyfile(source / filename, output / filename)
    config_file = output / "gliner_config.json"
    config = json.loads(config_file.read_text())
    config["model_name"] = str(backbone.resolve())
    config_file.write_text(json.dumps(config))
    (output / "provenance.json").write_text(
        json.dumps(
            {
                "id": MODEL_ID,
                "revision": MODEL_REVISION,
                "backbone_revision": BACKBONE_REVISION,
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    prepare(args.output)
    print("Pinned GLiNER fixture model prepared")


if __name__ == "__main__":
    main()
