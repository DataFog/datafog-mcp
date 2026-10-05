# Optional model setup and compatibility

The explicit CLI setup installs **DataFog PII EN 65M**, model 0.1.0, native runtime 0.2.0. It adds local first/last-name (`PERSON`) and street-address (`STREET_ADDRESS`) detection to the existing Core workflow. The native subprocess adapter is part of MCP; the published Core Python API does not load this model itself.

## Pinned release

- Repository: [DataFog/pii-en-65m](https://huggingface.co/DataFog/pii-en-65m).
- Immutable Hub revision: `555c45f524125c4e097c360ea203f62b2496c30a`.
- Native release: [`runtimes/v0.2.0/release-index.json`](https://huggingface.co/DataFog/pii-en-65m/blob/555c45f524125c4e097c360ea203f62b2496c30a/runtimes/v0.2.0/release-index.json).
- Frozen weights ONNX SHA-256: `04889c1ea2e9029d9b89cd5f35697224634bb06d9777abfa6ea575810b9a3eb2`.
- Runtime source/qualification provenance is recorded per platform in that index. Weight/tokenizer/calibration provenance retains the earlier `02cc6ca86a11dcb2b328861687770a22a7ea1b76` revision; the pinned Hub revision includes the release and canonical repository naming.

This is a different architecture and runtime from the separately published custom DeBERTa/CharCNN/CRF `DataFog/pii-en-71m`. Setup does not substitute that model or follow a moving `main` revision. Future model/runtime releases require a reviewed catalog and new compatibility evidence.

## Setup

```sh
datafog-mcp model install
```

By default, the new directory is under `~/.local/share/datafog/models/`, named for the exact model, runtime, and platform. Override it with `--directory /new/absolute/path`. The directory must not exist. Set the printed absolute path as `[model].bundle_directory` in `~/.config/datafog/policy.toml`, then run:

```sh
datafog-mcp model status
```

The repository is public and downloads are anonymous over HTTPS. Network access occurs only in explicit setup. Reads, transformations, policy discovery, and server startup perform no downloads. Setup never executes Python code from the Hub, unpickles training files, or installs a Python inference stack.

For offline/managed environments, acquire the exact archive named in the release index, then use:

```sh
datafog-mcp model install --archive /absolute/pinned-release.tar.gz --directory /new/absolute/path
```

Both paths enforce the built-in SHA-256 and exact archive size. Before extraction, setup checks disk capacity for a downloaded archive plus two copies of up to 512 MiB of expanded files (staging and final installation). It rejects traversal, absolute/Windows-drive paths, duplicate entries, symlinks, hard links, special files, excessive entry counts, and expanded size. Files are extracted into a private staging directory. The pinned per-platform manifest hash is verified, every manifested file's hash/size is checked, and extra files are refused before the executable is started.

Only then does setup probe an empty JSONL request, suppressing native stderr. A new owner-controlled directory is exclusively reserved; the receipt is written after the verified files are copied. Failed downloads, extraction, probing, copying, or final verification remove this attempt's directory and staging files. An existing installation is never replaced. A hard process/machine crash can leave an incomplete directory: it has no valid receipt and cannot be used; inspect/remove it locally before retrying.

Installation records the exact repository/revision, platform, archive identity, model/runtime versions, and manifest hash. Runtime compares this receipt with the built-in catalog and verifies all manifested files before its first native launch or a restart after file identities change. The manifest hash is also pinned in code, so editing a local manifest and receipt together cannot approve altered files. These are integrity checks against reviewed release bytes, not publisher signatures or protection against a compromised local MCP installation/account.

## Pairing and platforms

MCP **0.1.0**, Core **0.4.1 or 0.4.2**, model **0.1.0**, and runtime **0.2.0** are the current accepted pairing. Other Core/MCP versions fail the compatibility check until qualified explicitly. The adapter uses Core `Finding` objects and Core transformations; the model is a local JSONL subprocess, not a Core model API.

| Archive | Admission requirement | Release qualification environment |
| --- | --- | --- |
| linux-x86_64 | glibc >=2.28 | Linux x86_64, glibc 2.35 |
| linux-aarch64 | glibc >=2.28, 64-bit ARM | Linux aarch64, glibc 2.39 |
| macos-arm64 | macOS >=14 | macOS 14 arm64 |
| macos-x86_64 | macOS >=15 | macOS 15 x86_64 |
| windows-x86_64 | x64 Visual C++ v14 redistributable | Windows Server 2022 x64 |

Release qualification covered native boundary tests, fresh installation, seven parity/golden cases, and integration with the older PR 32/33 adapter at the revisions in the index. That evidence does not qualify this new atomic PR by itself. Its ordinary CI uses deterministic peers and tiny synthetic archives; a separate opt-in test exercises this PR's actual MCP tools with the real installed archive. Local development verified the macOS arm64 archive. Hosted OS/platform verification remains separate from the local checks.

The admission requirements are minimum library/platform checks, not guarantees about every OS release, CPU, distribution, or device. Native startup may still fail, for example for missing system libraries. Unsupported architectures (including Windows arm64 and Linux armv7), musl/Alpine, and older macOS versions fail without downloading. Windows startup failures may require Microsoft's x64 Visual C++ redistributable.

## Detection contract

Configuring a bundle opts default requests into PERSON/STREET_ADDRESS in addition to the current Core defaults. An explicit `entity_types` list replaces the defaults. Core-only selections do not invoke the model. Model categories requested without a configured bundle fail with setup guidance before reading input. A missing, incompatible, modified, malformed, or timed-out requested model cannot produce a Core-only clean result or partial output copy.

Model first/last names are separate PERSON spans, not full-person identity resolution. Other model categories are ignored in favor of existing Core detector semantics. Findings use exact half-open UTF-8 byte offsets converted to original Unicode codepoints, then existing overlap resolution, typed exact allowlists, and transformation tools. Neither source text, native redacted text, matched values, confidence values, nor file digests enter MCP responses or error logs.

Requests use persistent serialized native processes with bounded JSONL responses and a configurable model inference deadline (default 30 seconds, maximum 300). Waiting and all outer text segments share that deadline. Larger text uses 16,384-character outer segments with 1,024-character overlap; owned entities touching a truncated segment edge fail explicitly. The native runtime also has overlapping token windows. Finite overlap does not guarantee detection of arbitrarily long entities or identical predictions under every segmentation. The existing 1 MiB file limit remains; general Core/whole-operation timeout and file-limit work are planned separately.

This PR's base does not include the independent CSV/TSV parser in #41 or ENV/SQL format settings in #37. Model inference currently receives file text. When those PRs integrate, preserve complete decoded/header-labeled CSV record context, restrict transformed spans to cell values, and share one model deadline across records. Do not replace that work with bare-cell inference: it missed addresses in the earlier fixtures. Large-file admission/performance work remains deferred.

The model is experimental. Published synthetic metrics and small integration fixtures are not evidence of production detection reliability. Names, addresses, and other sensitive data can be missed. Model failures never authorize reading the original through another tool.

## Standalone/Core users

The same explicit setup command can be used without registering or running an MCP server. It produces the standalone native bundle; installing it does not activate a model in Core's current Python API. Applications must use a compatible adapter or invoke the local native executable with the bundle path and JSONL `{ "text": "..." }` requests. The executable returns findings and redacted text; application developers must enforce their own output/log privacy contract. Windows uses `datafog-pii.exe`.

For users who do not install the MCP package, the model repository also contains standalone installation tooling and download instructions. It verifies the explicitly supplied archive SHA-256 and its manifest; this MCP CLI additionally binds the manifest hash and MCP/Core pairing to its reviewed catalog.

## Reproduce real integration

```sh
DATAFOG_TEST_MODEL_BUNDLE=/absolute/verified/installation \
  uv run pytest tests/test_model_workflow.py::test_real_release_opt_in --no-cov
```

Run explicit installation before enabling this test. Ordinary CI neither downloads weights nor contacts Hugging Face. Model/native archive bytes are never committed to this repository. Weights and DataFog source are Apache-2.0; bundles retain third-party runtime/dependency notices and dataset attribution (CC-BY-4.0). Uninstalling MCP preserves model directories; remove an installation and its policy section locally when no longer needed.
