# Consistent pseudonyms and local key setup

Use `datafog_pseudonymize(path, scope)` when analysis needs to link repeated values across files. Core creates deterministic keyed pseudonyms: the same exact value and entity type, with the same key, produces the same replacement. Separate keys separate linkage; different scope names alone do not. Changes in case, formatting, or detector boundaries may affect matches. Pseudonymization preserves linkage and does **not** make data anonymous.

The same `input_format` and `has_header` options apply as for the other file tools. CSV/TSV pseudonyms use decoded values, preserving headers, table structure, and untouched cell syntax; exact allowlists still apply. Missing scanning folders return the same warnings without blocking explicit pseudonymization or widening routine scope.

Configure a scope in `~/.config/datafog/policy.toml`. Keys never belong in the policy, tool arguments, or environment variables:

```toml
version = 1

[pseudonymization.scopes.customers]
key_ref = "customer-analysis"
key_version = "1"
backend = "keyring"
```

Then explicitly create its key locally:

```bash
datafog-mcp keys create customers
```

The default backend accepts only OS credential stores supported by `keyring`: macOS Keychain, Windows Credential Manager, Linux Secret Service/libsecret, or KWallet. The OS store must be configured and unlocked. Plaintext, fallback, and chained backends are refused; explicitly select a supported OS backend if your keyring setup normally uses a chain. An unavailable or locked store fails instead of switching to a file. Setup never intentionally replaces an existing key and prints no key material. Concurrent OS-store setup commands use a local `.key-setup.lock` directory beside the policy; a stale lock must be inspected and removed locally before retrying.

For a headless **POSIX** system, explicitly select file storage instead:

```toml
[pseudonymization.scopes.customers]
key_ref = "customer-analysis"
key_version = "1"
backend = "file"
key_file = "/home/service/.config/datafog/keys/customers.key"
```

Create the private parent directory yourself (`mkdir -p` and `chmod 700`), then run the same `keys create customers` command. The path must be absolute (or start with `~`), without `..` or symlinks in any component. Use the actual canonical path if a directory such as `/tmp` is a symlink on your OS. Setup exclusively creates an owner-only `0600` file containing a base64-encoded 256-bit random key; this backend is protected by filesystem permissions, not encryption at rest. Retrieval requires a regular file owned by the current user, exactly `0600`, with one hard link. Symlinks, hard links, malformed keys, and unavailable storage are refused. File storage is not supported on Windows.

Missing keys fail even when the input has no findings. MCP tools never create keys, rotate them, or choose a different backend. Each request resolves one key snapshot. Configured key files and their symbolic/hard-link aliases are refused as data inputs and copy destinations. Copies retain the existing roots, fixed-directory, no-overwrite, permission, and disk-space safeguards; exact allowlists still apply. Tool responses expose paths and counts, never keys, matched values, pseudonyms, or content digests.

To recommend this strategy after a scan, add:

```toml
[workflow]
on_findings = "transform"
transform_strategy = "pseudonymize"
pseudonym_scope = "customers"
```

`datafog_policy` and `datafog-mcp policy` expose configured scope names without retrieving keys. A workflow naming an absent scope is invalid. Preserve the key, reference/version, and policy securely if future outputs must remain joinable. Deleting or replacing a key breaks linkage with earlier outputs; no key export, recovery, or rotation command is provided in this release.


[Back to the README](../README.md)
