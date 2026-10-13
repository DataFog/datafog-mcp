# Uninstall

Remove the registration first. If the program goes first, Claude Code fails to start `datafog` in every session (`ENOENT`) until the registration is removed too.

```bash
claude mcp remove datafog --scope user
uv tool uninstall datafog-mcp
```

Then remove the configuration, if you created it with `datafog-mcp roots --edit`:

```bash
rm ~/.config/datafog/allowed_roots
```

The optional `~/.config/datafog/policy.toml` stores your copy destination, exact allowlists, routine scanning scope, and workflow guidance. Keep it for reinstalling, or remove it separately if you want to discard those settings. Removing it does not delete any copies.

If you remove both configuration files, `rmdir ~/.config/datafog` removes the now-empty directory.

If you set `DATAFOG_MCP_ALLOWED_ROOTS` in your shell profile, remove it there.

The server keeps no cache, log, or data directory of its own.

Two things remain, on purpose:

- **Copies the tools wrote.** These are your files, saved beside their originals or in your configured output directory with `_redacted`, `_masked`, or `_removed` in the name, and they may still hold values the detectors missed. Uninstalling doesn't touch them. To find them, review the results before deleting anything:

  ```bash
  find ~ \( -name '*_redacted.*' -o -name '*_masked.*' -o -name '*_removed.*' -o -name '*_pseudonymized.*' \) -type f
  ```

- **Claude Code's logs about the server.** Claude Code records its connections to each MCP server and keeps those records after the server is gone. They're under `~/.cache/claude-cli-nodejs/*/mcp-logs-datafog/` on Linux and `~/Library/Caches/claude-cli-nodejs/*/mcp-logs-datafog/` on macOS, and you can delete them.

For another MCP client, remove the `datafog` entry from that client's MCP configuration in place of the `claude mcp remove` step.

[Back to the README](../README.md)

## Pseudonymization keys

Uninstalling does not delete keys from OS credential storage or configured private files. Preserve them if future outputs must remain joinable. Deleting or replacing a key breaks linkage with earlier outputs. See [pseudonymization setup](pseudonymization.md).
