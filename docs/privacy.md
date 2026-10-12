# Privacy and security boundaries

**What stays on the machine.** File contents are read and processed locally, and the server makes no network requests while running. FastMCP's update check is switched off, and its OpenTelemetry hooks do nothing unless you install an OpenTelemetry SDK and configure an exporter yourself. Tool responses are a different matter: they go into the agent's context, and the agent sends its context to its model provider. That is why responses carry no file contents or matched values. Installing the server downloads packages, which is separate from running it.

**What this does and does not protect.** No tool response contains file contents or matched values, so "is this file sensitive" can be answered without the answer carrying the sensitive parts. That is the whole of the guarantee. Note that the agent can still open the file directly, and sometimes will.

The guarantee holds when a tool fails, too. An unexpected error returns only its type, such as `datafog failed with RuntimeError`, and its details are kept out of both the response and the server's log.

These checks are advisory and reduce exposure; they do not de-identify data or enforce an agent's file access. They complement enterprise data-loss-prevention (DLP) and endpoint controls rather than replace them. Plain-text names and street addresses are not detected by this installation.

What responses do carry:

- **Paths.** Every response names the files it read and wrote, and errors name the path they refused. A filename like `jane_doe_lab_results.csv` identifies a person on its own.
- **Metadata.** Entity types, per-type counts, and character offsets, plus numeric record/column locations for tables. These reveal that a file holds, say, two email addresses at known positions, without revealing addresses, cell values, or header text.
- **Allowed roots.** A refused path returns the configured roots, which name directories on your machine.

For vulnerability reporting, see [SECURITY.md](../SECURITY.md).

[Back to the README](../README.md)
