<p align="center">
  <a href="https://nullify.ai">
    <img src="https://uploads-ssl.webflow.com/6492db86d53f84f396b6623d/64dad6c12b98dee05eb08088_nullify%20logo.png" alt="Nullify" width="300"/>
  </a>
</p>

<p align="center">
  <strong>The CLI for Nullify — a fully autonomous AI workforce for product security.</strong>
</p>

<p align="center">
  <a href="https://github.com/Nullify-Platform/cli/releases">
    <img src="https://img.shields.io/github/v/release/Nullify-Platform/cli" alt="GitHub release" />
  </a>
  <a href="https://github.com/Nullify-Platform/cli/actions/workflows/release.yml">
    <img src="https://github.com/Nullify-Platform/cli/actions/workflows/release.yml/badge.svg" alt="Release Status" />
  </a>
  <a href="https://docs.nullify.ai">
    <img src="https://img.shields.io/badge/docs-docs.nullify.ai-purple" alt="Documentation" />
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License" />
  </a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/Nullify-Platform/cli">
    <img src="https://api.securityscorecards.dev/projects/github.com/Nullify-Platform/cli/badge" alt="OpenSSF Scorecard" />
  </a>
  <a href="https://goreportcard.com/report/github.com/nullify-platform/cli">
    <img src="https://goreportcard.com/badge/github.com/nullify-platform/cli" alt="Go Report Card" />
  </a>
</p>

---

Scan, triage, fix, and track security vulnerabilities across your entire stack — from code to cloud — directly from your terminal. The Nullify CLI connects to your [Nullify](https://nullify.ai) instance and gives you access to SAST, SCA, secrets detection, DAST/pentesting, bug hunting, CSPM, AI-powered autofix, and interactive AI security agents.

## Features

- **Unified findings** — Query vulnerabilities across all scanner types (SAST, SCA, secrets, DAST, CSPM) in a single command
- **AI-powered remediation** — Generate fix patches and open PRs automatically
- **CI/CD quality gates** — Block deployments when critical findings are present
- **DAST/Pentest scanning** — Run API security scans in the cloud or locally via Docker
- **MCP server** — 50+ tools for AI coding assistants (Claude Code, Cursor, VS Code, and more)
- **Multi-instance support** — Manage multiple Nullify instances and switch between them

## Installation

### macOS / Linux

```sh
curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh
```

Pre-configure your instance during install:

```sh
curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh -s -- --host api.acme.nullify.ai
```

### Go

```sh
go install github.com/nullify-platform/cli/cmd/cli@latest
```

### Windows

Download the latest `.zip` for your architecture from [GitHub Releases](https://github.com/Nullify-Platform/cli/releases) and add the binary to your `PATH`.

### Verify

```sh
nullify --version
```

The installer verifies SHA-256 checksums automatically. Binaries are available for Linux, macOS, and Windows on both amd64 and arm64.

## Quick Start

```sh
# Set up your instance, authenticate, and configure MCP — all in one step
nullify init

# Check your security posture
nullify status

# View findings across all scanner types
nullify findings

```

## Authentication

### Interactive (SSO/IdP)

```sh
nullify auth login
```

Opens your browser to sign in through nullify.ai with your identity provider (for example Microsoft Entra ID or GitLab). After sign-in, the CLI selects the installation that holds your data: it uses the only one automatically, asks you to pick one in a terminal, or takes `--installation <name>` in scripts. Tokens are stored locally and refreshed automatically.

If you sign in through nullify.ai, do not set `--host` or `NULLIFY_HOST` to your instance; run `nullify auth login` and the CLI routes data requests to the selected installation. An explicit instance host uses only the credentials stored for that host.

To sign in to your own Nullify instance instead, pass its host:

```sh
nullify auth login --host acme.nullify.ai
```

Switch to another installation after signing in through nullify.ai:

```sh
nullify auth switch --installation other-org
```

### Environment Variables

```sh
export NULLIFY_HOST=api.acme.nullify.ai
export NULLIFY_TOKEN=your-token-here
```

### Multiple Instances

```sh
# Log in to a second instance
nullify auth login --host api.staging.nullify.ai

# Switch the active instance
nullify auth switch --host api.staging.nullify.ai

# List configured instances
nullify auth switch
```

## Commands

### Core

| Command | Description |
|---------|-------------|
| `nullify init` | Interactive setup wizard (instance, auth, MCP config) |
| `nullify status` | Security posture overview with finding counts by scanner |
| `nullify findings` | List findings across all scanner types with filters (same as `nullify findings list`) |
| `nullify findings allowlist` | Suppress a finding, with a required reason and allowlist type |
| `nullify findings unallowlist` | Re-open an allowlisted finding, with a required reason |
| `nullify findings archive` / `unarchive` | Archive or restore a finding (CSPM) |
| `nullify findings mark-false-positive` / `unmark-false-positive` | Set or clear the false positive mark |
| `nullify findings get` / `triage` | Read a finding or its AI triage |
| `nullify findings create-ticket` / `delete-ticket` | Manage the ticket of a finding |
| `nullify findings feedback` / `get-feedback` | Record or read feedback on a finding of any type |
### Authentication

| Command | Description |
|---------|-------------|
| `nullify auth login` | Authenticate via browser SSO |
| `nullify auth logout` | Clear stored credentials for a host |
| `nullify auth status` | Show auth state, host, and token expiry |
| `nullify auth token` | Print raw access token to stdout (pipe-friendly) |
| `nullify auth switch` | Switch active instance or installation, or list configured instances |
| `nullify auth config` | Print current CLI config as JSON |

### Scanning

| Command | Description |
|---------|-------------|
| `nullify pentest` | Run DAST pentest scans (cloud or local via Docker) |
| `nullify bughunt` | Cloud-based automated bug hunting |

### CI/CD

| Command | Description |
|---------|-------------|
| `nullify ci gate` | Quality gate — exits non-zero when findings exceed threshold |
| `nullify ci report` | Generate a markdown summary for PR comments |

### Tooling

| Command | Description |
|---------|-------------|
| `nullify mcp serve` | Start the MCP server for AI coding tools |
| `nullify completion` | Generate shell completions (bash, zsh, fish, powershell) |

## Findings

```sh
# All findings across every scanner
nullify findings

# Filter by severity and scanner type
nullify findings --severity critical --type sast

# Filter by repository and status
nullify findings --repo my-repo --status open

# Limit results
nullify findings --limit 50

# List CSPM or SCPM findings in one UTC window
nullify findings list --type cspm --from 2026-11-01T00:00:00Z --to 2026-11-02T00:00:00Z
nullify findings list --type scpm
```

`--type` accepts `sast`, `sca_dependencies`, `sca_containers`, `secrets`, `secrets_sensitive_data`, `pentest`, `bughunt`, `cspm` and `scpm`. An unknown type is an error.

`--type secrets` lists credentials and sensitive data together. To act on a listed finding, pass the `type` value of its row, for example `nullify findings get abc123 --type SecretsSensitiveData`. In a verb, `secrets` means credentials only.

The output reports `total`, `returned` and `truncated`:

| Result | Meaning |
|--------|---------|
| `total` 0, exit 0 | No finding matches the filters |
| `truncated` true, exit 0 | More findings exist; raise `--limit` |
| Exit 3 | An API or network failure, including no access (401 or 403) |

Act on a finding. Allowlisting needs a reason and an explicit type: `UserFalsePositive` when triage was wrong, `UserAssumeRisk` when the risk is real and accepted, `UserFixed` or `UserOther` otherwise. The server may not record the type for `bughunt`, `sca_dependencies`, `sca_containers` and `secrets_sensitive_data` yet. For these types the command writes a warning to stderr and adds a `warning` field to the result. The reason is recorded. For a CSPM false positive, use `findings mark-false-positive`: allowlisting with `UserFalsePositive` does not set `is_false_positive` on a CSPM finding.

```sh
nullify findings mark-false-positive abc123 --type cspm --reason "Bucket is public by design"
nullify findings allowlist abc123 --type sast --allowlist-type UserFalsePositive --reason "Test fixture"
nullify findings unallowlist abc123 --type cspm --reason "Bucket is no longer public"
nullify findings archive abc123 --type cspm
nullify findings feedback abc123 --verdict wrong --comment "Not reachable from the internet"
```

Raw API commands follow the API spec: `nullify api cspm create-allowlist-by-id`, `create-unallowlist-by-id`, `create-archive-by-id`, `create-unarchive-by-id`, `create-mark-false-positive-by-id`, `create-unmark-false-positive-by-id`, `patch-findings`, `get-triage` and `delete-ticket`.

## Command stability

`spec/command-names.lock` fixes the name of each API command, and `spec/command-surface.tsv` lists every command and flag. CI fails if a command or flag disappears unless `internal/commands/surface_decisions.go` records the decision. A moved command keeps working as a deprecated alias that calls the new route. See [CHANGELOG.md](CHANGELOG.md) for the moves.

## Pentest Scans

### Cloud Scan

```sh
nullify pentest \
  --app-name      "My REST API" \
  --spec-path     ./openapi.json \
  --target-host   https://api.myapp.dev \
  --github-owner  my-org \
  --github-repo   my-repo \
  --header        "Authorization: Bearer token123"
```

### Local Scan (Docker)

For APIs that aren't publicly accessible. Requires Docker.

```sh
nullify pentest \
  --app-name      "My REST API" \
  --spec-path     ./openapi.json \
  --target-host   http://localhost:8080 \
  --github-owner  my-org \
  --github-repo   my-repo \
  --local
```

Add `--use-host-network` if the target is running directly on the host machine.

## CI/CD Integration

### Quality Gate

Block PRs and deployments when findings exceed a severity threshold:

```yaml
# .github/workflows/security.yml
name: Security Gate
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Nullify CLI
        run: curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh

      - name: Security Gate
        run: nullify ci gate --severity-threshold high
        env:
          NULLIFY_HOST: ${{ vars.NULLIFY_HOST }}
          NULLIFY_TOKEN: ${{ secrets.NULLIFY_TOKEN }}
```

### PR Security Summary

Add a security report to your pull request:

```yaml
      - name: Security Report
        run: nullify ci report >> $GITHUB_STEP_SUMMARY
        env:
          NULLIFY_HOST: ${{ vars.NULLIFY_HOST }}
          NULLIFY_TOKEN: ${{ secrets.NULLIFY_TOKEN }}
```

## MCP Server

The CLI includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/) server with 50+ tools, giving AI coding assistants full access to your security data. Capabilities include:

- **Query** — findings, repositories, SBOMs, cloud accounts, metrics, trends
- **Triage** — allowlist, archive or mark false positive across every finding type, including CSPM, reopen, and record feedback
- **Remediate** — start AI-powered fixes, then follow them with `nullify_get_fix_status` and `nullify_get_fix_diff`
- **Track** — campaigns, action items, SLA policies, code reviews

`nullify mcp serve --tools findings-write` adds the tools that the default set leaves out: archive, unarchive, mark and unmark false positive, and delete ticket. `--tools all` also has them. Every tool that changes state carries the destructive annotation, so a client can ask a person first. `spec/mcp-tools.tsv` lists every tool, its access and its tool sets.

### Setup

Add the following to your MCP config file:

| Tool | Config path |
|------|-------------|
| Claude Code | `.mcp.json` (project root) or `~/.claude.json` (user) |
| Cursor | `.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` |

```json
{
  "mcpServers": {
    "nullify": {
      "command": "nullify",
      "args": ["mcp", "serve"]
    }
  }
}
```

Scope findings to a specific repository with `--repo`:

```json
{
  "mcpServers": {
    "nullify": {
      "command": "nullify",
      "args": ["mcp", "serve", "--repo", "my-repo"]
    }
  }
}
```

## Configuration

The CLI stores configuration at `~/.nullify/config.json`. Host resolution priority:

1. `--host` flag
2. `NULLIFY_HOST` environment variable
3. Config file (`~/.nullify/config.json`)

When the host is `nullify.ai`, the CLI signs in and refreshes tokens on nullify.ai and sends data requests to the selected installation's instance. GitHub Actions token exchange (`--github-token`) needs your instance host, not `nullify.ai`.

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--host` | Nullify instance (e.g., `acme.nullify.ai`), or `nullify.ai` to sign in through the Nullify router | From config |
| `--output, -o` | Output format (`json`, `table`, `yaml`) | `json` |
| `--verbose, -v` | Enable verbose logging | `false` |
| `--debug, -d` | Enable debug logging | `false` |
| `--nullify-token` | API token (overrides stored credentials) | |
| `--github-token` | GitHub Actions job token (auto-exchanged for Nullify token) | |

## Requirements

- **macOS, Linux, or Windows** (amd64 or arm64)
- **Docker** — required only for local pentest scans (`--local`)
- A [Nullify](https://nullify.ai) instance — [request access](https://nullify.ai)

## Documentation

Full documentation is available at **[docs.nullify.ai](https://docs.nullify.ai)**.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## License

[MIT](LICENSE)
