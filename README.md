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

Opens your browser to sign in with your identity provider (for example Microsoft Entra ID or GitLab). Tokens are stored locally and refreshed automatically.

With no host saved, the CLI signs in through nullify.ai, the Nullify router. With a host saved or passed, it first asks that instance where its login runs (`GET /auth/cli/config`): an instance on the router hands the login to the router, and an instance that signs in itself keeps its own login. The CLI only follows an answer naming your instance or a Nullify router, and fails otherwise.

```sh
# Through the router, or wherever your saved instance says
nullify auth login

# Name your instance; on the router this still signs in at the router
nullify auth login --host acme.nullify.ai

# Choose the organization to start with
nullify auth login --org acme-web
```

One router login covers every instance the router lists for you, so `--host <instance>` works afterwards without another login, and an older login an instance ran itself is replaced. After signing in, the CLI selects the organization commands run as: the one you pass with `--org`, the one you used last, the only one, or the one you pick in a terminal.

### Organizations

One login can cover several organizations, on one instance or several. Each command runs as the first of these that applies:

1. `--org <name|id>`
2. `NULLIFY_ORG` (name or id)
3. `NULLIFY_GITHUB_OWNER_ID`
4. The owner of the current directory's git remote, if it names exactly one of your organizations on the instance (worktrees and submodules included)
5. Your default, set by `nullify org use` or the last login
6. Your only organization on the instance

If your default is no longer available, the command stops and says so rather than running as another organization; in a terminal it asks. When nothing applies and you have several organizations, the CLI asks in a terminal and remembers the answer; elsewhere it fails and lists the choices. `nullify org list` shows your organizations and which rule picked the one in use.

Signed in through the router, `nullify org use` can name an organization on another instance: plain commands then run on that instance. `--org` does the same for one command when no `--host` is set.

```sh
# See your organizations on this instance and which one is in use
nullify org list

# Make one your default
nullify org use acme-web

# Run one command as another
nullify findings --org acme-payments
```

An API token (`NULLIFY_TOKEN`) belongs to one organization, and the server uses it when the command names none. With a token, only `--org`, `NULLIFY_ORG` and `NULLIFY_GITHUB_OWNER_ID` apply (the first two are looked up on the instance itself); `nullify org use`, the git remote and the prompt are for browser logins. An API token always needs your instance as the host (`--host` or `NULLIFY_HOST`), never `nullify.ai`. When `NULLIFY_TOKEN` is set it wins over your browser login, and `nullify auth status` says so.

### Upgrading from an earlier version

Your login and your selected organization carry over. If you used an API token as a workaround for the router login, remove `NULLIFY_TOKEN` and `NULLIFY_GITHUB_OWNER_ID` from your shell and your MCP configuration, run `nullify auth login`, and restart your MCP servers. Upgrade every copy of the CLI your tools run: an older copy running alongside can overwrite the login file.

### Environment Variables

```sh
export NULLIFY_HOST=api.acme.nullify.ai
export NULLIFY_TOKEN=your-token-here
export NULLIFY_ORG=acme-web   # optional: organization to run as, by name or id
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
| `nullify findings` | List findings across all scanner types with filters |
### Authentication

| Command | Description |
|---------|-------------|
| `nullify auth login` | Authenticate via browser SSO |
| `nullify auth logout` | Clear stored credentials for a host |
| `nullify auth status` | Show auth state, host, auth host, organization, and token expiry |
| `nullify auth token` | Print raw access token to stdout (pipe-friendly) |
| `nullify auth switch` | Switch active instance or list configured instances |
| `nullify auth config` | Print the effective host, auth host, data host, and organization as JSON |
| `nullify org list` | List the organizations you can use, and which one commands run as and why |
| `nullify org use <name\|id>` | Remember the organization commands run as (and, through the Nullify router, its instance) |

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
```

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
- **Triage** — mark findings as false positive, accepted risk, or reopen
- **Remediate** — generate AI-powered fix diffs and open PRs, end-to-end
- **Track** — campaigns, escalations, SLA policies, code reviews

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

One server serves one instance. When your login covers several organizations there, every tool takes an optional `org` argument (name or id), and the `list_organizations` tool lists them; every result says which organization it ran as. Without the argument a call uses the default the server settled when it started (`--org`, then the same order as the CLI); `nullify org use` in a terminal does not change a running server. If that leaves several organizations, the call returns the choices instead of guessing. To give each organization its own server, add one entry per organization:

```json
{
  "mcpServers": {
    "nullify-acme-web": {
      "command": "nullify",
      "args": ["mcp", "serve", "--org", "acme-web"]
    },
    "nullify-acme-payments": {
      "command": "nullify",
      "args": ["mcp", "serve", "--org", "acme-payments"]
    }
  }
}
```

With Claude Code:

```sh
claude mcp add nullify-acme-web -- nullify mcp serve --org acme-web
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

The CLI stores configuration in `~/.nullify/`:

| File | Holds |
|------|-------|
| `config.json` | The active instance |
| `credentials.json` | Login tokens, one entry per login host (the router's login is shared by the instances that use it) |
| `hosts.json` | Per instance: the host its login runs on, and the organization picked with `nullify org use` |

Host resolution priority:

1. `--host` flag
2. `NULLIFY_HOST` environment variable
3. Config file (`~/.nullify/config.json`)

When the host is `nullify.ai`, the CLI signs in and refreshes tokens on nullify.ai and sends data requests to the selected organization's instance. GitHub Actions token exchange (`--github-token`) needs your instance host, not `nullify.ai`.

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--host` | Nullify instance (e.g., `acme.nullify.ai`), or `nullify.ai` to sign in through the Nullify router | From config |
| `--org` | Organization to run as, by name or id (see [Organizations](#organizations)) | |
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
