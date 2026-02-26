<a href="https://nullify.ai">
  <img src="https://uploads-ssl.webflow.com/6492db86d53f84f396b6623d/64dad6c12b98dee05eb08088_nullify%20logo.png" alt="Nullify" width="300"/>
</a>

# Nullify CLI

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
</p>
<p align="center">
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/Nullify-Platform/cli">
    <img src="https://api.securityscorecards.dev/projects/github.com/Nullify-Platform/cli/badge" alt="OpenSSF Scorecard" />
  </a>
  <a href="https://goreportcard.com/report/github.com/nullify-platform/cli">
    <img src="https://goreportcard.com/badge/github.com/nullify-platform/cli" alt="Go Report Card" />
  </a>
</p>

The Nullify CLI is the command-line interface for [Nullify](https://nullify.ai) — a fully autonomous AI workforce for product security. It provides access to SAST, SCA, Secrets Detection, Pentest, BugHunt, CSPM, and AI security agents.

## Installation

### macOS / Linux

```sh
curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh
```

### Windows

Download the latest `.zip` archive for your platform from the [GitHub Releases](https://github.com/Nullify-Platform/cli/releases) page and add the binary to your `PATH`.

### GitHub Actions

```yaml
- name: Install Nullify CLI
  run: curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh
```

### Verify Installation

```sh
nullify --version
```

## Quick Start

```sh
# 1. Run the setup wizard
nullify init

# 2. Check your security posture
nullify status

# 3. View findings
nullify findings

# 4. Chat with Nullify's AI agents
nullify chat
```

## Commands

| Command | Description |
|---------|-------------|
| `nullify init` | Interactive setup wizard (domain, auth, MCP config) |
| `nullify auth login` | Authenticate with your Nullify instance |
| `nullify auth status` | Show authentication status |
| `nullify pentest` | Run pentest scans (local Docker + cloud) |
| `nullify bughunt` | Cloud-based automated bug hunting |
| `nullify findings` | List findings across all scanner types |
| `nullify status` | Security posture overview |
| `nullify chat` | Interactive AI chat with security agents |
| `nullify ci gate` | CI quality gate (exit non-zero on findings) |
| `nullify ci report` | Generate markdown report for PR comments |
| `nullify mcp serve` | Start MCP server for AI tools |
| `nullify completion` | Generate shell completion scripts |

## Authentication

### Interactive Login

```sh
nullify auth login --host api.acme.nullify.ai
```

### Environment Variables

```sh
export NULLIFY_HOST=api.acme.nullify.ai
export NULLIFY_TOKEN=your-token-here
```

### GitHub Actions

```yaml
- name: Run Nullify Gate
  run: nullify ci gate --severity-threshold high
  env:
    NULLIFY_HOST: api.acme.nullify.ai
    NULLIFY_TOKEN: ${{ secrets.NULLIFY_TOKEN }}
```

### Multi-Host

The CLI supports multiple Nullify instances. Use `--host` to switch between them or `nullify auth switch` to change the default.

## Pentest Scans

### Cloud Scan

```sh
nullify pentest \
  --app-name      "My REST API" \
  --spec-path     "./openapi.json" \
  --target-host   "https://api.myapp.dev" \
  --github-owner  "my-org" \
  --github-repo   "my-repo" \
  --header        "Authorization: Bearer token123"
```

### Local Docker Scan

```sh
nullify pentest \
  --app-name      "My REST API" \
  --spec-path     "./openapi.json" \
  --target-host   "http://localhost:8080" \
  --github-owner  "my-org" \
  --github-repo   "my-repo" \
  --local
```

### Same-Machine Scan (Host Network)

```sh
nullify pentest \
  --app-name      "My REST API" \
  --spec-path     "./openapi.json" \
  --target-host   "http://localhost:8080" \
  --github-owner  "my-org" \
  --github-repo   "my-repo" \
  --local \
  --use-host-network
```

## Interactive Chat

```sh
# Interactive REPL
nullify chat

# Single-shot query
nullify chat "what are my critical findings?"

# Resume a conversation
nullify chat --chat-id abc123 "tell me more"
```

## Findings

```sh
# All findings
nullify findings

# Filter by severity and type
nullify findings --severity critical --type sast

# Filter by repository
nullify findings --repo my-repo --status open
```

## CI/CD Integration

### Quality Gate

Block deployments when critical or high findings are present:

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

### PR Report

Add a security summary as a PR comment:

```yaml
      - name: Security Report
        run: nullify ci report >> $GITHUB_STEP_SUMMARY
        env:
          NULLIFY_HOST: ${{ vars.NULLIFY_HOST }}
          NULLIFY_TOKEN: ${{ secrets.NULLIFY_TOKEN }}
```

## MCP Integration

The CLI includes an MCP (Model Context Protocol) server for use with AI coding tools.

### Claude Code

Add to your project's `.claude/mcp.json`:

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

### Cursor

Add to your project's `.cursor/mcp.json`:

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

### VS Code

Add to your project's `.vscode/mcp.json`:

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

The MCP server exposes tools for SAST, SCA, Secrets, Pentest, BugHunt, CSPM, Infrastructure, Code Reviews, and composite workflows like `remediate_finding` and `get_critical_path`.

## Global Options

| Flag | Description | Default |
|------|-------------|---------|
| `--host` | Nullify API instance (e.g., `api.acme.nullify.ai`) | From config |
| `--verbose, -v` | Enable verbose logging | `false` |
| `--debug, -d` | Enable debug logging | `false` |
| `--output, -o` | Output format (`json`, `table`, `yaml`) | `json` |
| `--nullify-token` | Nullify API token | From config |
| `--github-token` | GitHub Actions job token | |
