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

Pin a release, for example in CI:

```sh
curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh -s -- --version v0.28.0
```

The installer writes `nullify` to `/usr/local/bin` when it can, otherwise to `~/.local/bin`. Without `--version` it asks the GitHub API for the latest release; set `GITHUB_TOKEN` to avoid that API's rate limit on shared CI runners. Unknown options are an error, and `--help` lists the options.

### Go

```sh
go install github.com/nullify-platform/cli/cmd/cli@latest
mv "$(go env GOPATH)/bin/cli" "$(go env GOPATH)/bin/nullify"
```

`go install` names the binary `cli`, after its directory, and puts it in `$(go env GOPATH)/bin` (or `$GOBIN` when set). Rename it to `nullify`, as above, so the commands in this README work.

### Windows

Download `nullify_windows_amd64.zip` from [GitHub Releases](https://github.com/Nullify-Platform/cli/releases), unpack it and add `nullify.exe` to your `PATH`. Windows on Arm runs the same build. In Git Bash, the install script above works too.

### Verify

```sh
nullify --version
```

The installer verifies SHA-256 checksums automatically and refuses an archive without one. Binaries are available for Linux and macOS on amd64 and arm64, and for Windows on amd64. A `go install` build reports its module version.

### Upgrade

`nullify update` checks for a newer release and prints the installer command pinned to it (on Windows, the steps for the zip). It does not change the installed binary itself.

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

Signed in through the router, `nullify org use` can name an organization on another instance: plain commands then run on that instance. `--org` does the same for one command when the command's host is the router (`nullify.ai`, the default after a router login).

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
export NULLIFY_ORG=acme-web              # optional: organization to run as, by name or id
export NULLIFY_GITHUB_OWNER_ID=12345678  # optional: organization to run as, by GitHub owner id
export NULLIFY_HTTP_TIMEOUT=120s         # optional: API request timeout as a Go duration (default 30s)
```

`NULLIFY_HOST` applies when `--host` is not passed (see [Configuration](#configuration)), and `NULLIFY_ORG` and `NULLIFY_GITHUB_OWNER_ID` when `--org` is not (see [Organizations](#organizations)). Raise `NULLIFY_HTTP_TIMEOUT` for slow calls such as starting a scan or an autofix.

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
| `nullify fix <finding-id>` | Generate an autofix for a finding and wait for it (`--create-pr` reports the pull request it opened, `--no-wait` returns at once) |
| `nullify findings fix-status` / `fix-diff` | Read the state and pull requests of a finding's autofix run, or the change it proposes |
| `nullify repos` | List every monitored repository |
| `nullify sbom get` | Get the latest SBOM of each project in a repository, or of one with `--project-id` |
| `nullify threat list` / `get` / `create` | List, read or create threat investigations (`--severity` takes `critical`, `high`, `medium`, `low` or `informational`) |
| `nullify open` | Open the Nullify dashboard in your browser |

### Authentication

| Command | Description |
|---------|-------------|
| `nullify auth login` | Authenticate via browser SSO |
| `nullify auth logout` | Clear stored credentials for a host |
| `nullify auth status` | Show auth state, host, auth host, organization, and token expiry |
| `nullify auth token` | Print raw access token to stdout (pipe-friendly) |
| `nullify auth switch` | Switch active instance or list configured instances |
| `nullify auth config` | Print the effective host, auth host, data host, and organization as JSON |
| `nullify whoami` | Show the host, the auth source (a login, an API token or a GitHub Actions token), and the organization commands run as |
| `nullify org list` | List the organizations you can use, and which one commands run as and why |
| `nullify org use <name\|id>` | Remember the organization commands run as (and, through the Nullify router, its instance) |

### Scanning

| Command | Description |
|---------|-------------|
| `nullify pentest` | Run DAST pentest scans (cloud or local via Docker) |
| `nullify bughunt` | Cloud-based automated bug hunting |
| `nullify secrets scan-file` | Local secret scan of a single file or stdin buffer; no API call or network access |
| `nullify scan start` / `status <scanId>` | Start a cloud scan, or check the status of one |
| `nullify scan runs` | List a repository's scan runs (`--type` takes `sast`, `sca`, `sca_dependencies`, `sca_containers` or `secrets`) |

### CI/CD

| Command | Description |
|---------|-------------|
| `nullify ci gate` | Quality gate for the repository being built — exits non-zero when its open findings meet the severity threshold |
| `nullify ci report` | Markdown (or `--format sarif`) summary of the repository's open findings, for PR comments |
| `nullify deps analyze` | Malware gate for dependencies (exit 20 on a suspicious package, 30 on a malicious one) |

`ci gate` and `ci report` cover one repository. They read its ID from GitHub Actions (`GITHUB_REPOSITORY_ID`), GitLab CI (`CI_PROJECT_ID`), Bitbucket Pipelines (`BITBUCKET_REPO_UUID`) or Azure Pipelines with Azure Repos (`BUILD_REPOSITORY_ID`). Elsewhere, pass `--repository-id <provider repository ID>`, or `--all-repositories` to gate on every repository; with neither, they exit 4. `--severity-threshold` applies to every scanner; secrets findings, and findings of unknown severity, count at any threshold. Pentest, bug hunt and cloud findings have no repository, so they count in every repository's gate. Exit codes: 0 pass, 1 findings at or above the threshold, 2 authentication failed or a scanner refused access, 3 an API or network failure, 4 invalid flags or no repository ID.

`deps analyze` fails (exit 1) when a dependency has no verdict yet, so a pass always means every dependency was judged benign. Pass `--wait` to wait for verdicts, or `--fail-on=none` to queue analyses without gating.

### Tooling

| Command | Description |
|---------|-------------|
| `nullify mcp serve` | Start the MCP server for AI coding tools |
| `nullify completion` | Generate shell completions (bash, zsh, fish, powershell) |
| `nullify api` | Direct API access, one command per API route (see [Command stability](#command-stability)) |
| `nullify update` | Check for a newer release and print how to install it |
| `nullify version` | Show the version, commit, build date, Go version, and platform |

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

Act on a finding. Allowlisting needs a reason and an explicit type: `UserFalsePositive` when triage was wrong, `UserAssumeRisk` when the risk is real and accepted, `UserFixed` or `UserOther` otherwise. The server records the reason and the type for every finding type. For a CSPM false positive, use `findings mark-false-positive`: allowlisting with `UserFalsePositive` does not set `is_false_positive` on a CSPM finding.

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

The CLI includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/) server with about 50 tools, giving AI coding assistants access to your security data. Capabilities include:

- **Query**: findings, repositories, applications, SBOMs and dependencies, scan runs, cloud scans, metrics and trends
- **Triage**: allowlist and unallowlist a finding of any type, and record feedback. Archive, unarchive and mark false positive are for CSPM findings only, and unmark false positive covers CSPM and SCPM findings.
- **Remediate**: start AI-powered fixes, then follow them with `nullify_get_fix_status` and `nullify_get_fix_diff`
- **Track**: campaigns, action items, SLA policies and threat investigations

`nullify mcp serve --tools findings-write` adds the tools that the default set leaves out: archive, unarchive, mark and unmark false positive, and delete ticket. `--tools all` also has them. Every tool that changes state carries the destructive annotation, so a client can ask a person first. `spec/mcp-tools.tsv` lists every tool, its access and its tool sets.

### Setup

`nullify init` configures each client it finds. To do it yourself:

| Tool | How to add the server |
|------|-----------------------|
| Claude Code | `claude mcp add --scope user nullify -- nullify mcp serve`, or `.mcp.json` in the project root with the `mcpServers` snippet below |
| Cursor | `.cursor/mcp.json` with the `mcpServers` snippet below |
| VS Code | `.vscode/mcp.json` with the `servers` snippet below |

Claude Code (`.mcp.json`) and Cursor (`.cursor/mcp.json`):

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

VS Code (`.vscode/mcp.json`):

```json
{
  "servers": {
    "nullify": {
      "type": "stdio",
      "command": "nullify",
      "args": ["mcp", "serve"]
    }
  }
}
```

One server serves one instance. When your login covers several organizations there, every tool takes an optional `org` argument (name or id), and the `list_organizations` tool lists them; every result says which organization it ran as. Without the argument a call uses the default the server settled when it started (`--org`, then the same order as the CLI); `nullify org use` in a terminal does not change a running server. If that leaves several organizations, the call returns the choices instead of guessing. To give each organization its own server, add one entry per organization (VS Code puts the same entries under `servers`, each with `"type": "stdio"`):

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
claude mcp add --scope user nullify-acme-web -- nullify mcp serve --org acme-web
```

### Default repository

Findings searches and metrics default to one repository: the one that `--repo` names (owner/name preferred), or else the repository of the git remote in the directory where the server starts. `nullify_search_findings`, `get_critical_path` and `get_security_posture_summary` filter to it for every finding type that can belong to a repository; cloud and bug hunt findings have none, so they are not filtered. The metrics tools and the `nullify://posture` resource filter to it as well, which leaves cloud and bug hunt findings out of them. A call that names a repository searches that one instead, and `nullify_search_findings` with `repository` set to `*` searches every repository. A result that the default filtered says so.

```json
{
  "mcpServers": {
    "nullify": {
      "command": "nullify",
      "args": ["mcp", "serve", "--repo", "acme/my-repo"]
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

- **macOS or Linux** (amd64 or arm64), or **Windows** (amd64, which Windows on Arm also runs)
- **Docker** — required only for local pentest scans (`--local`)
- A [Nullify](https://nullify.ai) instance — [request access](https://nullify.ai)

## Documentation

Full documentation is available at **[docs.nullify.ai](https://docs.nullify.ai)**.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## License

[MIT](LICENSE)
