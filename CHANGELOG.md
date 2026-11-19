# Changelog

## Unreleased

### Changed

- `nullify ci gate` and `nullify ci report` now cover the repository being built. They sent `repository=<name>`, which no findings route reads, so every repository's gate counted every other repository's findings. They now read the repository's ID from GitHub Actions, GitLab CI, Bitbucket Pipelines or Azure Pipelines (Azure Repos), and send it the way each route scopes a request. Elsewhere, pass `--repository-id`, or `--all-repositories` for every repository. With neither, they exit 4 rather than count other repositories' findings. Pentest, bug hunt and CSPM findings have no repository and still count in every gate.
- `--severity-threshold` on `ci gate` and `ci report` applies to every scanner. It used to apply to SAST and CSPM only, so a low SCA, secrets, pentest or bug hunt finding failed a `critical` gate. Secrets findings carry no severity, so they count at any threshold, as do findings of unknown severity.
- Exit codes of `ci gate` and `ci report`: 2 now covers a scanner that refuses access (401 or 403), which exited 3, and the new 4 means invalid flags, which exited 1 like a failed gate.
- `nullify deps analyze` exits 1 when a dependency comes back with no verdict, or with an inconclusive one, so a pass means every dependency was judged. The API does not return verdicts yet, so until it does, pass `--fail-on=none` to queue analyses without gating. An unknown `--fail-on` value is an error.
- `nullify mcp serve --repo`, and the git remote it falls back to, now make the server filter findings searches and metrics to that repository. The flag used to add `?repository=` to every request, which no route reads, so nothing was filtered. A tool call that names a repository searches that one instead, and `repository: "*"` searches every repository.
- `nullify init` writes each AI client's MCP config where that client reads it. For Claude Code it runs `claude mcp add --scope user nullify -- nullify mcp serve`, or writes `.mcp.json` in the project when `claude` is not installed; it used to write `~/.claude/mcp.json`, which Claude Code does not read. For VS Code it writes `.vscode/mcp.json` with `servers` and `type: stdio`; it used to write `mcpServers`, which VS Code does not read. It no longer overwrites a config file it cannot parse, such as one with comments: it prints the entry to add by hand.
- `get_security_posture_summary` reports real totals of open findings by type and severity. It reported a page count of 0 or 1 per scanner, and fetched every bug hunt finding.
- `nullify update` compares versions, recognises development builds, and prints steps that work: the install script pinned to the new version on macOS and Linux, and the zip on Windows. It no longer suggests the Homebrew tap, which does not exist.
- `nullify open` opens `app.<instance>.nullify.ai`, or `app.nullify.ai` for an instance that signs in through the router. It opened `<instance>.nullify.ai`, which is the marketing site.
- `nullify auth logout` revokes the refresh token at Nullify before deleting the local credentials, so a copied credentials file stops working. A failed revocation prints a warning and the local credentials still go.
- `nullify auth login`, `logout` and `token` honour `NULLIFY_HOST`, in the same order as every other command: `--host`, then `NULLIFY_HOST`, then the configured host.
- `nullify whoami` reports an API token or GitHub Actions token as the sign-in, instead of "no credentials found".
- `nullify pentest` works again. It called API routes that no longer exist, so every run failed with 404. It now requests an assessment of an application configured in Nullify, as the dashboard's Request assessment button does. Nullify reviews the request before the pentest runs, so the command returns with the scan awaiting review and no traffic sent to the target. Name the application with `--app-name` or the new `--app-id`; when both are set they must name the same application. `--target-host` picks the deployment when the application has several. The command refuses a target that is not confirmed as non-production. The output is JSON with `scan_id`, `status`, `mode`, `awaiting_review`, `target_url` and `check_with`.
- `nullify fix` now follows the run. It used to send the request, read the diff and exit 0 without waiting for the run. CI callers now wait up to 50 minutes by default, because a run can take 45. `--timeout` sets the wait. A failed run, or a run still going at the timeout, exits 1 and prints how to check it. The run continues on the server. `--no-wait` gives the fast return: it starts the run, prints its state and exits 0. If the token expires during the wait, the command refreshes it and continues. If it cannot refresh it, the command prints `run_id`, `state` and `check_with`, and exits 3.
- `nullify mcp serve` and `nullify fix` honour `NULLIFY_HTTP_TIMEOUT`.
- `nullify ci gate` is unchanged.
- `nullify fix`: any API failure on the start request now exits 3, including 403 and 409. It exited 1 before.
- The MCP search with `limit: 0` is now an error.
- `nullify api admin delete-mapping` and `update-mapping` now print the fields of the published response only, because the published API now describes these responses. Other fields are dropped.
- For a search, `sca` means dependencies and containers. For a verb on one finding, `sca` still means the dependency route. The MCP tool `type` parameters accept the same names as the CLI.
- `get_findings_for_repo` returns `total`, `returned` and `truncated` per section, and says that cloud and bug hunt findings have no repository instead of an empty list.
- `nullify_fix_finding` now starts the run and returns at once, with a non-error result. It no longer waits and no longer takes `create_pr`. Use `nullify_get_fix_status` and `nullify_get_fix_diff`.

### Added

- `nullify api` follows the API that prod serves (bundle of 19 November 2026). New commands include batch allowlist and unallowlist for every scanner, pentest schedules, credential login status and runs, Slack identity links, application folders, scanner mirror reads and code review overrides.
- `ci gate` and `ci report`: `--repository-id` and `--all-repositories`.
- The install script takes `--version <tag>` to install a specific release, sends `GITHUB_TOKEN` to the GitHub API when it is set, and has `--help`.
- MCP: `nullify_list_scan_runs` takes `scan_type` (`sca_dependencies` or `sca_containers`) and lists SCPM runs; `list_repositories` takes `next_token`; `nullify_start_cloud_scan` takes `provider`, `account_ids` and `cluster_ids`; `nullify_create_threat_investigation` takes `informational`.
- `nullify api` now follows the API published on 2 November 2026 (it was pinned to 26 May). This adds about 530 commands, including `nullify api cspm` allowlist, unallowlist, archive, unarchive, mark and unmark false positive, patch, triage and ticket delete, and a new `nullify api dast` group.
- `nullify findings` subcommands: `list`, `get`, `triage`, `allowlist`, `unallowlist`, `archive`, `unarchive`, `mark-false-positive`, `unmark-false-positive`, `create-ticket`, `delete-ticket`, `feedback` and `get-feedback`.
- `nullify findings --type` accepts `scpm`. `--from` and `--to` set time bounds. The output adds `returned` and `truncated`. Each row is the JSON that the server sent, so it holds only the fields of that row and any field that the CLI does not know.
- MCP tools in the default set: `nullify_submit_finding_feedback`, `nullify_get_finding_feedback`. `nullify_allowlist_finding`, `nullify_unallowlist_finding` and `nullify_get_finding_triage` work for CSPM, and `nullify_unallowlist_finding` and `nullify_create_ticket` work for bug hunt.
- MCP tools in the new `findings-write` set and in `all`, not in the default set: `nullify_archive_finding`, `nullify_unarchive_finding`, `nullify_mark_false_positive`, `nullify_unmark_false_positive`, `nullify_delete_ticket`.
- `nullify findings fix-status` and `fix-diff`, with the MCP tools `nullify_get_fix_status` and `nullify_get_fix_diff`.
- MCP `list_action_items`. Every MCP tool now has read-only or destructive annotations.

### Known limits

- `nullify fix` exits 1 when a run succeeded but its diff cannot be read, even when it prints a new pull request. The exit is the same as before.
- `nullify findings` and the MCP search tools use the unified search. It returns triaged findings only, and a repository filter matches the exact stored name. With no `--type` inside a repository, cloud and bug hunt findings are excluded.


### Fixed

- The GitHub Actions token exchange (`--github-token`) posted to `https://<instance>.nullify.ai/auth/github_token`, which is the marketing site, so it has failed TLS on every run since v0.13.0. It now posts to the API host.
- The MCP server recovers from an expired token. Instance APIs deny an expired token with API Gateway's own 403, not 401, and the server only refreshed on 401, so a long session saw up to five minutes of 403s every hour. A refreshable token is now also replaced six minutes before it expires.
- `nullify_list_scan_runs` sent no repository, and no scan type for SCA, so every call failed or returned nothing.
- `nullify ci report` asked for 1,000 findings per page, which the SAST, SCA and secrets routes reject above 100, so those sections were empty and the command still exited 0. It now reads every page of 100. It also counted every SCA, secrets, pentest and bug hunt finding four times, once per severity, in the summary and in SARIF.
- Closed bug hunt findings (fixed, allowlisted, archived or false positive) no longer fail `ci gate`. SAST and CSPM findings of unknown severity now count.
- `nullify deps analyze` sends the organization for a user login, waits for a cached job that is still queued, treats `timed_out` as finished, and no longer sends one idempotency key shared by every tenant.
- `nullify auth login --org` on an instance that signs in itself now selects that organization. It was ignored. An unknown name saves no login.
- A pasted dashboard host (`app.<instance>.nullify.ai`) names the instance. It became `api.app.<instance>.nullify.ai`.
- An API token with no host says to set `--host` or `NULLIFY_HOST`, instead of suggesting `nullify auth login`.
- Bug hunt allowlisting records the allowlist type, through the new POST routes. SCA, sensitive data, bug hunt and CSPM now record the type and the unallowlist reason, so the `warning` field and the stderr warning are gone.
- Secrets credential actions call `/secrets/credentials/findings/*`, not the deprecated `/secrets/findings/*` alias.
- `nullify threat create --severity` and the MCP tool send the upper-case value the server filters on. The CLI rejects an unknown severity.
- `nullify repos` lists every repository, not only the first 100.
- `nullify sbom get` returns the newest SBOM of each project, or of `--project-id`, through a download link. Large repositories failed with a 500 at the 6 MB response cap, and `--project-id` returned the oldest SBOMs first.
- `nullify scan runs --type sca` sends the scan type the route requires. `--type` also takes `sca_dependencies` and `sca_containers`.
- `nullify --version` works on a build from `go install`; it was an unknown flag.
- The install script installs `nullify.exe` on Windows (Git Bash, MSYS), refuses an archive that has no checksum instead of skipping the check, and reports a `--host` with no value or an unknown option.
- `list_applications` sends its `limit`; `nullify://recent-findings` returns the newest findings, not the highest priority; the `investigate-repo` prompt no longer searches cloud and bug hunt findings by repository; the MCP server no longer advertises resource subscriptions it does not send.
- Login refuses an empty or zero-lifetime token, and a sign-in URL that is not https on the instance's domain. `~/.nullify` is tightened to 0700 when it already exists with looser permissions. Auth requests send the CLI's User-Agent.
- `make lint-docker` no longer lints a Dockerfile that does not exist.
- `nullify api context push` asked for upload credentials at `POST /admin/context/credentials`, which the API does not serve. It now uses `POST /admin/context/ingest`, which takes the same request and returns the same response.
- A test now checks every API path that hand-written code calls, with its method where the call names one, against the vendored OpenAPI spec that the typed client is generated from. A hand-written call that keeps an old path now fails CI instead of returning 404.
- `nullify fix --create-pr` stops when the server rescues an abandoned pull-request step and moves the run to `cached`. It exits 1 and says that no new pull request was opened. It used to wait for the whole timeout and then say that the run was still going.
- `nullify findings` and the MCP search reject a `--from` or `--to` that is not RFC 3339, plain dates included. The server ignored such a value, so the result was not filtered and the command exited 0.
- `nullify findings --type secrets` and `--type bughunt` sent filter values that the API rejects, and exited 3 with a 400.
- The MCP `type=scpm` search sent `Platform`, which the API accepts but which matches no finding, so it always returned nothing. `--type Platform` now means `scpm`. `--type Unknown` is rejected, because it also matches no finding.
- `nullify findings --type cspm` no longer filters by the repository of the working directory. Cloud findings have no repository, so that result was always empty.
- `nullify findings` rejects a `--limit` of zero or less, an unknown `--type` and an unknown `--status`. Each of these returned a wrong result before. Text after `nullify findings` that is not a subcommand is now an error, so a mistyped verb does not list findings.
- `nullify fix --create-pr` called a route that the API removed. The fix run opens the pull request itself, so the command now waits for that pull request and reports it. `nullify fix` also waits for the fix to end before it reads the diff, and accepts every type with autofix.
- `nullify_fix_finding` no longer calls the removed diff routes for CSPM, SCPM and pentest.
- `nullify fix` reported success for a failed fix. A failed state, a run still going at the timeout, and `--create-pr` with no new pull request now exit non-zero. The output adds `state` and `run_id`. `--create-pr` reports only a pull request that this run opened, never an older one.
- `nullify findings` could list sensitive-data secrets but every verb used the credential routes. `--type secrets_sensitive_data` uses `/secrets/sensitivedata/findings/...`, and each verb accepts the `type` value of a listed row. `--type secrets` still lists both.
- Unallowlisting a secret sends the `unallowlistType` that the API requires, with the value that the dashboard sends.
- MCP allowlist and unallowlist reject an empty reason or an invalid allowlist type before they call the API.

### Moved

These commands keep working. Each prints a deprecation notice on stderr and calls the new route.

| Old command | New command |
|-------------|-------------|
| `nullify api asset-graph list-reachability` | `nullify api context list-reachability` |
| `nullify api asset-graph list-search` | `nullify api context list-search` |
| `nullify api asset-graph list-subgraph` | `nullify api context list-subgraph` |
| `nullify api asset-graph list-summary` | `nullify api context list-asset-graph-summary` |
| `nullify api infrastructure list-graphs` | `nullify api context list-graphs` |
| `nullify api infrastructure list-info` | `nullify api context list-info` |
| `nullify api infrastructure list-summary` | `nullify api context list-infrastructure-graphs-summary` |
| `nullify api infrastructure get-graphs` | `nullify api context get-graphs` |
| `nullify api infrastructure get-download` | `nullify api context get-download` |
| `nullify api infrastructure get-graphs-versions` | `nullify api context get-infrastructure-graphs-versions` |
| `nullify api infrastructure get-graphs-versions-2` | `nullify api context get-infrastructure-graphs-versions-2` |

### Removed

The API no longer serves these routes, so these commands could only return 404. None of the routes is in the service specs of the deployed API.

| Command | Replacement |
|---------|-------------|
| `nullify api admin create-initialize`, `create-uninitialize` | `nullify api admin update-repositories-scan-scope` |
| `nullify api context list-cloud-accounts` | `nullify api context list-asset-inventory` |
| `nullify api context list-cloud-resources`, `list-resources` | `nullify api context list-asset-inventory` |
| `nullify api context list-public-facing` | `nullify api context list-public` |
| `nullify api cspm get-diff` | `nullify api cspm get-state` |
| `nullify api scpm get-diff` | `nullify api scpm get-state` |
| `nullify pentest get-pentest-findings-autofix-cache-diff` | `nullify api dast get-state` |
| `nullify api scpm create-cache-by-id`, `create-create_pr-by-id` | `nullify api scpm create-fix-by-id` |
| `nullify api scpm create-retriage` | `nullify api orchestrator create-retriage`, with a new body |
| `nullify api scpm list-dependencies` | `nullify api scpm create-dependencies-analyze`, `create-batch` |
| `nullify api sca get-sbom` | `nullify sbom get`, `nullify api context get-sboms-repository-latest` |
| `nullify api orchestrator create-complete` | None: the route exists only in a local stack |
| `nullify api manager list-credits`, `create-credits` | None: the credits system is gone |
| `nullify api manager list-customer-questions`, `get-customer-questions`, `delete-customer-questions`, `delete-customer-questions-2`, `delete-questions`, `patch-answers` | `nullify api manager list-action-items` |
| `nullify api manager list-escalations`, `patch-escalations` | `nullify api manager list-action-items` |

These commands called staff-only routes. The API gives a customer token 403 on them, so they could only fail. The published API lists them because they are not marked private at source.

| Command | Route |
|---------|-------|
| `nullify api admin create-approve`, `create-invitation`, `create-renew`, `create-revoke`, `list-operation`, `list-requests` | `/admin/operator/workspace-bootstrap/*` |
| `nullify api admin create-operator-github-tenant-route`, `create-operator-native-tenant-route` | `/admin/operator/{github,native}-tenant/route` |
| `nullify api admin create-operator-external-writes-initialize` | `/admin/operator/external-writes/initialize` |
| `nullify api admin list-package-feeds`, `create-package-feeds` | `/admin/operator/package-feeds` |
| `nullify api admin list-scan-entitlement`, `update-scan-entitlement` | `/admin/operator/scan-entitlement` |
| `nullify api admin list-operator-scan-scope-repositories`, `update-repositories` | `/admin/operator/scan-scope/repositories` |
| `nullify api admin list-operator-tenant-capabilities`, `update-operator-tenant-capabilities` | `/admin/operator/tenant-capabilities` |
| `nullify api context create-cloud-connector-pr-runs-recover-by-id`, `create-waf-allowlist-pr-runs-recover-by-id` | `/context/{cloud-connector,waf-allowlist}-pr/runs/{runId}/recover` |

`nullify api context create-reports` and `get-reports` are removed: the API deleted the legacy SBOM PDF reports. Use `nullify sbom get`.

`ci gate --repo` and `ci report --repo` are deprecated and have no effect. They never narrowed the results; use `--repository-id`.

The MCP tool `list_escalations` is removed. Its route `GET /manager/escalations` is gone from prod (#5596), so the tool only returned errors. Use `list_action_items`, which returns a different schema, so it is not an alias. `spec/mcp-tools.tsv` now locks the MCP tool names, annotations and tool sets.

`nullify pentest` drops `--spec-path`, `--header`, `--auth-config` and `--github-repo`, because the API schema, credentials and repository now come from the application's configuration in Nullify. It also drops `--local`, `--image-label`, `--force-pull` and `--use-host-network`, because the old Docker workflow called retired API routes. This release removes local execution for private-network targets. The server still accepts findings from an authorized creator of an external scan. Passing one of these flags fails with an unknown-flag error that names it. For a hosted assessment, configure the API schema and credentials on the application in Nullify, then run `nullify pentest --app-name <name>`, adding `--target-host <url>` when the application has several deployments.

### Deprecated flags

The API no longer accepts these filters. The flags stay accepted, have no effect and print a notice.

- `nullify api cspm list-scans --region`, `--scan-type`
- `nullify api asset-graph list-reachability --account-id`, `list-subgraph --account-id`
