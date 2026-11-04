# Changelog

## Unreleased

### Changed

- `nullify fix` now waits up to 50 minutes, because a run can take 45. It waited 5 minutes before. `--timeout` sets the wait. A run still going at the timeout exits non-zero and prints how to check it, and it continues on the server. `--no-wait` starts the run, prints its state and exits 0. If the token expires during the wait, the command refreshes it and continues. If it cannot refresh it, the command prints `run_id`, `state` and `check_with`, and exits 3.
- `nullify_fix_finding` now starts the run and returns at once, with a non-error result. It no longer waits and no longer takes `create_pr`. Use `nullify_get_fix_status` and `nullify_get_fix_diff`.

### Added

- `nullify api` now follows the API published on 2 November 2026 (it was pinned to 26 May). This adds about 530 commands, including `nullify api cspm` allowlist, unallowlist, archive, unarchive, mark and unmark false positive, patch, triage and ticket delete, and a new `nullify api dast` group.
- `nullify findings` subcommands: `list`, `get`, `triage`, `allowlist`, `unallowlist`, `archive`, `unarchive`, `mark-false-positive`, `unmark-false-positive`, `create-ticket`, `delete-ticket`, `feedback` and `get-feedback`.
- `nullify findings --type` accepts `scpm`. `--from` and `--to` set UTC bounds. The output adds `returned` and `truncated`.
- MCP tools in the default set: `nullify_submit_finding_feedback`, `nullify_get_finding_feedback`. `nullify_allowlist_finding`, `nullify_unallowlist_finding` and `nullify_get_finding_triage` work for CSPM, and `nullify_unallowlist_finding` and `nullify_create_ticket` work for bug hunt.
- MCP tools in the new `findings-write` set and in `all`, not in the default set: `nullify_archive_finding`, `nullify_unarchive_finding`, `nullify_mark_false_positive`, `nullify_unmark_false_positive`, `nullify_delete_ticket`.
- `nullify findings fix-status` and `fix-diff`, with the MCP tools `nullify_get_fix_status` and `nullify_get_fix_diff`.
- MCP `list_action_items`. Every MCP tool now has read-only or destructive annotations.

### Fixed

- `nullify findings --type secrets` and `--type bughunt` sent filter values that the API does not have, and always returned nothing.
- The MCP `type=scpm` search sent `Platform`, which the API does not have, and always returned nothing.
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

The MCP tool `list_escalations` is removed. Its route `GET /manager/escalations` is gone from prod (#5596), so the tool only returned errors. Use `list_action_items`, which returns a different schema, so it is not an alias. `spec/mcp-tools.tsv` now locks the MCP tool names, annotations and tool sets.

### Deprecated flags

The API no longer accepts these filters. The flags stay accepted, have no effect and print a notice.

- `nullify api cspm list-scans --region`, `--scan-type`
- `nullify api asset-graph list-reachability --account-id`, `list-subgraph --account-id`
