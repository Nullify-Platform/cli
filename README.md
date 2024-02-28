<a href="https://nullify.ai">
  <img src="https://uploads-ssl.webflow.com/6492db86d53f84f396b6623d/64dad6c12b98dee05eb08088_nullify%20logo.png" alt="Nullify" width="300"/>
</a>

# Nullify CLI

<p align="center">
  <a href="https://github.com/Nullify-Platform/cli/releases">
    <img src="https://img.shields.io/github/v/release/Nullify-Platform/cli" alt="GitHub release" />
  </a>
  <a href="https://github.com/Nullify-Platform/Kuat-Shipyards/actions/workflows/release.yml">
    <img src="https://github.com/Nullify-Platform/Kuat-Shipyards/actions/workflows/release.yml/badge.svg" alt="Release Status" />
  </a>
  <a href="https://join.slack.com/t/nullifycommunity/shared_invite/zt-1ve4xgket-PfkFjSDJK_kG8l~OA_GXUg">
    <img src="https://img.shields.io/badge/Slack-10%2B%20members-black" alt="Slack invite" />
  </a>
  <a href="https://docs.nullify.ai/features/api-scanning/cli/">
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

[Nullify](https://nullify.ai) CLI dynamically tests and fuzzes your endpoints for security vulnerabilities.

## Getting Started
 * Download the [latest release](https://github.com/Nullify-Platform/cli/releases) or build from source
 * See our [quickstart guide](https://docs.nullify.ai/features/api-testing) for more info

## Usage

```
Usage: nullify [--host HOST] [--verbose] [--debug] [--nullify-token NULLIFY-TOKEN] [--github-token GITHUB-TOKEN] <command> [<args>]

Options:
  --host HOST            The base URL of your Nullify API instance [default: https://api.nullify.ai]
  --verbose, -v          Enable verbose logging
  --debug, -d            Enable debug logging
  --nullify-token NULLIFY-TOKEN
                         Nullify API token
  --github-token GITHUB-TOKEN
                         GitHub actions job token to exchange for a Nullify API token
  --help, -h             display this help and exit
  --version              display version and exit

Commands:
  dast                   Test the given app for bugs and vulnerabilities
```

## Usage: DAST Scans

```
Usage: nullify dast [--app-name APP-NAME] [--spec-path SPEC-PATH] [--target-host TARGET-HOST] [--github-owner GITHUB-OWNER] [--github-repo GITHUB-REPO] [--header HEADER]

Options:
  --app-name APP-NAME    The unique name of the app to be scanned, you can set this to anything e.g. Core API
  --spec-path SPEC-PATH
                         The file path to the OpenAPI file (both yaml and json are supported) e.g. ./openapi.yaml
  --target-host TARGET-HOST
                         The base URL of the API to be scanned e.g. https://api.nullify.ai
  --github-owner GITHUB-OWNER
                         The GitHub username or organisation to create the Nullify issue dashboard in e.g. nullify-platform
  --github-repo GITHUB-REPO
                         The repository name to create the Nullify issue dashboard in e.g. cli
  --header HEADER        List of headers for the DAST agent to authenticate with your API
  --local                Test the given app locally for bugs and vulnerabilities in private networks
  --version VERSION      Version of the DAST local image that is used for scanning [default: latest]

Global options:
  --host HOST            The base URL of your Nullify API instance [default: https://api.nullify.ai]
  --verbose, -v          Enable verbose logging
  --debug, -d            Enable debug logging
  --nullify-token NULLIFY-TOKEN
                         Nullify API token
  --github-token GITHUB-TOKEN
                         GitHub actions job token to exchange for a Nullify API token
  --help, -h             display this help and exit
  --version              display version and exit
```

## Usage: Authentication

The Nullify CLI need to authenticate with the Nullify API.

This can be done in the following ways:

- Using the `--nullify-token` option
- Using the `NULLIFY_TOKEN` environment variable

### Example DAST Scan

Cloud Hosted Scan:
```sh
nullify dast \
  --app-name      "My REST API" \
  --spec-path     "./openapi.json" \
  --target-host   "https://api.myapp1234.dev" \
  --github-owner  "my-username" \
  --github-repo   "my-repo" \
  --header        "Authorization: Bearer 1234"
```

Locally Hosted Scan:
```sh
nullify dast \
  --app-name      "My REST API" \
  --spec-path     "./openapi.json" \
  --target-host   "https://api.myapp1234.dev" \
  --github-owner  "my-username" \
  --github-repo   "my-repo" \
  --header        "Authorization: Bearer 1234" \
  --local
```

The locally hosted scan can be run from within private networks to test private APIs.

## Global Options

| Name                | Description                                                            | Required | Default                |
|---------------------|------------------------------------------------------------------------|----------|------------------------|
| **`host`**          | The base URL of your Nullify API instance, e.g. https://api.nullify.ai | `false`  | https://api.nullify.ai |
| **`verbose`**       | Enable verbose logging                                                 | `false`  |                        |
| **`debug`**         | Enable debug logging                                                   | `false`  |                        |
| **`nullify-token`** | Nullify API token                                                      | `false`  |                        |
| **`github-token`**  | GitHub actions job token to exchange for a Nullify API token           | `false`  |                        |
| **`help`**          | Display help and exit                                                  | `false`  |                        |
| **`version`**       | Display version and exit                                               | `false`  |                        |

## DAST Options

| Name               | Description                                                                                         | Required | Default |
|--------------------|-----------------------------------------------------------------------------------------------------|----------|---------|
| **`app-name`**     | The unique name of the app to be scanned, e.g. Core API                                             | `true`   |         |
| **`spec-path`**    | The file path to the OpenAPI file (both yaml and json are supported), e.g. ./openapi.yaml           | `true`   |         |
| **`target-host`**  | The base URL of the API to be scanned, e.g. https://api.nullify.ai                                  | `true`   |         |
| **`github-owner`** | The GitHub username or organisation to create the Nullify issue dashboard in, e.g. nullify-platform | `true`   |         |
| **`github-repo`**  | The repository name to create the Nullify issue dashboard in, e.g. cli                              | `true`   |         |
| **`header`**       | List of headers for the DAST agent to authenticate with your API                                    | `false`  |         |
| **`local`**        | Test the given app locally for bugs and vulnerabilities in private networks                         | `false`  |         |
| **`version`**      | Version of the DAST local image that is used for scanning [default: ]                               | `false`  | latest  |

