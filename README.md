# Nullify CLI

This project is for a CLI tool to interact with Nullify.

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

Commands:
  dast                   Test the given app for bugs and vulnerabilities
```

## Running DAST Scans

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

Global options:
  --host HOST            The base URL of your Nullify API instance [default: https://api.nullify.ai]
  --verbose, -v          Enable verbose logging
  --debug, -d            Enable debug logging
  --nullify-token NULLIFY-TOKEN
                         Nullify API token
  --github-token GITHUB-TOKEN
                         GitHub actions job token to exchange for a Nullify API token
  --help, -h             display this help and exit
```

example:

```sh
nullify dast \
  --app-name     "My REST API" \
  --spec-path    "./openapi.json" \
  --target-host  "https://api.myapp1234.dev" \
  --github-owner "my-username" \
  --github-repo  "my-repo" \
  --header       "Authorization: Bearer 1234" \
```
