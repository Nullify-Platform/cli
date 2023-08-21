# Nullify CLI

This project is for a CLI tool to interact with Nullify.

## Usage

```
Usage: nullify [--host HOST] [--verbose] [--debug] [--nullify-token NULLIFY-TOKEN] [--github-token GITHUB-TOKEN] <command> [<args>]

Options:
  --host HOST, -h HOST [default: https://api.nullify.ai]
  --verbose, -v          enable verbose logging
  --debug, -d            enable debug logging
  --nullify-token NULLIFY-TOKEN
                         nullify api token
  --github-token GITHUB-TOKEN
                         github actions job token to exchange for a nullify token
  --help, -h             display this help and exit

Commands:
  dast                   test the given API for bugs and vulnerabilities
```
