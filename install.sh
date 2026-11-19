#!/bin/sh
# Nullify CLI installer
# Usage: curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh
set -e

REPO="Nullify-Platform/cli"
BINARY_NAME="nullify"

usage() {
  cat <<'EOF'
Usage: install.sh [--host <instance>] [--version <tag>]

Installs the Nullify CLI. Without --version it installs the latest release.

Options:
  --host <instance>  Save your Nullify instance, for example acme.nullify.ai
  --version <tag>    Install this release instead of the latest, for example v1.2.3
  -h, --help         Show this help

Environment:
  GITHUB_TOKEN       If set, sent to the GitHub API when looking up the latest
                     release, so shared CI IPs are not rate limited
EOF
}

# Print an error and the usage, then exit.
usage_error() {
  echo "Error: $1" >&2
  echo "" >&2
  usage >&2
  exit 1
}

# Detect OS
detect_os() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    linux)  echo "linux" ;;
    darwin) echo "darwin" ;;
    mingw*|msys*|cygwin*) echo "windows" ;;
    *) echo "Unsupported OS: $os" >&2; exit 1 ;;
  esac
}

# Detect architecture
detect_arch() {
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
  esac
}

# Succeed when an option value is present and is not another option.
is_option_value() {
  [ -n "$1" ] && [ "${1#-}" = "$1" ]
}

# Print a release tag in the v1.2.3 or v1.2.3-rc.1 form, adding the leading
# v when it is missing. Fail on anything else, so the tag is safe in a URL.
normalize_version() {
  tag="$1"
  case "$tag" in
    *[!0-9A-Za-z.-]*) return 1 ;;
  esac
  case "$tag" in
    v*) ;;
    *) tag="v${tag}" ;;
  esac
  printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || return 1
  echo "$tag"
}

# GET a GitHub API URL. GITHUB_TOKEN, when set, goes in a curl config read
# from stdin, so it never appears in the process list or the output.
github_api_get() {
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    printf 'header = "Authorization: Bearer %s"\n' "$GITHUB_TOKEN" | curl -sSfL --config - "$1"
  else
    curl -sSfL "$1"
  fi
}

# Get latest release version from GitHub API
get_latest_version() {
  version=$(github_api_get "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  if [ -z "$version" ]; then
    echo "Failed to determine latest version" >&2
    exit 1
  fi
  echo "$version"
}

# The release binary is nullify.exe on Windows and nullify elsewhere.
binary_file_name() {
  if [ "$1" = "windows" ]; then
    echo "${BINARY_NAME}.exe"
  else
    echo "${BINARY_NAME}"
  fi
}

# Print the SHA-256 of a file.
sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum > /dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "Error: no sha256sum or shasum found, cannot verify binary integrity" >&2
    exit 1
  fi
}

# Verify an archive against checksums.txt. An archive missing from
# checksums.txt is an error: installing it would skip the integrity check.
verify_checksum() {
  archive_path="$1"
  archive_file="$2"
  checksums_path="$3"

  expected_checksum=$(awk -v f="$archive_file" '$2 == f {print $1}' "$checksums_path")
  if [ -z "$expected_checksum" ]; then
    echo "Error: checksums.txt has no checksum for ${archive_file}, refusing to install an unverified binary" >&2
    exit 1
  fi

  actual_checksum=$(sha256_of "$archive_path")
  if [ "$actual_checksum" != "$expected_checksum" ]; then
    echo "Checksum verification failed!" >&2
    echo "Expected: ${expected_checksum}" >&2
    echo "Actual:   ${actual_checksum}" >&2
    exit 1
  fi
  echo "Checksum verified."
}

main() {
  # Parse arguments
  NULLIFY_HOST=""
  requested_version=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --host)
        if [ $# -lt 2 ] || ! is_option_value "$2"; then
          usage_error "--host needs a value, for example --host acme.nullify.ai"
        fi
        NULLIFY_HOST="$2"
        shift 2
        ;;
      --host=*)
        NULLIFY_HOST="${1#*=}"
        if [ -z "$NULLIFY_HOST" ]; then
          usage_error "--host needs a value, for example --host=acme.nullify.ai"
        fi
        shift
        ;;
      --version)
        if [ $# -lt 2 ] || ! is_option_value "$2"; then
          usage_error "--version needs a release tag, for example --version v1.2.3"
        fi
        requested_version="$2"
        shift 2
        ;;
      --version=*)
        requested_version="${1#*=}"
        if [ -z "$requested_version" ]; then
          usage_error "--version needs a release tag, for example --version=v1.2.3"
        fi
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        usage_error "unknown argument: $1"
        ;;
    esac
  done

  if [ -n "$requested_version" ]; then
    version=$(normalize_version "$requested_version") ||
      usage_error "--version must be a release tag such as v1.2.3 or v1.2.3-rc.1, not: ${requested_version}"
  fi

  os=$(detect_os)
  arch=$(detect_arch)
  if [ -z "$requested_version" ]; then
    version=$(get_latest_version)
  fi

  echo "Installing Nullify CLI ${version} for ${os}/${arch}..."

  # Determine archive extension
  if [ "$os" = "windows" ]; then
    ext="zip"
    if ! command -v unzip > /dev/null 2>&1; then
      echo "Error: unzip is required to extract the Windows release" >&2
      exit 1
    fi
  else
    ext="tar.gz"
  fi
  binary_file=$(binary_file_name "$os")

  archive_name="nullify_${os}_${arch}.${ext}"
  download_url="https://github.com/${REPO}/releases/download/${version}/${archive_name}"
  checksums_url="https://github.com/${REPO}/releases/download/${version}/checksums.txt"

  # Create temp directory
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir"' EXIT

  # Download archive and checksums
  echo "Downloading ${download_url}..."
  if ! curl -sSfL -o "${tmp_dir}/${archive_name}" "$download_url"; then
    echo "Error: could not download ${archive_name} for ${version}." >&2
    echo "Check that the release exists: https://github.com/${REPO}/releases/tag/${version}" >&2
    exit 1
  fi
  curl -sSfL -o "${tmp_dir}/checksums.txt" "$checksums_url"

  # Verify checksum
  echo "Verifying checksum..."
  verify_checksum "${tmp_dir}/${archive_name}" "$archive_name" "${tmp_dir}/checksums.txt"

  # Extract
  echo "Extracting..."
  if [ "$ext" = "zip" ]; then
    unzip -q "${tmp_dir}/${archive_name}" -d "${tmp_dir}/extracted"
  else
    mkdir -p "${tmp_dir}/extracted"
    tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}/extracted"
  fi

  if [ ! -f "${tmp_dir}/extracted/${binary_file}" ]; then
    echo "Error: ${archive_name} does not contain ${binary_file}" >&2
    exit 1
  fi

  # Determine install directory
  if [ -w "/usr/local/bin" ]; then
    install_dir="/usr/local/bin"
  elif [ -d "${HOME}/.local/bin" ]; then
    install_dir="${HOME}/.local/bin"
  else
    mkdir -p "${HOME}/.local/bin"
    install_dir="${HOME}/.local/bin"
  fi

  # Install binary
  cp "${tmp_dir}/extracted/${binary_file}" "${install_dir}/${binary_file}"
  chmod +x "${install_dir}/${binary_file}"

  echo ""
  echo "Nullify CLI ${version} installed to ${install_dir}/${binary_file}"

  # Check if install dir is in PATH
  case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *)
      echo ""
      echo "NOTE: ${install_dir} is not in your PATH."
      echo "Add it by running:"
      echo "  export PATH=\"${install_dir}:\$PATH\""
      ;;
  esac

  # Configure host if provided
  if [ -n "$NULLIFY_HOST" ]; then
    config_dir="${HOME}/.nullify"
    mkdir -m 0700 -p "$config_dir"
    # Sanitize host: strip characters that could break JSON
    sanitized_host=$(printf '%s' "$NULLIFY_HOST" | tr -d '"\\')
    printf '{"host":"%s"}\n' "$sanitized_host" > "${config_dir}/config.json"
    chmod 0600 "${config_dir}/config.json"
    echo "Configured host: ${NULLIFY_HOST}"
  fi

  echo ""
  echo "Run 'nullify --version' to verify the installation."

  if [ -n "$NULLIFY_HOST" ]; then
    echo "Run 'nullify auth login' to authenticate."
  else
    echo "Run 'nullify auth login' to sign in through nullify.ai, or 'nullify auth login --host <your-instance>.nullify.ai' for your own instance."
  fi
}

main "$@"
