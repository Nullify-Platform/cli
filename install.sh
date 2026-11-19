#!/bin/sh
# Nullify CLI installer
# Usage: curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh
set -e

REPO="Nullify-Platform/cli"
BINARY_NAME="nullify"

usage() {
  cat <<'EOF'
Usage: install.sh [--host <instance>]

Installs the latest Nullify CLI release.

Options:
  --host <instance>  Save your Nullify instance, for example acme.nullify.ai
  -h, --help         Show this help
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

# Get latest release version from GitHub API
get_latest_version() {
  version=$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
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
  while [ $# -gt 0 ]; do
    case "$1" in
      --host)
        if [ $# -lt 2 ] || [ -z "$2" ] || [ "${2#-}" != "$2" ]; then
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
      -h|--help)
        usage
        exit 0
        ;;
      *)
        usage_error "unknown argument: $1"
        ;;
    esac
  done

  os=$(detect_os)
  arch=$(detect_arch)
  version=$(get_latest_version)

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
  curl -sSfL -o "${tmp_dir}/${archive_name}" "$download_url"
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
