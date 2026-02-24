#!/bin/sh
# Nullify CLI installer
# Usage: curl -sSfL https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh | sh
set -e

REPO="Nullify-Platform/cli"
BINARY_NAME="nullify"

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

main() {
  # Parse arguments
  NULLIFY_HOST=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --host)
        NULLIFY_HOST="$2"
        shift 2
        ;;
      --host=*)
        NULLIFY_HOST="${1#*=}"
        shift
        ;;
      *)
        shift
        ;;
    esac
  done

  os=$(detect_os)
  arch=$(detect_arch)
  version=$(get_latest_version)
  version_number="${version#v}"

  echo "Installing Nullify CLI ${version} for ${os}/${arch}..."

  # Determine archive extension
  if [ "$os" = "windows" ]; then
    ext="zip"
  else
    ext="tar.gz"
  fi

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
  expected_checksum=$(grep "${archive_name}" "${tmp_dir}/checksums.txt" | awk '{print $1}')
  if [ -z "$expected_checksum" ]; then
    echo "Warning: could not find checksum for ${archive_name}, skipping verification" >&2
  else
    if command -v sha256sum > /dev/null 2>&1; then
      actual_checksum=$(sha256sum "${tmp_dir}/${archive_name}" | awk '{print $1}')
    elif command -v shasum > /dev/null 2>&1; then
      actual_checksum=$(shasum -a 256 "${tmp_dir}/${archive_name}" | awk '{print $1}')
    else
      echo "Warning: no sha256sum or shasum found, skipping verification" >&2
      actual_checksum="$expected_checksum"
    fi

    if [ "$actual_checksum" != "$expected_checksum" ]; then
      echo "Checksum verification failed!" >&2
      echo "Expected: ${expected_checksum}" >&2
      echo "Actual:   ${actual_checksum}" >&2
      exit 1
    fi
    echo "Checksum verified."
  fi

  # Extract
  echo "Extracting..."
  if [ "$ext" = "zip" ]; then
    unzip -q "${tmp_dir}/${archive_name}" -d "${tmp_dir}/extracted"
  else
    mkdir -p "${tmp_dir}/extracted"
    tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}/extracted"
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
  cp "${tmp_dir}/extracted/${BINARY_NAME}" "${install_dir}/${BINARY_NAME}"
  chmod +x "${install_dir}/${BINARY_NAME}"

  echo ""
  echo "Nullify CLI ${version} installed to ${install_dir}/${BINARY_NAME}"

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
    mkdir -p "$config_dir"
    printf '{"host":"%s"}\n' "$NULLIFY_HOST" > "${config_dir}/config.json"
    echo "Configured host: ${NULLIFY_HOST}"
  fi

  echo ""
  echo "Run 'nullify --version' to verify the installation."

  if [ -n "$NULLIFY_HOST" ]; then
    echo "Run 'nullify auth login' to authenticate."
  else
    echo "Run 'nullify auth login --host api.<your-instance>.nullify.ai' to get started."
  fi
}

main "$@"
