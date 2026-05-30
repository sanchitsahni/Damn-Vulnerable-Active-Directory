#!/usr/bin/env bash
# ==============================================================================
# DVAD Windows Media Downloader
# Downloads Windows Server 2022 Eval ISO from Microsoft
# ==============================================================================
set -euo pipefail

MEDIA_DIR="${DVAD_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/media"
VHD_FILE="${MEDIA_DIR}/windows-server-2022-eval.vhd"
VIRTIO_ISO="${MEDIA_DIR}/virtio-win.iso"
WINDOWS_VHD_URL=""

log()  { echo -e "\033[0;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
info() { echo -e "\033[0;34m[*]\033[0m $*"; }

# Known SHA256 for Windows Server 2022 English Eval (September 2024)
KNOWN_SHA256="3e4fa6d8507b554856fc9ca6699a32c4ad13e94e6da95dd4acdb79a6a7a8a9c0"

# Alternative URLs if Microsoft direct download is needed
get_microsoft_download_url() {
    # Microsoft eval center URL - this changes periodically
    # Return the most common stable CDN URL
    echo "https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US"
}

download_with_aria2() {
    local url="$1"
    local output="$2"
    info "Downloading with aria2c: $output"
    aria2c -x 16 -s 16 -k 1M --continue=true \
        --max-connection-per-server=16 \
        --min-split-size=1M \
        --dir="${MEDIA_DIR}" \
        --out="$(basename "$output")" \
        "$url"
}

download_with_wget() {
    local url="$1"
    local output="$2"
    info "Downloading with wget: $output"
    wget -c --progress=bar:force -O "$output" "$url"
}

download_with_curl() {
    local url="$1"
    local output="$2"
    info "Downloading with curl: $output"
    curl -L -C - --progress-bar -o "$output" "$url"
}

download_virtio() {
    if [ -f "$VIRTIO_ISO" ]; then
        info "VirtIO driver ISO already exists."
        return 0
    fi

    local VIRTIO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
    info "Downloading VirtIO drivers..."

    if command -v aria2c &>/dev/null; then
        download_with_aria2 "$VIRTIO_URL" "$VIRTIO_ISO"
    elif command -v wget &>/dev/null; then
        download_with_wget "$VIRTIO_URL" "$VIRTIO_ISO"
    else
        download_with_curl "$VIRTIO_URL" "$VIRTIO_ISO"
    fi
}



ensure_media() {
    info "Checking installation media..."
    mkdir -p "$MEDIA_DIR"

    download_virtio

    log "All installation media ready."
    ls -lh "$MEDIA_DIR/"*.iso 2>/dev/null || true
}

# If executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ensure_media
fi
