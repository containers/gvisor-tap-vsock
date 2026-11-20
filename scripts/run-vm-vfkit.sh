#!/bin/bash
# run-vm-vfkit.sh - Run Fedora CoreOS VM with gvisor-tap-vsock using vfkit (macOS only)
set -euo pipefail

# Check if running on macOS
if [ "$(uname)" != "Darwin" ]; then
    echo "Error: vfkit only works on macOS" >&2
    echo "Use run-vm-qemu.sh on Linux" >&2
    exit 1
fi

# Check if vfkit is installed
if ! command -v vfkit &> /dev/null; then
    echo "Error: vfkit is not installed" >&2
    echo "Install with: brew install vfkit" >&2
    exit 1
fi

# Check vfkit version (needs >= 0.6 for ignition support)
VFKIT_VERSION=$(vfkit -v | grep -oE '[0-9]+\.[0-9]+' | head -1)
VFKIT_MAJOR=$(echo "$VFKIT_VERSION" | cut -d. -f1)
VFKIT_MINOR=$(echo "$VFKIT_VERSION" | cut -d. -f2)

if [ "$VFKIT_MAJOR" -eq 0 ] && [ "$VFKIT_MINOR" -lt 6 ]; then
    echo "Error: vfkit version 0.6 or higher is required (found $VFKIT_VERSION)" >&2
    echo "Upgrade with: brew upgrade vfkit" >&2
    exit 1
fi

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}/.."
TMP_DIR="${TMP_DIR:-${PROJECT_DIR}/tmp}"
BIN_DIR="${BIN_DIR:-${PROJECT_DIR}/bin}"
DISKS_DIR="${TMP_DIR}/disks"

# Sockets and ports
GVPROXY_SOCK="${TMP_DIR}/gvproxy-vfkit.sock"
VFKIT_SOCK="${TMP_DIR}/vfkit.sock"
SSH_PORT=2223

# SSH credentials
IGNITION_USER="${IGNITION_USER:-test}"
IGNITION_PASSWORD_HASH='$y$j9T$TqJWt3/mKJbH0sYi6B/LD1$QjVRuUgntjTHjAdAkqhkr4F73m.Be4jBXdAaKw98sPC' # password: test
PRIVATE_KEY="${TMP_DIR}/id_vfkit_test"
PUBLIC_KEY="${PRIVATE_KEY}.pub"

# VM configuration
IGNITION_FILE="${TMP_DIR}/vfkit.ign"
EFI_STORE="${TMP_DIR}/efi-variable-store"
MEMORY="${MEMORY:-2048}"
CPUS="${CPUS:-2}"

# Filter API
SERVICES_SOCK="${TMP_DIR}/gvproxy-vfkit-services.sock"
OUTBOUND_ALLOW="${OUTBOUND_ALLOW:-}"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    [ -n "${GVPROXY_PID:-}" ] && kill "${GVPROXY_PID}" 2>/dev/null || true
    [ -n "${VFKIT_PID:-}" ] && kill "${VFKIT_PID}" 2>/dev/null || true
    rm -f "${GVPROXY_SOCK}" "${VFKIT_SOCK}" "${SERVICES_SOCK}"
    # Clean up ignition socket created by vfkit
    rm -f /tmp/ignition.sock
}

trap cleanup EXIT INT TERM

# Create directories
mkdir -p "${TMP_DIR}" "${DISKS_DIR}"

# Generate SSH keys if they don't exist
if [ ! -f "${PRIVATE_KEY}" ]; then
    echo "Generating SSH key pair..."
    ssh-keygen -t ed25519 -f "${PRIVATE_KEY}" -N "" -C "gvisor-vfkit-test"
fi

SSH_PUBLIC_KEY=$(cat "${PUBLIC_KEY}")

# Create ignition file
echo "Creating ignition file..."
cat > "${IGNITION_FILE}" <<EOF
{
  "ignition": {
    "version": "3.3.0"
  },
  "passwd": {
    "users": [
      {
        "name": "${IGNITION_USER}",
        "passwordHash": "${IGNITION_PASSWORD_HASH}",
        "sshAuthorizedKeys": [
          "${SSH_PUBLIC_KEY}"
        ],
        "groups": [
          "wheel",
          "sudo"
        ]
      }
    ]
  },
  "systemd": {
    "units": [
      {
        "name": "serial-getty@ttyS0.service",
        "dropins": [
          {
            "name": "autologin.conf",
            "contents": "[Service]\nExecStart=\nExecStart=-/usr/sbin/agetty --autologin ${IGNITION_USER} --noclear %I \$TERM\nTTYVTDisallocate=no"
          }
        ]
      }
    ]
  }
}
EOF

# Download Fedora CoreOS image
FCOS_IMAGE="${DISKS_DIR}/fedora-coreos-applehv.raw"
if [ ! -f "${FCOS_IMAGE}" ]; then
    echo "Downloading Fedora CoreOS image for Apple Hypervisor..."
    echo "This may take a while on first run..."

    # Use Go to download (reusing test infrastructure)
    cat > "${TMP_DIR}/download.go" <<'GOEOF'
package main

import (
    "fmt"
    "os"
    e2e_utils "github.com/containers/gvisor-tap-vsock/test-utils"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Fprintf(os.Stderr, "Usage: %s <disks-dir>\n", os.Args[0])
        os.Exit(1)
    }

    disksDir := os.Args[1]
    downloader, err := e2e_utils.NewFcosDownloader(disksDir)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error creating downloader: %v\n", err)
        os.Exit(1)
    }

    image, err := downloader.DownloadImage("applehv", "raw.gz")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error downloading image: %v\n", err)
        os.Exit(1)
    }

    fmt.Println(image)
}
GOEOF

    FCOS_IMAGE=$(cd "${PROJECT_DIR}" && go run "${TMP_DIR}/download.go" "${DISKS_DIR}" | tail -1)
    rm -f "${TMP_DIR}/download.go"
fi

echo "Using FCOS image: ${FCOS_IMAGE}"

# Start gvproxy
echo "Starting gvproxy..."
GVPROXY_ARGS=(
    "--listen=unix://${GVPROXY_SOCK}"
    "--listen-vfkit=unixgram://${VFKIT_SOCK}"
    "--ssh-port=${SSH_PORT}"
    "--services=unix://${SERVICES_SOCK}"
)

if [ -n "${OUTBOUND_ALLOW}" ]; then
    # --config disables built-in defaults (DNS, forwards, DHCP), so the
    # generated config must include them alongside the filtering options.
    GVPROXY_CONFIG="${TMP_DIR}/gvproxy-vfkit-config.yaml"
    ALLOW_YAML=""
    for pattern in ${OUTBOUND_ALLOW}; do
        ALLOW_YAML="${ALLOW_YAML}
    - \"${pattern}\""
    done
    cat > "${GVPROXY_CONFIG}" <<CFGEOF
listen:
  - unix://${GVPROXY_SOCK}
interfaces:
  vfkit: unixgram://${VFKIT_SOCK}
services: unix://${SERVICES_SOCK}
stack:
  outboundAllow:${ALLOW_YAML}
  dns:
    - name: containers.internal.
      records:
        - name: gateway
          ip: 192.168.127.1
        - name: host
          ip: 192.168.127.254
    - name: docker.internal.
      records:
        - name: gateway
          ip: 192.168.127.1
        - name: host
          ip: 192.168.127.254
  forwards:
    "127.0.0.1:${SSH_PORT}": "192.168.127.2:22"
  dhcpStaticLeases:
    "192.168.127.2": "5a:94:ef:e4:0c:ee"
CFGEOF
    # Replace individual flags with --config (they're already in the YAML)
    GVPROXY_ARGS=("--config=${GVPROXY_CONFIG}")
fi

"${BIN_DIR}/gvproxy" "${GVPROXY_ARGS[@]}" &
GVPROXY_PID=$!

# Wait for sockets to be created
echo "Waiting for gvproxy sockets..."
for i in {1..30}; do
    if [ -S "${GVPROXY_SOCK}" ] && [ -S "${VFKIT_SOCK}" ] && [ -S "${SERVICES_SOCK}" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -S "${GVPROXY_SOCK}" ]; then
    echo "Error: gvproxy socket not created" >&2
    exit 1
fi

echo "gvproxy started (PID: ${GVPROXY_PID})"
echo "API socket: ${GVPROXY_SOCK}"
echo "Services socket: ${SERVICES_SOCK}"
echo "vfkit socket: ${VFKIT_SOCK}"

# Remove old EFI store to ensure clean boot
rm -f "${EFI_STORE}"

# Start vfkit
echo "Starting vfkit VM..."
vfkit \
    --cpus ${CPUS} \
    --memory ${MEMORY} \
    --bootloader efi,variable-store="${EFI_STORE}",create \
    --device virtio-blk,path="${FCOS_IMAGE}" \
    --ignition "${IGNITION_FILE}" \
    --device virtio-net,unixSocketPath="${VFKIT_SOCK}",mac=5a:94:ef:e4:0c:ee &

VFKIT_PID=$!
echo "vfkit started (PID: ${VFKIT_PID})"

# Wait for SSH to be ready
echo "Waiting for VM to boot and SSH to be ready..."
echo "This may take 1-2 minutes on first boot..."
for i in {1..120}; do
    if ssh -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=2 \
           -o IdentitiesOnly=yes \
           -i "${PRIVATE_KEY}" \
           -p "${SSH_PORT}" \
           "${IGNITION_USER}@127.0.0.1" "echo ready" &>/dev/null; then
        echo "VM is ready!"
        break
    fi

    # Check if vfkit is still running
    if ! kill -0 ${VFKIT_PID} 2>/dev/null; then
        echo "Error: vfkit process died" >&2
        exit 1
    fi

    if [ $i -eq 120 ]; then
        echo "Error: VM failed to become ready" >&2
        exit 1
    fi

    sleep 1
done

# Display connection info
echo ""
echo "======================================"
echo "VM is running!"
echo "======================================"
echo ""
echo "SSH access:"
echo "  ssh -i ${PRIVATE_KEY} -p ${SSH_PORT} ${IGNITION_USER}@127.0.0.1"
echo ""
echo "Or use the helper:"
echo "  alias vm-ssh='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${PRIVATE_KEY} -p ${SSH_PORT} ${IGNITION_USER}@127.0.0.1'"
echo ""
echo "Filter API (curl examples):"
echo "  curl --unix-socket ${SERVICES_SOCK} http://localhost/services/filter/stats | jq"
echo "  curl --unix-socket ${SERVICES_SOCK} http://localhost/services/filter/connections | jq"
echo "  curl --unix-socket ${SERVICES_SOCK} http://localhost/services/filter/dns/queries | jq"
echo ""
echo "Test filtering:"
echo "  # Add domain to allowlist (allows domain + all subdomains)"
echo "  curl --unix-socket ${SERVICES_SOCK} -X POST http://localhost/services/filter/allowlist \\"
echo "    -d '{\"domain\":\"example.com\"}'"
echo ""
echo "  # Block by domain (domain + all subdomains)"
echo "  curl --unix-socket ${SERVICES_SOCK} -X POST http://localhost/services/filter/blocklist \\"
echo "    -d '{\"domain\":\"example.com\",\"reason\":\"blocked\"}'"
echo ""
echo "  # Watch events in real-time"
echo "  curl --unix-socket ${SERVICES_SOCK} http://localhost/services/filter/events"
echo ""
echo "Press Ctrl+C to stop the VM"
echo ""

# Wait for processes
wait
