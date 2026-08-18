#!/bin/bash
# run-vm-qemu.sh - Run Fedora CoreOS VM with gvisor-tap-vsock using QEMU
set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}/.."
TMP_DIR="${TMP_DIR:-${PROJECT_DIR}/tmp}"
BIN_DIR="${BIN_DIR:-${PROJECT_DIR}/bin}"
DISKS_DIR="${TMP_DIR}/disks"

# Sockets and ports
GVPROXY_SOCK="${TMP_DIR}/gvproxy-qemu.sock"
QEMU_PORT=5555
SSH_PORT=2222

# SSH credentials
IGNITION_USER="${IGNITION_USER:-test}"
IGNITION_PASSWORD_HASH='$y$j9T$TqJWt3/mKJbH0sYi6B/LD1$QjVRuUgntjTHjAdAkqhkr4F73m.Be4jBXdAaKw98sPC' # password: test
PRIVATE_KEY="${TMP_DIR}/id_qemu_test"
PUBLIC_KEY="${PRIVATE_KEY}.pub"

# VM configuration
IGNITION_FILE="${TMP_DIR}/qemu.ign"
QCON_LOG="${TMP_DIR}/qemu-console.log"
MEMORY="${MEMORY:-2048}"
CPUS="${CPUS:-2}"

# Filter API
SERVICES_SOCK="${TMP_DIR}/gvproxy-qemu-services.sock"
OUTBOUND_ALLOW="${OUTBOUND_ALLOW:-}"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    [ -n "${GVPROXY_PID:-}" ] && kill "${GVPROXY_PID}" 2>/dev/null || true
    [ -n "${QEMU_PID:-}" ] && kill "${QEMU_PID}" 2>/dev/null || true
    rm -f "${GVPROXY_SOCK}" "${SERVICES_SOCK}"
}

trap cleanup EXIT INT TERM

# Create directories
mkdir -p "${TMP_DIR}" "${DISKS_DIR}"

# Detect QEMU executable
detect_qemu() {
    local arch
    case "$(uname -m)" in
        x86_64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac

    for qemu in qemu-kvm "qemu-system-${arch}"; do
        if command -v "$qemu" &> /dev/null; then
            echo "$qemu"
            return
        fi
    done

    echo "Error: QEMU not found" >&2
    exit 1
}

QEMU_BIN=$(detect_qemu)
echo "Using QEMU: ${QEMU_BIN}"

# Detect architecture and acceleration
detect_qemu_args() {
    local machine accel

    case "$(uname)" in
        Darwin) accel="hvf:tcg" ;;
        Linux) accel="kvm:tcg" ;;
        *) accel="tcg" ;;
    esac

    case "$(uname -m)" in
        x86_64) machine="q35" ;;
        aarch64|arm64) machine="virt" ;;
        *) machine="q35" ;;
    esac

    echo "-machine ${machine},accel=${accel} -smp ${CPUS} -cpu host"
}

QEMU_ARGS=$(detect_qemu_args)

# Generate SSH keys if they don't exist
if [ ! -f "${PRIVATE_KEY}" ]; then
    echo "Generating SSH key pair..."
    ssh-keygen -t ed25519 -f "${PRIVATE_KEY}" -N "" -C "gvisor-qemu-test"
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
FCOS_IMAGE="${DISKS_DIR}/fedora-coreos.qcow2"
if [ ! -f "${FCOS_IMAGE}" ]; then
    echo "Downloading Fedora CoreOS image..."
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

    image, err := downloader.DownloadImage("qemu", "qcow2.xz")
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
    "--listen-qemu=tcp://127.0.0.1:${QEMU_PORT}"
    "--ssh-port=${SSH_PORT}"
    "--services=unix://${SERVICES_SOCK}"
)

if [ -n "${OUTBOUND_ALLOW}" ]; then
    # --config disables built-in defaults (DNS, forwards, DHCP), so the
    # generated config must include them alongside the filtering options.
    GVPROXY_CONFIG="${TMP_DIR}/gvproxy-qemu-config.yaml"
    ALLOW_YAML=""
    for pattern in ${OUTBOUND_ALLOW}; do
        ALLOW_YAML="${ALLOW_YAML}
    - \"${pattern}\""
    done
    cat > "${GVPROXY_CONFIG}" <<CFGEOF
listen:
  - unix://${GVPROXY_SOCK}
interfaces:
  qemu: tcp://127.0.0.1:${QEMU_PORT}
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
    if [ -S "${GVPROXY_SOCK}" ] && [ -S "${SERVICES_SOCK}" ]; then
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

# Detect EFI firmware
detect_efi() {
    if [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "arm64" ]; then
        for fw in /usr/share/AAVMF/AAVMF_CODE.fd /opt/homebrew/share/qemu/edk2-aarch64-code.fd; do
            if [ -f "$fw" ]; then
                echo "-drive if=pflash,format=raw,readonly=on,file=$fw"
                return
            fi
        done
    fi
    echo ""
}

EFI_ARGS=$(detect_efi)

# Start QEMU
echo "Starting QEMU VM..."
${QEMU_BIN} \
    ${QEMU_ARGS} \
    ${EFI_ARGS} \
    -m ${MEMORY} \
    -nographic \
    -serial "file:${QCON_LOG}" \
    -drive "if=virtio,file=${FCOS_IMAGE},snapshot=on" \
    -fw_cfg "name=opt/com.coreos/config,file=${IGNITION_FILE}" \
    -netdev "socket,id=vlan,connect=127.0.0.1:${QEMU_PORT}" \
    -device "virtio-net-pci,netdev=vlan,mac=5a:94:ef:e4:0c:ee" &

QEMU_PID=$!
echo "QEMU started (PID: ${QEMU_PID})"

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

    if [ $i -eq 120 ]; then
        echo "Error: VM failed to become ready" >&2
        echo "Check console log: ${QCON_LOG}"
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
echo "Console log: ${QCON_LOG}"
echo ""
echo "Press Ctrl+C to stop the VM"
echo ""

# Wait for processes
wait
