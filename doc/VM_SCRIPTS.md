# VM Scripts for Testing gvisor-tap-vsock

This directory contains shell scripts to easily run Fedora CoreOS VMs with gvisor-tap-vsock for testing and development.

## Available Scripts

### `run-vm-qemu.sh` - QEMU-based VM (Linux/macOS)

Runs a Fedora CoreOS VM using QEMU with gvisor-tap-vsock networking.

**Supported Platforms:**
- Linux (x86_64, aarch64)
- macOS (x86_64, arm64)

**Prerequisites:**
```bash
# Linux
sudo apt-get install qemu-kvm qemu-system-x86 qemu-system-aarch64

# macOS
brew install qemu
```

**Usage:**
```bash
# Basic usage
./scripts/run-vm-qemu.sh

# With environment variables
MEMORY=4096 CPUS=4 ./scripts/run-vm-qemu.sh

# With outbound filtering (generates a YAML config automatically)
OUTBOUND_ALLOW="^.*\.github\.com$" ./scripts/run-vm-qemu.sh

# Multiple patterns (space-separated)
OUTBOUND_ALLOW="^.*\.github\.com$ ^registry\.fedoraproject\.org$" ./scripts/run-vm-qemu.sh
```

### `run-vm-vfkit.sh` - vfkit-based VM (macOS only)

Runs a Fedora CoreOS VM using vfkit (Apple Hypervisor Framework) with gvisor-tap-vsock networking.

**Supported Platforms:**
- macOS (arm64, x86_64) - requires macOS 11+

**Prerequisites:**
```bash
# Install vfkit (requires version 0.6+)
brew install vfkit

# Verify version
vfkit -v
```

**Usage:**
```bash
# Basic usage
./scripts/run-vm-vfkit.sh

# With environment variables
MEMORY=4096 CPUS=4 ./scripts/run-vm-vfkit.sh

# With outbound filtering (generates a YAML config automatically)
OUTBOUND_ALLOW="^.*\.example\.com$" ./scripts/run-vm-vfkit.sh
```

## Configuration

Both scripts support the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TMP_DIR` | `./tmp` | Working directory for temporary files |
| `BIN_DIR` | `./bin` | Directory containing compiled binaries |
| `MEMORY` | `2048` | VM memory in MB |
| `CPUS` | `2` | Number of CPU cores |
| `IGNITION_USER` | `test` | SSH username |
| `OUTBOUND_ALLOW` | _(empty)_ | Space-separated outbound allowlist patterns (regex). When set, the script generates a YAML config file and passes it via `--config` |

## First Run

On first run, the scripts will:

1. **Download Fedora CoreOS image** (~800MB) - this is cached in `./tmp/disks/`
2. **Generate SSH keys** - stored in `./tmp/id_*_test`
3. **Create ignition config** - for VM initialization
4. **Start gvproxy** - networking proxy with filter API
5. **Start VM** - takes 1-2 minutes to boot

Subsequent runs will reuse the cached image and SSH keys.

## Default Credentials

- **Username:** `test`
- **Password:** `test` (for console login)
- **SSH:** Key-based authentication (keys in `./tmp/`)

## Accessing the VM

### SSH Access

The scripts display SSH connection info after the VM boots:

```bash
# Direct SSH
ssh -i ./tmp/id_qemu_test -p 2222 test@127.0.0.1   # QEMU
ssh -i ./tmp/id_vfkit_test -p 2223 test@127.0.0.1  # vfkit

# Or use the alias (shown in script output)
alias vm-ssh='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ./tmp/id_qemu_test -p 2222 test@127.0.0.1'
vm-ssh
```

### Filter API Access

The Filter REST API is available via Unix socket:

```bash
# QEMU
SOCK="./tmp/gvproxy-qemu-services.sock"

# vfkit
SOCK="./tmp/gvproxy-vfkit-services.sock"

# View statistics
curl --unix-socket "$SOCK" http://localhost/services/filter/stats | jq

# View connections
curl --unix-socket "$SOCK" http://localhost/services/filter/connections | jq

# View DNS queries
curl --unix-socket "$SOCK" http://localhost/services/filter/dns/queries | jq

# Add domain to allowlist (allows domain + all subdomains)
curl --unix-socket "$SOCK" -X POST http://localhost/services/filter/allowlist \
  -d '{"domain":"example.com"}'

# Block connection
curl --unix-socket "$SOCK" -X POST http://localhost/services/filter/blocklist \
  -d '{"protocol":"tcp","ip":"10.0.0.5","port":443}'

# Watch real-time events
curl --unix-socket "$SOCK" http://localhost/services/filter/events
```

## Testing Filtering

### Example 1: Basic Allowlist

```bash
# Start VM with allowlist
OUTBOUND_ALLOW="^.*\.github\.com$" ./scripts/run-vm-qemu.sh

# In the VM, test allowed domain
vm-ssh curl https://github.com  # Should work

# Test blocked domain
vm-ssh curl https://google.com  # Should fail (not in allowlist)

# View blocked connections
curl --unix-socket ./tmp/gvproxy-qemu-services.sock \
  http://localhost/services/filter/connections/blocked | jq
```

### Example 2: Dynamic Control

```bash
# Start VM without filtering
./scripts/run-vm-qemu.sh

# Initially, all connections should work
vm-ssh curl https://example.com  # Works

# Block example.com dynamically
curl --unix-socket ./tmp/gvproxy-qemu-services.sock -X POST \
  http://localhost/services/filter/blocklist \
  -d '{"protocol":"tcp","ip":"93.184.215.14","port":443}'

# Now it should be blocked
vm-ssh curl https://example.com  # Blocked

# View statistics
curl --unix-socket ./tmp/gvproxy-qemu-services.sock \
  http://localhost/services/filter/stats | jq
```

### Example 3: Real-Time Monitoring

```bash
# Terminal 1: Start event stream
curl --unix-socket ./tmp/gvproxy-qemu-services.sock \
  http://localhost/services/filter/events

# Terminal 2: Generate traffic
vm-ssh curl https://github.com
vm-ssh curl https://example.com

# Terminal 1 will show:
# event: connection_allowed
# data: {"protocol":"tcp","ip":"140.82.121.4","port":443,...}
#
# event: dns_allowed
# data: {"domain":"github.com","status":"allowed"}
```

## Troubleshooting

### QEMU VM won't start

```bash
# Check if KVM is available (Linux)
ls -la /dev/kvm

# Check QEMU installation
qemu-system-x86_64 --version
qemu-system-aarch64 --version

# View console log
tail -f ./tmp/qemu-console.log
```

### vfkit VM won't start

```bash
# Check vfkit version (needs >= 0.6)
vfkit -v

# Upgrade if needed
brew upgrade vfkit

# Check if port is in use
lsof -i :2223
```

### Can't SSH to VM

```bash
# Wait longer - first boot takes 1-2 minutes
# Check if VM is running
ps aux | grep qemu  # or vfkit

# Test SSH manually
ssh -vvv -i ./tmp/id_qemu_test -p 2222 test@127.0.0.1

# Check gvproxy logs
# (gvproxy output is visible in the script terminal)
```

### Filter API not working

```bash
# Check if services socket exists
ls -la ./tmp/gvproxy-*-services.sock

# Test API directly
curl --unix-socket ./tmp/gvproxy-qemu-services.sock \
  http://localhost/services/filter/stats

# If socket doesn't exist, restart with --services flag
# (scripts do this automatically)
```

### Image download fails

```bash
# Download manually
cd ./tmp/disks

# QEMU
curl -L -o fcos.qcow2.xz https://builds.coreos.fedoraproject.org/prod/streams/next/builds/.../x86_64/fedora-coreos-...-qemu.x86_64.qcow2.xz
unxz fcos.qcow2.xz

# vfkit
curl -L -o fcos.raw.gz https://builds.coreos.fedoraproject.org/prod/streams/next/builds/.../aarch64/fedora-coreos-...-applehv.aarch64.raw.gz
gunzip fcos.raw.gz
```

## Cleanup

To stop the VM and clean up:

```bash
# Press Ctrl+C in the terminal running the script
# This will automatically:
# - Kill the VM process
# - Kill gvproxy
# - Remove socket files

# To fully clean up (remove images and keys)
rm -rf ./tmp/
```

## Performance Notes

### QEMU
- **First boot:** 60-120 seconds (downloading image)
- **Subsequent boots:** 30-60 seconds
- **Acceleration:**
  - Linux: Uses KVM (fast)
  - macOS: Uses Hypervisor.framework/HVF (fast)

### vfkit
- **First boot:** 60-120 seconds (downloading image)
- **Subsequent boots:** 20-40 seconds (faster than QEMU)
- **Native Apple Hypervisor:** Best performance on macOS

## Advanced Usage

### Multiple VMs

You can run multiple VMs simultaneously by using different ports and directories:

```bash
# Terminal 1: VM on port 2222
TMP_DIR=./tmp/vm1 ./scripts/run-vm-qemu.sh

# Terminal 2: VM on port 2224 (edit script to change SSH_PORT)
TMP_DIR=./tmp/vm2 SSH_PORT=2224 QEMU_PORT=5556 ./scripts/run-vm-qemu.sh
```

### Custom Ignition Config

Edit the ignition file before starting:

```bash
# Generate base config
./scripts/run-vm-qemu.sh  # Ctrl+C after ignition creation

# Edit ignition
vim ./tmp/qemu.ign

# Start with custom config
./scripts/run-vm-qemu.sh
```

### Integration with Tests

These scripts use the same infrastructure as the test suite:

```bash
# Run actual tests
make test-qemu   # or make test-vfkit

# Or use scripts for manual testing
./scripts/run-vm-qemu.sh
```

## See Also

- [FILTER_API.md](FILTER_API.md) - Complete Filter API documentation
- [test-qemu/](test-qemu/) - QEMU test suite
- [test-vfkit/](test-vfkit/) - vfkit test suite
- [test-utils/](test-utils/) - Shared testing utilities
