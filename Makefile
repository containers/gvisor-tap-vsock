TAG ?= $(shell git describe --match=NeVeRmAtCh --always --abbrev=40 --dirty)
GIT_VERSION ?= $(shell git describe --always --dirty)
CONTAINER_RUNTIME ?= podman

.PHONY: build
build: gvproxy qemu-wrapper vm

TOOLS_DIR := tools
include tools/tools.mk

VERSION_LDFLAGS=-X github.com/containers/gvisor-tap-vsock/pkg/types.gitVersion=$(GIT_VERSION)
LDFLAGS = -s -w $(VERSION_LDFLAGS)

.PHONY: gvproxy
gvproxy:
	go build -ldflags "$(LDFLAGS)" -o bin/gvproxy ./cmd/gvproxy

.PHONY: qemu-wrapper
qemu-wrapper:
	go build -ldflags "$(LDFLAGS)" -o bin/qemu-wrapper ./cmd/qemu-wrapper

.PHONY: vm
vm:
	GOOS=linux CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/gvforwarder ./cmd/vm

# win-sshproxy is compiled as a windows GUI to support backgrounding
.PHONY: win-sshproxy
win-sshproxy:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS) -H=windowsgui" -o bin/win-sshproxy.exe ./cmd/win-sshproxy
	GOOS=windows GOARCH=arm64 go build -ldflags "$(LDFLAGS) -H=windowsgui" -o bin/win-sshproxy-arm64.exe ./cmd/win-sshproxy

# gvproxy for windows is compiled as a windows GUI to support backgrounding
.PHONY: win-gvproxy
win-gvproxy:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS) -H=windowsgui" -o bin/gvproxy.exe ./cmd/gvproxy
	GOOS=windows GOARCH=arm64 go build -ldflags "$(LDFLAGS) -H=windowsgui" -o bin/gvproxy-arm64.exe ./cmd/gvproxy

.PHONY: clean
clean:
	rm -rf ./bin

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor

.PHONY: lint
lint: $(TOOLS_BINDIR)/golangci-lint
	"$(TOOLS_BINDIR)"/golangci-lint run

.PHONY: image
image:
	${CONTAINER_RUNTIME} build -t quay.io/crcont/gvisor-tap-vsock:$(TAG) -f images/Dockerfile .

.PHONY: cross
cross: $(TOOLS_BINDIR)/makefat
	GOARCH=amd64 GOOS=freebsd  go build -ldflags "$(LDFLAGS)" -o bin/gvproxy-freebsd-amd64 ./cmd/gvproxy
	GOARCH=amd64 GOOS=windows go build -ldflags "$(LDFLAGS)" -o bin/gvproxy-windows.exe ./cmd/gvproxy
	GOARCH=arm64 GOOS=windows  go build -ldflags "$(LDFLAGS)" -o bin/gvproxy-windows-arm64.exe ./cmd/gvproxy
	GOARCH=amd64 GOOS=linux   go build -ldflags "$(LDFLAGS)" -o bin/gvproxy-linux-amd64 ./cmd/gvproxy
	GOARCH=arm64 GOOS=linux   go build -ldflags "$(LDFLAGS)" -o bin/gvproxy-linux-arm64 ./cmd/gvproxy
	GOARCH=amd64 GOOS=darwin  go build -ldflags "$(LDFLAGS)" -o bin/gvproxy-darwin-amd64 ./cmd/gvproxy
	GOARCH=arm64 GOOS=darwin  go build -ldflags "$(LDFLAGS)" -o bin/gvproxy-darwin-arm64 ./cmd/gvproxy
	cd bin && $(TOOLS_BINDIR)/makefat gvproxy-darwin gvproxy-darwin-amd64 gvproxy-darwin-arm64 && rm gvproxy-darwin-amd64 gvproxy-darwin-arm64

.PHONY: test-companion
test-companion:
	GOOS=linux go build -ldflags "$(LDFLAGS)" -o bin/test-companion ./cmd/test-companion

.PHONY: test
test: gvproxy test-companion
	go test -timeout 20m -v ./...
