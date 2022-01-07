TAG ?= $(shell git describe --match=NeVeRmAtCh --always --abbrev=40 --dirty)
CONTAINER_RUNTIME ?= podman

LDFLAGS = -ldflags '-s -w'

.PHONY: build
build: gvproxy qemu-wrapper vm

.PHONY: gvproxy
gvproxy:
	go build $(LDFLAGS) -o bin/gvproxy ./cmd/gvproxy

.PHONY: qemu-wrapper
qemu-wrapper:
	go build $(LDFLAGS) -o bin/qemu-wrapper ./cmd/qemu-wrapper

.PHONY: vm
vm:
	GOOS=linux CGO_ENABLED=0 go build $(LDFLAGS) -o bin/vm ./cmd/vm

# win-sshproxy is compiled as a windows GUI to support backgrounding
.PHONY: win-sshproxy
win-sshproxy:
	GOOS=windows go build -ldflags -H=windowsgui -o bin/win-sshproxy.exe ./cmd/win-sshproxy

.PHONY: clean
clean:
	rm -rf ./bin

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor

.PHONY: lint
lint:
	golangci-lint run

.PHONY: image
image:
	${CONTAINER_RUNTIME} build -t quay.io/crcont/gvisor-tap-vsock:$(TAG) -f images/Dockerfile .

.PHONY: cross
cross:
	GOOS=windows go build $(LDFLAGS) -o bin/gvproxy-windows.exe ./cmd/gvproxy
	GOOS=darwin  go build $(LDFLAGS) -o bin/gvproxy-darwin ./cmd/gvproxy
	GOOS=linux   go build $(LDFLAGS) -o bin/gvproxy-linux ./cmd/gvproxy

.PHONY: test-companion
test-companion:
	GOOS=linux go build $(LDFLAGS) -o bin/test-companion ./cmd/test-companion

.PHONY: test
test: gvproxy test-companion
	go test -v ./test
