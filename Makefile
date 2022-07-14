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
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/gvproxy-windows-amd64.exe ./cmd/gvproxy
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o bin/gvproxy-windows-arm64.exe ./cmd/gvproxy
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/gvproxy-darwin-amd64 ./cmd/gvproxy
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/gvproxy-darwin-arm64 ./cmd/gvproxy
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/gvproxy-linux-amd64 ./cmd/gvproxy
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/gvproxy-linux-arm64 ./cmd/gvproxy

.PHONY: test-companion
test-companion:
	GOOS=linux go build $(LDFLAGS) -o bin/test-companion ./cmd/test-companion

.PHONY: test
test: gvproxy test-companion
	go test -v ./test
