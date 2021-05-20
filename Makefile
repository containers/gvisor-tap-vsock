TAG ?= $(shell git describe --match=NeVeRmAtCh --always --abbrev=40 --dirty)
CONTAINER_RUNTIME ?= podman

LDFLAGS = -ldflags '-s -w -extldflags "-static"'

.PHONY: build
build:
	go build $(LDFLAGS) -o bin/gvproxy ./cmd/gvproxy
	GOOS=linux CGO_ENABLED=0 go build $(LDFLAGS) -o bin/vm ./cmd/vm

.PHONY: clean
clean:
	rm -rf ./bin

.PHONY: crc
crc: build
	scp bin/vm crc:

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

.PHONY: test
test: build
	go test -v ./test
