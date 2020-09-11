TAG ?= $(shell git describe --match=NeVeRmAtCh --always --abbrev=40 --dirty)

.PHONY: all
all:
	go build -ldflags '-s -w -extldflags "-static"' -o bin/host ./cmd/host
	CGO_ENABLED=0 go build -ldflags '-s -w -extldflags "-static"' -o bin/vm ./cmd/vm

.PHONY: crc
crc: all
	scp bin/vm crc:
	scp setup.sh crc:

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor

.PHONY: lint
lint:
	golangci-lint run

.PHONY: image
image:
	docker build -t quay.io/gurose/gvisor-tap-vsock:$(TAG) .
