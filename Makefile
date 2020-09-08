.PHONY: all
all:
	go build -ldflags '-s -w -extldflags "-static"' -o bin/host ./cmd/host
	go build -o bin/vm ./cmd/vm

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
