.PHONY: all
all:
	go build -o bin/host ./cmd/host
	go build -o bin/vm ./cmd/vm

.PHONY: crc
crc: all
	scp bin/vm crc:
	scp setup.sh crc:

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor