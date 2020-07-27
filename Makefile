all:
	go build -o bin/host ./host
	go build -o bin/vm ./vm


crc: all
	scp bin/vm crc:
	scp setup.sh crc:

vendor:
	go mod tidy
	go mod vendor