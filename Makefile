.PHONY: all
all:

	go build -ldflags '-s -w -extldflags "-static"' -o bin/host ./host
	go build -ldflags '-s -w -extldflags "-static"' -o bin/vm ./vm

.PHONY: crc
crc: all
	scp bin/vm crc:
	scp setup.sh crc:

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor

.PHONY: docker
docker:
	docker build -t quay.io/gurose/gvisor-tap-vsock .

publish: docker
	docker push quay.io/gurose/gvisor-tap-vsock

selinux:
	scp myapp.te crc:
	ssh crc sudo checkmodule -M -m -o myapp.mod myapp.te
	ssh crc sudo semodule_package -o myapp.pp -m myapp.mod
	ssh crc sudo semodule -i myapp.pp
