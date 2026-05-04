current_dir = $(shell pwd)

.PHONY: goimports
goimports:
	find . -name '*.go' -exec goimports -w -local github.com/ryancurrah/gomodguard {} +

.PHONY: lint
lint:
	golangci-lint run ./...
	cd cmd/gomodguard && golangci-lint run ./...

.PHONY: build
build:
	cd cmd/gomodguard && go build -o "$$(go env GOPATH)/bin/gomodguard" main.go

.PHONY: run
run: build
	./gomodguard

.PHONY: test
test:
	go test -v -coverprofile coverage.out
	cd cmd/gomodguard && go test -v -coverprofile coverage.out ./...
	cat cmd/gomodguard/coverage.out | tail -n +2 >> coverage.out

.PHONY: cover
cover:
	gocover-cobertura < coverage.out > coverage.xml

.PHONY: dockerrun
dockerrun: dockerbuild
	docker run -v "${current_dir}/.gomodguard.yaml:/.gomodguard.yaml" ryancurrah/gomodguard:latest

.PHONY: snapshot
snapshot:
	cd cmd/gomodguard && goreleaser --clean --snapshot

.PHONY: release
release:
	cd cmd/gomodguard && goreleaser --clean

.PHONY: clean
clean:
	rm -rf dist/
	rm -f gomodguard coverage.xml coverage.out
	rm -f cmd/gomodguard/coverage.out

.PHONY: tag
tag:
	@current=$$(git tag --sort=-v:refname --list 'v*' | head -n1 || echo "none"); \
	read -p "Current version: $$current. Enter new version: " version; \
	git tag "$$version" && \
	git tag "cmd/gomodguard/$$version" && \
	git push origin "$$version" "cmd/gomodguard/$$version"

.PHONY: install-mac-tools
install-tools-mac:
	brew install goreleaser/tap/goreleaser

.PHONY: install-go-tools
install-go-tools:
	go install -v github.com/t-yuki/gocover-cobertura@latest
