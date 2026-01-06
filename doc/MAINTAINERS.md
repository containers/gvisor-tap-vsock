## Releasing gvisor-tap-vsock

Here are the steps to follow to make a gvisor-tap-vsock release.
Releases are automated through this GitHub Actions workflow:
https://github.com/containers/gvisor-tap-vsock/blob/main/.github/workflows/release.yml

- fetch the latest upstream code, and optionally check it out locally: `git remote update`
- create a v0.1.0 tag for a 0.1.0 release: `git tag -s v0.1.0 origin/main`
- push the tag: `git push origin v0.1.0`
- wait until the "Release build" GitHub Actions workflow completes
- go to https://github.com/containers/gvisor-tap-vsock/releases. There should now be a v0.1.0 release with a Draft tag
- edit the release notes. I put new features first, then bug fixes, and I add a "## Dependencies Updates" section listing dependabot updates
- check "Make this release the latest" and click on "Publish"
- release is done !

There are a few more post release steps which can be done by other people.
packit will automatically create fedora PRs to update gvisor-tap-vsock in the
misc fedora releases. These pull requests need to be approved. After the PRs
are approved, packit will create the corresponding updates in bodhi:
https://bodhi.fedoraproject.org/updates/?packages=gvisor-tap-vsock

## Updating the gvisor.dev/gvisor go module

The upstream repository is hosted at https://github.com/google/gvisor
However neither the `main` branch nor the `release-xxxx` tags can be directly used with gvisor-tap-vsock as they expect to be built with the bazel build system.
If you try to use them, you will get compilation errors because some generated files are missing:
```
$ go get gvisor.dev/gvisor@release-20251215.0
$ go mod tidy
$ go mod vendor
$ make
go build -ldflags "-s -w -X github.com/containers/gvisor-tap-vsock/pkg/types.gitVersion=v0.8.7-78-g742b82bb-dirty" -o bin/gvproxy ./cmd/gvproxy
# gvisor.dev/gvisor/pkg/bits
vendor/gvisor.dev/gvisor/pkg/bits/uint64_arch.go:35:9: undefined: MaskOf64
# gvisor.dev/gvisor/pkg/waiter
vendor/gvisor.dev/gvisor/pkg/waiter/waiter.go:140:2: undefined: waiterEntry
vendor/gvisor.dev/gvisor/pkg/waiter/waiter.go:211:7: undefined: waiterList
make: *** [Makefile:16: gvproxy] Error 1
```

There’s a [`go`](https://github.com/google/gvisor/tree/go) branch with the required generated files, see [this link](https://github.com/google/gvisor?tab=readme-ov-file#using-go-get) for more details.
You want a commit of the form: `2214e5a4d Merge release-20251215.0-20-g28c24757e (automated)`:

```
$ go get gvisor.dev/gvisor@2214e5a4d
$ go mod tidy
$ go mod vendor
$ make
go build -ldflags "-s -w -X github.com/containers/gvisor-tap-vsock/pkg/types.gitVersion=v0.8.7-79-gb594f2e7" -o bin/gvproxy ./cmd/gvproxy
go build -ldflags "-s -w -X github.com/containers/gvisor-tap-vsock/pkg/types.gitVersion=v0.8.7-79-gb594f2e7" -o bin/qemu-wrapper ./cmd/qemu-wrapper
GOOS=linux CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/containers/gvisor-tap-vsock/pkg/types.gitVersion=v0.8.7-79-gb594f2e7" -o bin/gvforwarder ./cmd/vm
$
```
