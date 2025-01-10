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
