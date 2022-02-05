# CHANGELOG

## Unreleased

## v1.0.0

**This is the first release of package vsock that only supports Go 1.12+.
Users on older versions of Go must use an unstable release.**

- Initial stable commit!
- [API change]: the `vsock.Dial` and `vsock.Listen` constructors now accept an
  optional `*vsock.Config` parameter to enable future expansion in v1.x.x
  without prompting further breaking API changes. Because `vsock.Config` has no
  options as of this release, `nil` may be passed in all call sites to fix
  existing code upon upgrading to v1.0.0.
- [New API]: the `vsock.ListenContextID` function can be used to create a
  `*vsock.Listener` which is bound to an explicit context ID address, rather
  than inferring one automatically as `vsock.Listen` does.
