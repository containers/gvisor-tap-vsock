#!/usr/bin/env bash

# This script handles any custom processing of the spec file generated using the `post-upstream-clone`
# action and gets used by the fix-spec-file action in .packit.yaml.

set -eo pipefail

REPO="gvisor-tap-vsock"
SPEC=$REPO.spec

# Get Version from HEAD
# FIXME: Don't know where to fetch this from yet
VERSION=0.0

# Generate source tarball from HEAD
git archive --prefix=$REPO-$VERSION/ -o $REPO-$VERSION.tar.gz HEAD

# RPM Spec modifications

# Use the Version from version/version.go in rpm spec
sed -i "s/^Version:.*/Version: $VERSION/" $SPEC

# Use Packit's supplied variable in the Release field in rpm spec.
# podman.spec is generated using `rpkg spec --outdir ./` as mentioned in the
# `post-upstream-clone` action in .packit.yaml.
sed -i "s/^Release:.*/Release: $PACKIT_RPMSPEC_RELEASE%{?dist}/" $SPEC

# Use above generated tarball as Source in rpm spec
sed -i "s/^Source:.*.tar.gz/Source: $REPO-$VERSION.tar.gz/" $SPEC

# Use the right build dir for autosetup stage in rpm spec
sed -i "s/^%setup.*/%autosetup -Sgit -n %{name}-$VERSION/" $SPEC
