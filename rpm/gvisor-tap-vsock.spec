%global with_debug 1

%if 0%{?with_debug}
%global _find_debuginfo_dwz_opts %{nil}
%global _dwz_low_mem_die_limit 0
%else
%global debug_package %{nil}
%endif

%global gomodulesmode GO111MODULE=on

%global _gvisor_installdir %{_libexecdir}/podman

%global desc_gvforwarder Forward traffic from a tap interface over vsock

Name: gvisor-tap-vsock
%if %{defined copr_username}
Epoch: 103
%else
Epoch: 6
%endif
# DO NOT TOUCH the Version string!
# The TRUE source of this specfile is:
# https://github.com/containers/podman/blob/main/rpm/podman.spec
# If that's what you're reading, Version must be 0, and will be updated by Packit for
# copr and koji builds.
# If you're reading this on dist-git, the version is automatically filled in by Packit.
Version: 0
License: Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT
%if %{defined autorelease}
Release: %autorelease
%else
Release: 1
%endif
%if %{defined golang_arches_future}
ExclusiveArch: %{golang_arches_future}
%else
ExclusiveArch: aarch64 ppc64le s390x x86_64
%endif
Summary: Go replacement for libslirp and VPNKit
URL: https://github.com/containers/%{name}
# All SourceN files fetched from upstream
Source0: %{url}/archive/refs/tags/v%{version}.tar.gz
BuildRequires: gcc
BuildRequires: glib2-devel
BuildRequires: glibc-devel
BuildRequires: glibc-static
BuildRequires: golang
BuildRequires: git-core
%if %{defined rhel} && 0%{?rhel} == 8
BuildRequires: go-srpm-macros
%else
BuildRequires: go-rpm-macros
%endif
BuildRequires: make
%if %{defined copr_username}
Obsoletes: podman-gvproxy < 102:4.7.0-1
%else
Obsoletes: podman-gvproxy < 5:4.7.0-1
%endif
Provides: podman-gvproxy = %{epoch}:%{version}-%{release}
Requires: %{name}-gvforwarder = %{epoch}:%{version}-%{release}

%description
A replacement for libslirp and VPNKit, written in pure Go.
It is based on the network stack of gVisor. Compared to libslirp,
gvisor-tap-vsock brings a configurable DNS server and
dynamic port forwarding.

%package gvforwarder
Summary: %{desc_gvforwarder}
Provides: gvforwarder = %{epoch}:%{version}-%{release}
Obsoletes: %{name} < 6:0.7.0-6
Recommends: %{name} = %{epoch}:%{version}-%{release}

%description gvforwarder
%{desc_gvforwarder}

%prep
%autosetup -Sgit -n %{name}-%{version}

%build
%set_build_flags
export CGO_CFLAGS=$CFLAGS

# These extra flags present in $CFLAGS have been skipped for now as they break the build
CGO_CFLAGS=$(echo $CGO_CFLAGS | sed 's/-flto=auto//g')
CGO_CFLAGS=$(echo $CGO_CFLAGS | sed 's/-Wp,D_GLIBCXX_ASSERTIONS//g')
CGO_CFLAGS=$(echo $CGO_CFLAGS | sed 's/-specs=\/usr\/lib\/rpm\/redhat\/redhat-annobin-cc1//g')

%ifarch x86_64
export CGO_CFLAGS+=" -m64 -mtune=generic -fcf-protection=full"
%endif

# reset LDFLAGS for plugins and gvisor binaries
LDFLAGS=''

# build gvisor-tap-vsock binaries
%gobuild -o bin/gvproxy ./cmd/gvproxy
%gobuild -o bin/gvforwarder ./cmd/vm

%install
# install gvproxy
install -dp %{buildroot}%{_gvisor_installdir}
install -p -m0755 bin/gvproxy %{buildroot}%{_gvisor_installdir}
install -p -m0755 bin/gvforwarder %{buildroot}%{_gvisor_installdir}

#define license tag if not already defined
%{!?_licensedir:%global license %doc}

%files
%license LICENSE
%doc README.md
%dir %{_gvisor_installdir}
%{_gvisor_installdir}/gvproxy

%files gvforwarder
%dir %{_gvisor_installdir}
%{_gvisor_installdir}/gvforwarder

%changelog
%if %{defined autochangelog}
%autochangelog
%else
* Mon Jul 24 2023 RH Container Bot <rhcontainerbot@fedoraproject.org>
- Placeholder changelog for envs that are not autochangelog-ready
%endif
