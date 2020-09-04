module github.com/guillaumerose/gvisor-tap-vsock

go 1.13

require (
	github.com/dustin/go-humanize v1.0.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/google/gopacket v1.1.16
	github.com/google/tcpproxy v0.0.0-20200125044825-b6bb9b5b8252
	github.com/linuxkit/virtsock v0.0.0-20180830132707-8e79449dea07
	github.com/mdlayher/vsock v0.0.0-20200508120832-7ad3638b3fbc
	github.com/miekg/dns v1.1.30
	github.com/pkg/errors v0.9.1
	github.com/songgao/packets v0.0.0-20160404182456-549a10cd4091
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	golang.org/x/sys v0.0.0-20200831180312-196b9ba8737a // indirect
	gvisor.dev/gvisor v0.0.0-20200727050644-5e9c2950a570
)

replace github.com/miekg/dns => github.com/guillaumerose/dns-1 v1.1.5-0.20200731203003-fe9b991fbece
