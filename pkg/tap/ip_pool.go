package tap

import (
	"errors"
	"net/netip"
	"sync"
)

type IPPool struct {
	base   netip.Prefix
	leases map[netip.Addr]string
	lock   sync.Mutex
}

func NewIPPool(subnet string) (*IPPool, error) {
	base, err := netip.ParsePrefix(subnet)
	if err != nil {
		return nil, err
	}
	return &IPPool{
		base:   base,
		leases: make(map[netip.Addr]string),
	}, nil
}

func (p *IPPool) Leases() map[string]string {
	p.lock.Lock()
	defer p.lock.Unlock()
	leases := map[string]string{}
	for ip, mac := range p.leases {
		leases[ip.String()] = mac
	}
	return leases
}

func (p *IPPool) Mask() int {
	return p.base.Bits()
}

func (p *IPPool) GetOrAssign(mac string) (netip.Addr, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	for ip, candidate := range p.leases {
		if candidate == mac {
			return ip, nil
		}
	}

	// Start from the first usable IP (network address + 1)
	candidate := p.base.Masked().Addr().Next()

	// For IPv4, the all-ones host address is the subnet broadcast address and
	// must not be handed out as a host IP. IPv6 has no broadcast concept, so
	// this only applies to v4 pools.
	broadcast := netip.Addr{}
	if p.base.Addr().Is4() {
		broadcast = lastAddr(p.base)
	}

	// Iterate through all IPs in the subnet
	for candidate.IsValid() && p.base.Contains(candidate) {
		if candidate == broadcast {
			break
		}
		if _, ok := p.leases[candidate]; !ok {
			p.leases[candidate] = mac
			return candidate, nil
		}
		candidate = candidate.Next()
	}

	return netip.Addr{}, errors.New("cannot find available IP")
}

// lastAddr returns the highest address in prefix (all host bits set). For an
// IPv4 prefix this is the subnet broadcast address.
func lastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	bytes := addr.AsSlice()
	bits := prefix.Bits()
	for i := bits; i < len(bytes)*8; i++ {
		bytes[i/8] |= 1 << (7 - uint(i%8))
	}
	last, _ := netip.AddrFromSlice(bytes)
	return last
}

func (p *IPPool) Reserve(ip string, mac string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	p.leases[addr] = mac
	return nil
}

func (p *IPPool) Release(given string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	for ip, mac := range p.leases {
		if mac == given {
			delete(p.leases, ip)
			break
		}
	}
}
