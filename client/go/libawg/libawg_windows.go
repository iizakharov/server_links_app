//go:build windows

package main

// #include <stdint.h>
import "C"

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/iizakharov/amnezinu-vpn/libawg/firewall"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// netPlan is what the Rust side decided for the tunnel interface (see amz-tunnel/src/windows.rs).
type netPlan struct {
	Addresses  []string `json:"addresses"`
	Routes     []string `json:"routes"`
	DNS        []string `json:"dns"`
	MTU        int      `json:"mtu"`
	KillSwitch bool     `json:"kill_switch"`
	AllowLAN   bool     `json:"allow_lan"`
}

type netState struct {
	firewall bool
}

func prefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err2 := netip.ParseAddr(s)
			if err2 != nil {
				return nil, err
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p)
	}
	return out, nil
}

// setInterface: tunnel metric 0 (its routes and DNS win), MTU, no router discovery / DAD delays.
func setInterface(luid winipcfg.LUID, family winipcfg.AddressFamily, mtu int) error {
	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	ipif.UseAutomaticMetric = false
	ipif.Metric = 0
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	if family == windows.AF_INET6 && mtu < 1280 {
		mtu = 1280
	}
	ipif.NLMTU = uint32(mtu)
	return ipif.Set()
}

func applyPlan(t *tunnel, p *netPlan) error {
	native, ok := t.tun.(*tun.NativeTun)
	if !ok {
		return fmt.Errorf("not a Wintun interface")
	}
	luid := winipcfg.LUID(native.LUID())

	addrs, err := prefixes(p.Addresses)
	if err != nil {
		return fmt.Errorf("address: %w", err)
	}
	routes, err := prefixes(p.Routes)
	if err != nil {
		return fmt.Errorf("route: %w", err)
	}
	dns, err := prefixes(p.DNS)
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}

	if err := setInterface(luid, windows.AF_INET, p.MTU); err != nil {
		return fmt.Errorf("IPv4 interface: %w", err)
	}
	// IPv6 may be switched off on the machine: then there is nothing to leak through either
	_ = setInterface(luid, windows.AF_INET6, p.MTU)

	if err := luid.SetIPAddresses(addrs); err != nil {
		return fmt.Errorf("addresses: %w", err)
	}
	var rd []*winipcfg.RouteData
	for _, r := range routes {
		hop := netip.IPv4Unspecified()
		if r.Addr().Is6() {
			hop = netip.IPv6Unspecified()
		}
		rd = append(rd, &winipcfg.RouteData{Destination: r.Masked(), NextHop: hop, Metric: 0})
	}
	if err := luid.SetRoutes(rd); err != nil {
		return fmt.Errorf("routes: %w", err)
	}
	var dns4, dns6, all []netip.Addr
	for _, d := range dns {
		all = append(all, d.Addr())
		if d.Addr().Is4() {
			dns4 = append(dns4, d.Addr())
		} else {
			dns6 = append(dns6, d.Addr())
		}
	}
	if err := luid.SetDNS(windows.AF_INET, dns4, nil); err != nil {
		return fmt.Errorf("DNS: %w", err)
	}
	_ = luid.SetDNS(windows.AF_INET6, dns6, nil)

	// kill switch: WFP filters in a dynamic session, so they go away with this process.
	// A block left by awgBlock (after a crash) is replaced by the tunnel's rules.
	if p.KillSwitch && !t.net.firewall {
		firewall.DisableFirewall()
		if err := firewall.EnableFirewall(uint64(luid), false, p.AllowLAN, all); err != nil {
			return fmt.Errorf("kill switch: %w", err)
		}
		t.net.firewall = true
	} else if !p.KillSwitch && t.net.firewall {
		firewall.DisableFirewall()
		t.net.firewall = false
	}
	return nil
}

// awgNetSet applies addresses, routes, DNS, MTU and the kill switch to the tunnel interface.
// plan is JSON (netPlan); may be called again to replace routes. Returns 0, or -1 (see awgLastError).
//
//export awgNetSet
func awgNetSet(handle C.int32_t, plan *C.char) C.int32_t {
	t := get(handle)
	if t == nil {
		return fail(fmt.Errorf("no tunnel %d", handle))
	}
	var p netPlan
	if err := json.Unmarshal([]byte(C.GoString(plan)), &p); err != nil {
		return fail(err)
	}
	if err := applyPlan(t, &p); err != nil {
		return fail(err)
	}
	return 0
}

func netDown(t *tunnel) {
	if t.net.firewall {
		firewall.DisableFirewall()
		t.net.firewall = false
	}
}

// awgBlock blocks all traffic except this process, loopback, DHCP and (optionally) the local network, with
// no tunnel: the kill switch after the service was restarted following a crash. Returns 0 or -1.
//
//export awgBlock
func awgBlock(allowLAN C.int32_t) C.int32_t {
	firewall.DisableFirewall()
	if err := firewall.EnableFirewall(0, false, allowLAN != 0, nil); err != nil {
		return fail(err)
	}
	return 0
}

// awgUnblock lifts the block of awgBlock (a no-op if there is none).
//
//export awgUnblock
func awgUnblock() {
	firewall.DisableFirewall()
}
