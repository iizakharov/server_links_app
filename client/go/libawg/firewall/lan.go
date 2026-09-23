/* SPDX-License-Identifier: MIT
 *
 * AMneZinu addition to the WireGuard firewall: with the kill switch on, still allow the local network
 * (printers, router page, NAS, discovery), in and out. Same networks as the macOS pf rules.
 */

package firewall

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// IPv4 values are in host byte order.
var (
	lanV4 = []wtFwpV4AddrAndMask{
		{0x0a000000, 0xff000000}, // 10.0.0.0/8
		{0xac100000, 0xfff00000}, // 172.16.0.0/12
		{0xc0a80000, 0xffff0000}, // 192.168.0.0/16
		{0xa9fe0000, 0xffff0000}, // 169.254.0.0/16
		{0xe0000000, 0xf0000000}, // 224.0.0.0/4 multicast
		{0xffffffff, 0xffffffff}, // broadcast
	}
	lanV6 = []wtFwpV6AddrAndMask{
		{[16]uint8{0xfe, 0x80}, 10}, // link-local
		{[16]uint8{0xff}, 8},        // multicast
	}
)

func permitLAN(session uintptr, baseObjects *baseObjects, weight uint8) error {
	// conditions on the same field are OR-ed
	v4 := make([]wtFwpmFilterCondition0, len(lanV4))
	for i := range lanV4 {
		v4[i].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		v4[i].matchType = cFWP_MATCH_EQUAL
		v4[i].conditionValue._type = cFWP_V4_ADDR_MASK
		v4[i].conditionValue.value = uintptr(unsafe.Pointer(&lanV4[i]))
	}
	v6 := make([]wtFwpmFilterCondition0, len(lanV6))
	for i := range lanV6 {
		v6[i].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		v6[i].matchType = cFWP_MATCH_EQUAL
		v6[i].conditionValue._type = cFWP_V6_ADDR_MASK
		v6[i].conditionValue.value = uintptr(unsafe.Pointer(&lanV6[i]))
	}
	for _, r := range []struct {
		name       string
		layer      windows.GUID
		conditions []wtFwpmFilterCondition0
	}{
		{"Permit outbound LAN (IPv4)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4, v4},
		{"Permit inbound LAN (IPv4)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, v4},
		{"Permit outbound LAN (IPv6)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6, v6},
		{"Permit inbound LAN (IPv6)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, v6},
	} {
		displayData, err := createWtFwpmDisplayData0(r.name, "")
		if err != nil {
			return wrapErr(err)
		}
		layer := r.layer
		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            layer,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(r.conditions)),
			filterCondition:     &r.conditions[0],
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}
		filterID := uint64(0)
		if err := fwpmFilterAdd0(session, &filter, 0, &filterID); err != nil {
			return wrapErr(err)
		}
	}
	return nil
}
