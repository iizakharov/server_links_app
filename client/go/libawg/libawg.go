// Package main is a C API over amneziawg-go, linked into the AMneZinu helper (c-archive / c-shared).
// A tunnel is identified by a handle; configuration is the standard UAPI text (keys in hex).
package main

// #include <stdint.h>
// #include <stdlib.h>
import "C"

import (
	"sync"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

type tunnel struct {
	dev  *device.Device
	tun  tun.Device
	name string
	net  netState
}

var (
	mu        sync.Mutex
	tunnels   = map[int32]*tunnel{}
	nextID    int32
	lastError string
)

func fail(err error) C.int32_t {
	mu.Lock()
	lastError = err.Error()
	mu.Unlock()
	return -1
}

// awgTurnOn creates a TUN interface (macOS: "utun" = next free utunN; Windows: a Wintun adapter
// with this name, wintun.dll next to the executable) with the given MTU,
// applies the UAPI settings and brings the device up. Returns a handle >= 0, or -1 (see awgLastError).
//
//export awgTurnOn
func awgTurnOn(ifname *C.char, mtu C.int32_t, settings *C.char) C.int32_t {
	t, err := tun.CreateTUN(C.GoString(ifname), int(mtu))
	if err != nil {
		return fail(err)
	}
	name, err := t.Name()
	if err != nil {
		t.Close()
		return fail(err)
	}
	logger := device.NewLogger(device.LogLevelError, "("+name+") ")
	dev := device.NewDevice(t, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(C.GoString(settings)); err != nil {
		dev.Close()
		return fail(err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fail(err)
	}
	mu.Lock()
	defer mu.Unlock()
	id := nextID
	nextID++
	tunnels[id] = &tunnel{dev: dev, tun: t, name: name}
	return C.int32_t(id)
}

func get(handle C.int32_t) *tunnel {
	mu.Lock()
	defer mu.Unlock()
	return tunnels[int32(handle)]
}

// awgIfName returns the interface name (e.g. "utun7"); the caller frees the string.
//
//export awgIfName
func awgIfName(handle C.int32_t) *C.char {
	t := get(handle)
	if t == nil {
		return nil
	}
	return C.CString(t.name)
}

// awgTurnOff closes the tunnel and destroys its interface.
//
//export awgTurnOff
func awgTurnOff(handle C.int32_t) {
	mu.Lock()
	t := tunnels[int32(handle)]
	delete(tunnels, int32(handle))
	mu.Unlock()
	if t != nil {
		netDown(t)
		t.dev.Close()
	}
}

// awgGetConfig returns the UAPI "get" output (peers, rx/tx bytes, last handshake); the caller frees it.
//
//export awgGetConfig
func awgGetConfig(handle C.int32_t) *C.char {
	t := get(handle)
	if t == nil {
		return nil
	}
	s, err := t.dev.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(s)
}

// awgValidate applies UAPI settings to a device on an in-memory TUN (no root needed) and returns
// NULL if amneziawg-go accepts them, otherwise the error text. Used by tests.
//
//export awgValidate
func awgValidate(settings *C.char) *C.char {
	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	err := dev.IpcSet(C.GoString(settings))
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

// awgLastError returns the error of the last failed call; the caller frees it.
//
//export awgLastError
func awgLastError() *C.char {
	mu.Lock()
	defer mu.Unlock()
	return C.CString(lastError)
}

//export awgFree
func awgFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

func main() {}
