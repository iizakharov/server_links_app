//go:build !windows

package main

// Outside Windows the OS side (addresses, routes, DNS, firewall) is done by the Rust helper.
type netState struct{}

func netDown(*tunnel) {}
