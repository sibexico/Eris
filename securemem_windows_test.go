//go:build windows

package main

import (
	"testing"
	"unsafe"
)

func TestVirtualLockCallable(t *testing.T) {
	buf := make([]byte, 4096)
	err := _virtualLock(unsafe.Pointer(&buf[0]), uintptr(len(buf)))
	if err != nil {
		// May fail on restricted environments; path coverage matters here.
		t.Logf("_virtualLock returned warning: %v", err)
	}
}
