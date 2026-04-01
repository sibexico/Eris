//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentProcess    = kernel32.NewProc("GetCurrentProcess")
	procSetProcessWorkingSet = kernel32.NewProc("SetProcessWorkingSetSize")
)

func hardenProcess() error {
	// Expand working set so later page locks can succeed more consistently.
	h, _, _ := procGetCurrentProcess.Call()
	const minWS = uintptr(64 * 1024 * 1024)
	const maxWS = uintptr(256 * 1024 * 1024)
	r1, _, e1 := procSetProcessWorkingSet.Call(h, minWS, maxWS)
	if r1 == 0 {
		return fmt.Errorf("SetProcessWorkingSetSize failed: %v", e1)
	}
	return nil
}

func _virtualLock(ptr unsafe.Pointer, size uintptr) error {
	procVirtualLock := kernel32.NewProc("VirtualLock")
	r1, _, e1 := procVirtualLock.Call(uintptr(ptr), size)
	if r1 == 0 {
		return e1
	}
	return nil
}
