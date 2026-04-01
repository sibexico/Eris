//go:build linux

package main

import "golang.org/x/sys/unix"

func hardenProcess() error {
	// Disable coredumps and ptrace attachment for unprivileged processes.
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
