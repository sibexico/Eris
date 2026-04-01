//go:build !linux && !windows

package main

func hardenProcess() error {
	return nil
}
