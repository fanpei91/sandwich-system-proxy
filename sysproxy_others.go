//go:build !windows && !darwin
// +build !windows,!darwin

package main

func setSysProxy(_ string) error {
	return nil
}

func unsetSysProxy() error {
	return nil
}
