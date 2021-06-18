// +build !darwin

package main

func setSysProxy(_, _ string) error {
	return nil
}

func unsetSysProxy(_ string) error {
	return nil
}
