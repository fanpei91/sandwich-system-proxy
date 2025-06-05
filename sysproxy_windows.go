//go:build windows
// +build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func setSysProxy(listenAddr string) error {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}
	if strings.Trim(host, " ") == "" {
		host = "127.0.0.1"
	}

	command := fmt.Sprintf(`Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyServer -Value "http://%s:%s"`, host, port)
	cmd := exec.Command("powershell", command)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}

	command = `Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyEnable -Value 1`
	cmd = exec.Command("powershell", command)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}

	return nil
}

func unsetSysProxy() error {
	command := `Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name ProxyEnable -Value 0`
	cmd := exec.Command("powershell", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(string(out) + err.Error())
	}
	return nil
}
