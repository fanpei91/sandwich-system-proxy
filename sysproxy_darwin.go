// +build darwin

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

	networkservice := getNetworkInterface()

	cmd := exec.Command("sh", "-c", fmt.Sprintf("networksetup -setsecurewebproxy %s %s %s", networkservice, host, port))
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}

	cmd = exec.Command("sh", "-c", fmt.Sprintf("networksetup -setwebproxy %s %s %s", networkservice, host, port))
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}

	return nil
}

func unsetSysProxy() error {
	networkservice := getNetworkInterface()
	cmd := exec.Command("sh", "-c", fmt.Sprintf("networksetup -setsecurewebproxystate %s %s", networkservice, "off"))
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}

	cmd = exec.Command("sh", "-c", fmt.Sprintf("networksetup -setwebproxystate %s %s", networkservice, "off"))
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(string(out) + err.Error())
	}

	return nil
}

func getNetworkInterface() string {
	c := exec.Command("sh", "-c", "networksetup -listnetworkserviceorder | grep -B 1 $(route -n get default | grep interface | awk '{print $2}') | head -n 1 | sed 's/.*) //'")
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out)
	}
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, "usage") {
		return "Wi-Fi"
	}
	return output
}
