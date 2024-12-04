//go:build darwin
// +build darwin

package main

import (
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetSysProxy(t *testing.T) {
	err := setSysProxy(":9090")
	require.Nil(t, err)

	err = setSysProxy(":9090")
	require.Nil(t, err)
}

func TestUnsetSysProxy(t *testing.T) {
	setSysProxy(":9191")
	err := unsetSysProxy()
	require.Nil(t, err)

	setSysProxy(":9191")
	err = unsetSysProxy()
	require.Nil(t, err)
}

func TestGetNetworkInterface(t *testing.T) {
	i := getNetworkInterfaces()
	log.Println(i)
}
