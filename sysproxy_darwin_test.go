// +build darwin

package main

import (
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetSysProxy(t *testing.T) {
	err := setSysProxy(":9090", "default")
	require.Nil(t, err)

	err = setSysProxy(":9090", "all")
	require.Nil(t, err)
}

func TestUnsetSysProxy(t *testing.T) {
	setSysProxy(":9191", "default")
	err := unsetSysProxy("default")
	require.Nil(t, err)

	setSysProxy(":9191", "all")
	err = unsetSysProxy("all")
	require.Nil(t, err)
}

func TestGetNetworkInterface(t *testing.T) {
	i := getNetworkInterfaces("default")
	log.Println(i)

	i = getNetworkInterfaces("all")
	log.Println(i)
}
