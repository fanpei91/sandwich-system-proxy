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
}

func TestUnsetSysProxy(t *testing.T) {
	setSysProxy(":9191")
	err := unsetSysProxy()
	require.Nil(t, err)
}

func TestGetNetworkInterface(t *testing.T) {
	i := getNetworkInterface()
	log.Println(i)
}
