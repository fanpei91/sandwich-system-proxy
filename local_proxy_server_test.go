package main

import (
    "context"
    "log"
    "net"
    "net/http"
    "testing"

    "github.com/stretchr/testify/require"
)

func TestChinaIPFromDoH(t *testing.T) {
    chinaIPDB := newChinaIPRangeDB()
    client := &http.Client{
        Transport: &http.Transport{
            Proxy: nil,
        },
    }
    local := &localProxyServer{
        client: client,
        dns:    &dnsOverHTTPS{provider: defaultTestDoHProvider},
    }
    host := "www.baidu.com"
    err, answer, _ := local.dns.lookup(host)
    require.Nil(t, err)
    require.NotNil(t, answer)
    require.True(t, chinaIPDB.contains(answer))
}

func TestPullLatestIPRange(t *testing.T) {
    local := &localProxyServer{
        client: &http.Client{
            Transport: &http.Transport{
                Proxy: nil,
            },
        },
        chinaIPRangeDB: newChinaIPRangeDB(),
    }

    ctx, cancel := context.WithCancel(context.Background())

    defer cancel()

    log.Println(local.chinaIPRangeDB.Len())
    err := local.pullLatestIPRange(ctx)
    require.Nil(t, err)
    require.NotZero(t, local.chinaIPRangeDB.Len())
    log.Println(local.chinaIPRangeDB.Len())

    cn := "2001:da8:1001:7::88"
    require.True(t, local.chinaIPRangeDB.contains(net.ParseIP(cn)))

    usa := "172.217.11.68"
    require.False(t, local.chinaIPRangeDB.contains(net.ParseIP(usa)))

    cn = "106.85.37.170"
    require.True(t, local.chinaIPRangeDB.contains(net.ParseIP(cn)))
}
