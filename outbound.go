package main

import (
	"errors"
	"net"
)

type Dialer func(network, address string) (net.Conn, error)

var outboundDial = map[OutboundProtocol]Dialer{
	Direct: net.Dial,
	Block:  dialBlock,
}

var errBlocked = errors.New("blocked")

func dialBlock(network, address string) (net.Conn, error) {
	return nil, errBlocked
}
