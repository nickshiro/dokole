package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"

	"kalinka/inbound"
	"kalinka/outbound"
)

type Config struct {
	Inbounds  []inbound.Inbound   `json:"inbounds"`
	Outbounds []outbound.Outbound `json:"outbounds"`
}

var config Config

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("no config provided")
	}
	configPath := os.Args[1]
	configContents, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}
	if err := json.Unmarshal(configContents, &config); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}

	// TODO(arkriny): maybe there should be some defaults so empty config works
	if len(config.Inbounds) == 0 {
		log.Fatalf("no inbound specified")
	}
	if len(config.Outbounds) == 0 {
		log.Fatalf("no outbound specified")
	}

	for i := range config.Outbounds {
		ob := &config.Outbounds[i]
		if err := ob.ResolveDialer(); err != nil {
			log.Fatalf("outbound %d (%s): %v", i, ob.Protocol, err)
		}
	}

	for _, ib := range config.Inbounds {
		if err := ib.Run(route); err != nil {
			log.Fatalf("inbound %s: %v", ib.Protocol, err)
		}
		log.Printf("started inbound %s on address %s", ib.Protocol, ib.Address)
	}
	select {}
}

func route(ctx context.Context, network, addr string) (net.Conn, error) {
	log.Printf("routing %s %s", network, addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		log.Printf("failed to split host and port in %q: %v", addr, err)
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		log.Print(err)
		return nil, err
	}

	var ob outbound.Outbound
outer:
	for i := range config.Outbounds {
		ob = config.Outbounds[i]
		if len(ob.IP) == 0 {
			break
		}
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip)
			if !ok {
				log.Panicf("resolver returned invalid IP address %v", ip)
			}
			a = a.Unmap()
			for _, prefix := range ob.IP {
				if prefix.Contains(a) {
					addr = net.JoinHostPort(ip.String(), port)
					break outer
				}
			}
		}
	}
	log.Printf("dialing %s %s via outbound %s", network, addr, ob.Protocol)
	c, err := ob.Dialer(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("outbound %s: %w", ob.Protocol, err)
	}
	return c, nil
}
