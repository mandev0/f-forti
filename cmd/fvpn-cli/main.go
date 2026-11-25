// fvpn-cli brings up a FortiGate SSL-VPN tunnel into an in-process TCP/IP
// stack (gVisor netstack). It changes nothing on the host: no adapter, no
// routes, no DNS, no admin rights. Use it to verify the tunnel/PPP layer:
// resolve names and open TCP connections through the VPN, or run a loopback
// SOCKS5 proxy for manual tests (curl --socks5-hostname ...).
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"f-forti/internal/cliauth"
	"f-forti/internal/forti"
	"f-forti/internal/ppp"
	"f-forti/internal/socks5"
	"f-forti/internal/tunnel"
	"f-forti/internal/vpn"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

func main() {
	var resolves, tcps, pings list
	server := flag.String("server", "", "VPN server host[:port] (required)")
	realm := flag.String("realm", "", "SSL-VPN realm")
	user := flag.String("user", "", "username")
	pin := flag.String("trusted-cert", "", "server certificate SHA-256 fingerprint")
	debug := flag.Bool("debug", false, "HTTP and PPP details")
	socks := flag.String("socks", "", "after the tests, serve SOCKS5 on this loopback address (e.g. 127.0.0.1:1080)")
	echo := flag.Duration("echo", 30*time.Second, "LCP echo interval when idle (0 = off)")
	flag.Var(&resolves, "resolve", "name to resolve via tunnel DNS (repeatable)")
	flag.Var(&tcps, "tcp", "TCP connect test through the tunnel host:port (repeatable)")
	flag.Var(&pings, "ping", "IP to ping through the tunnel (repeatable)")
	flag.Parse()
	if *server == "" {
		fmt.Fprintln(os.Stderr, "usage: fvpn-cli -server host:port -trusted-cert SHA256 [-resolve name] [-tcp host:port] [-ping ip] [-socks 127.0.0.1:1080]")
		os.Exit(2)
	}
	log.SetFlags(log.Ltime)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cfg := forti.Config{Server: *server, Realm: *realm, TrustedCert: *pin}
	if *debug {
		cfg.Debug = os.Stderr
	}
	c, err := forti.New(cfg)
	check(err)

	in := bufio.NewReader(os.Stdin)
	if _, err := cliauth.Login(ctx, c, in, *user); err != nil {
		var ce *forti.CertError
		if errors.As(err, &ce) {
			log.Fatalf("%v\nIf you recognise the certificate: -trusted-cert %s", ce, ce.Fingerprint)
		}
		log.Fatalf("login: %v", err)
	}
	log.Println("logged in")
	defer func() {
		lctx, lc := context.WithTimeout(context.Background(), 10*time.Second)
		defer lc()
		if err := c.Logout(lctx); err != nil {
			log.Printf("logout: %v", err)
		} else {
			log.Println("logged out")
		}
	}()

	_, tc, err := c.TunnelConfig(ctx)
	if err != nil {
		log.Printf("WARNING: could not fetch tunnel configuration: %v", err)
		return
	}
	routes, _ := tc.CompactRoutes()
	log.Printf("XML: assigned IP %s, DNS %v, %d routes, %d split-DNS groups",
		tc.IPv4.Assigned.IP, tc.DNSServers(), len(routes), len(tc.IPv4.SplitDNS))

	// Tunnel + PPP
	conn, err := c.DialTunnel(ctx)
	if err != nil {
		log.Printf("cannot open tunnel: %v", err)
		return
	}
	pcfg := ppp.Config{EchoInterval: *echo}
	if *debug {
		pcfg.Logf = log.Printf
	}
	sctx, scancel := context.WithTimeout(ctx, 30*time.Second)
	link, err := ppp.Start(sctx, tunnel.New(conn), pcfg)
	scancel()
	if err != nil {
		log.Printf("PPP negotiation failed: %v", err)
		return
	}
	defer link.Close()
	info := link.Info()
	log.Printf("tunnel up: IP %s, peer %s, DNS %v, MTU %d", info.LocalIP, info.PeerIP, info.DNS, info.PeerMRU)
	if x := tc.IPv4.Assigned.IP; x != "" && x != info.LocalIP.String() {
		log.Printf("WARNING: IPCP address (%s) differs from XML (%s)", info.LocalIP, x)
	}

	dns := info.DNS
	for _, s := range tc.DNSServers() {
		if a, err := netip.ParseAddr(s); err == nil && !containsAddr(dns, a) {
			dns = append(dns, a)
		}
	}
	mtu := info.PeerMRU
	if mtu > 1500 || mtu < 576 {
		mtu = 1400
	}
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{info.LocalIP}, dns, mtu)
	if err != nil {
		log.Printf("netstack: %v", err)
		return
	}
	defer dev.Close()

	bctx, bcancel := context.WithCancel(ctx)
	defer bcancel()
	bridgeErr := make(chan error, 1)
	go func() { bridgeErr <- vpn.Bridge(bctx, dev, link) }()

	failed := 0
	for _, name := range resolves {
		rctx, rc := context.WithTimeout(ctx, 10*time.Second)
		t0 := time.Now()
		addrs, err := tnet.LookupContextHost(rctx, name)
		rc()
		if err != nil {
			failed++
			log.Printf("resolve %s: ERROR %v", name, err)
		} else {
			log.Printf("resolve %s: %v (%s)", name, addrs, time.Since(t0).Round(time.Millisecond))
		}
	}
	for _, target := range tcps {
		dctx, dc := context.WithTimeout(ctx, 10*time.Second)
		t0 := time.Now()
		cn, err := tnet.DialContext(dctx, "tcp", target)
		dc()
		if err != nil {
			failed++
			log.Printf("tcp %s: ERROR %v", target, err)
			continue
		}
		log.Printf("tcp %s: connected (%s)", target, time.Since(t0).Round(time.Millisecond))
		cn.Close()
	}
	for _, ip := range pings {
		rtt, err := ping(tnet, ip)
		if err != nil {
			failed++
			log.Printf("ping %s: ERROR %v", ip, err)
		} else {
			log.Printf("ping %s: %s", ip, rtt.Round(time.Millisecond))
		}
	}

	if *socks != "" {
		log.Printf("SOCKS5 listening on %s. Example: curl --socks5-hostname %s https://internal-host/  (Ctrl+C to exit)", *socks, *socks)
		go func() {
			if err := socks5.Serve(bctx, *socks, tnet.DialContext, log.Printf); err != nil {
				log.Printf("socks: %v", err)
				bcancel()
			}
		}()
		statsTick := time.NewTicker(60 * time.Second)
		defer statsTick.Stop()
	wait:
		for {
			select {
			case <-ctx.Done():
				break wait
			case <-link.Done():
				log.Printf("tunnel down: %v", link.Err())
				break wait
			case err := <-bridgeErr:
				log.Printf("bridge stopped: %v", err)
				break wait
			case <-statsTick.C:
				s := link.Stats()
				log.Printf("traffic: rx %d packets/%d B, tx %d packets/%d B, dropped %d", s.RxPackets, s.RxBytes, s.TxPackets, s.TxBytes, s.Dropped)
			}
		}
	}

	s := link.Stats()
	log.Printf("summary: rx %d packets/%d B, tx %d packets/%d B, dropped %d, failed tests %d", s.RxPackets, s.RxBytes, s.TxPackets, s.TxBytes, s.Dropped, failed)
}

func ping(tnet *netstack.Net, ip string) (time.Duration, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return 0, err
	}
	pc, err := tnet.DialPingAddr(netip.Addr{}, addr)
	if err != nil {
		return 0, err
	}
	defer pc.Close()
	msg := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1, 'f', 'v', 'p', 'n'}
	binary.BigEndian.PutUint16(msg[2:], icmpChecksum(msg))
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	t0 := time.Now()
	if _, err := pc.Write(msg); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := pc.Read(buf)
		if err != nil {
			return 0, err
		}
		if n >= 8 && buf[0] == 0 { // echo reply
			return time.Since(t0), nil
		}
	}
}

func icmpChecksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func containsAddr(l []netip.Addr, a netip.Addr) bool {
	for _, x := range l {
		if x == a {
			return true
		}
	}
	return false
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
