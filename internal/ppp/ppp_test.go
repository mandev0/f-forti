package ppp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"f-forti/internal/tunnel"
)

func opt(t byte, d ...byte) option { return option{t, d} }

// fakeGate plays a FortiGate-like PPP peer on the far end of a pipe.
type fakeGate struct {
	t         *testing.T
	fc        *tunnel.Conn
	sawLCPRej bool
	sawProtoR bool
	ipcpNaked bool
	clientMag []byte
	echoReply chan []byte
	ipv4      chan []byte
	termAck   chan struct{}
}

func (g *fakeGate) send(proto uint16, p packet) {
	if err := g.fc.WriteFrame(proto, p.encode()); err != nil {
		g.t.Logf("gate write: %v", err)
	}
}

func (g *fakeGate) run() {
	// FortiGate opens with an LCP request including PFC/ACFC.
	g.send(ProtoLCP, packet{codeConfReq, 1, encodeOptions([]option{
		opt(lcpMRU, 0x05, 0x4a), opt(lcpMagic, 1, 2, 3, 4), opt(7), opt(8),
	})})
	for {
		proto, data, err := g.fc.ReadFrame()
		if err != nil {
			return
		}
		if proto == ProtoIPv4 {
			g.ipv4 <- data
			continue
		}
		p, err := parsePacket(data)
		if err != nil {
			g.t.Errorf("gate parse: %v", err)
			return
		}
		switch proto {
		case ProtoLCP:
			switch p.code {
			case codeConfRej:
				opts, _ := parseOptions(p.data)
				if len(opts) != 2 || opts[0].typ != 7 || opts[1].typ != 8 {
					g.t.Errorf("PFC/ACFC reddi bekleniyordu: %+v", opts)
				}
				g.sawLCPRej = true
				g.send(ProtoLCP, packet{codeConfReq, 2, encodeOptions([]option{
					opt(lcpMRU, 0x05, 0x4a), opt(lcpMagic, 1, 2, 3, 4),
				})})
			case codeConfAck:
				// our request (id 2) accepted; push an IPv6CP request
				g.send(0x8057, packet{codeConfReq, 1, encodeOptions([]option{opt(1, 0, 0, 0, 0, 0, 0, 0, 1)})})
			case codeConfReq:
				opts, _ := parseOptions(p.data)
				for _, o := range opts {
					if o.typ == lcpMagic {
						g.clientMag = o.data
					}
				}
				g.send(ProtoLCP, packet{codeConfAck, p.id, p.data})
				g.send(ProtoIPCP, packet{codeConfReq, 1, encodeOptions([]option{opt(ipcpAddr, 192, 0, 2, 1)})})
			case codeProtoRej:
				if binary.BigEndian.Uint16(p.data) == 0x8057 {
					g.sawProtoR = true
				}
			case codeEchoReply:
				g.echoReply <- p.data
			case codeTermAck:
				close(g.termAck)
			}
		case ProtoIPCP:
			switch p.code {
			case codeConfReq:
				opts, _ := parseOptions(p.data)
				if !g.ipcpNaked {
					g.ipcpNaked = true
					if len(opts) != 3 {
						g.t.Errorf("IPCP isteği 3 seçenek içermeli: %+v", opts)
					}
					g.send(ProtoIPCP, packet{codeConfNak, p.id, encodeOptions([]option{
						opt(ipcpAddr, 192, 0, 2, 10), opt(ipcpDNS1, 198, 18, 1, 53), opt(ipcpDNS2, 198, 18, 1, 54),
					})})
				} else {
					g.send(ProtoIPCP, packet{codeConfAck, p.id, p.data})
				}
			}
		}
	}
}

func pipe(t *testing.T) (*tunnel.Conn, *fakeGate) {
	a, b := net.Pipe()
	g := &fakeGate{t: t, fc: tunnel.New(b), echoReply: make(chan []byte, 1), ipv4: make(chan []byte, 1), termAck: make(chan struct{})}
	go g.run()
	t.Cleanup(func() { a.Close(); b.Close() })
	return tunnel.New(a), g
}

func TestNegotiationAndData(t *testing.T) {
	fc, g := pipe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, err := Start(ctx, fc, Config{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	inf := l.Info()
	if inf.LocalIP != netip.MustParseAddr("192.0.2.10") || inf.PeerIP != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("adresler: %+v", inf)
	}
	if len(inf.DNS) != 2 || inf.DNS[1] != netip.MustParseAddr("198.18.1.54") || inf.PeerMRU != 1354 {
		t.Fatalf("info: %+v", inf)
	}
	if !g.sawLCPRej {
		t.Fatal("PFC/ACFC reddedilmedi")
	}

	// outbound data
	pkt := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 1, 0, 0, 192, 0, 2, 10, 198, 18, 1, 53}
	if err := l.WritePacket(pkt); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-g.ipv4:
		if !bytes.Equal(got, pkt) {
			t.Fatalf("giden paket bozuk: %x", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("paket gateway'e ulaşmadı")
	}

	// inbound data
	g.fc.WriteFrame(ProtoIPv4, pkt)
	got, err := l.ReadPacket()
	if err != nil || !bytes.Equal(got, pkt) {
		t.Fatalf("gelen paket: %x %v", got, err)
	}

	// echo
	g.send(ProtoLCP, packet{codeEchoReq, 9, []byte{1, 2, 3, 4, 'x'}})
	select {
	case d := <-g.echoReply:
		if !bytes.Equal(d[:4], g.clientMag) || string(d[4:]) != "x" {
			t.Fatalf("echo reply yanlış: %x (magic %x)", d, g.clientMag)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("echo reply gelmedi")
	}
	if !g.sawProtoR {
		t.Fatal("IPv6CP için Protocol-Reject gönderilmedi")
	}

	// peer terminates
	g.send(ProtoLCP, packet{codeTermReq, 3, nil})
	select {
	case <-g.termAck:
	case <-time.After(2 * time.Second):
		t.Fatal("TermAck gelmedi")
	}
	select {
	case <-l.Done():
		if !strings.Contains(l.Err().Error(), "terminated") {
			t.Fatalf("beklenmeyen hata: %v", l.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("link kapanmadı")
	}
}

func TestStartTimeoutWhenPeerSilent(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { // drain, never answer
		buf := make([]byte, 4096)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()
	_, err := Start(context.Background(), tunnel.New(a), Config{RetryInterval: 50 * time.Millisecond, MaxRetries: 3})
	if err == nil || !strings.Contains(err.Error(), "not responding") {
		t.Fatalf("zaman aşımı hatası bekleniyordu: %v", err)
	}
}

func TestLinkStaysUp(t *testing.T) {
	fc, _ := pipe(t)
	l, err := Start(context.Background(), fc, Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = l
	// handled by fakeGate which never answers echo requests; just make sure
	// the defaults don't kill a healthy link quickly.
	select {
	case <-l.Done():
		t.Fatalf("link erken kapandı: %v", l.Err())
	case <-time.After(300 * time.Millisecond):
	}
	l.Close()
}
