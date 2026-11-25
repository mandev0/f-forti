// Package ppp implements the client side of the PPP subset FortiGate uses
// inside the SSL-VPN tunnel: LCP (MRU, magic, echo) and IPCP (address and
// DNS servers). IPv6CP, CCP etc. are protocol-rejected.
package ppp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// PPP protocol numbers.
const (
	ProtoIPv4 = 0x0021
	ProtoIPv6 = 0x0057
	ProtoLCP  = 0xc021
	ProtoIPCP = 0x8021
)

// LCP / IPCP option types.
const (
	lcpMRU   = 1
	lcpACCM  = 2
	lcpMagic = 5

	ipcpAddr = 3
	ipcpDNS1 = 129
	ipcpDNS2 = 131
)

// FrameConn is a framed PPP transport (see tunnel.Conn).
type FrameConn interface {
	ReadFrame() (proto uint16, info []byte, err error)
	WriteFrame(proto uint16, info []byte) error
	Close() error
}

// Config tunes the link.
type Config struct {
	Logf func(format string, args ...any) // optional

	// EchoInterval: send an LCP Echo-Request after this much silence from
	// the peer (dead peer detection). 0 disables.
	EchoInterval time.Duration
	// EchoFailures: give up after this many unanswered echo requests.
	EchoFailures int
	// RetryInterval / MaxRetries for Configure-Requests.
	RetryInterval time.Duration
	MaxRetries    int
}

// Info is the negotiated result.
type Info struct {
	LocalIP netip.Addr
	PeerIP  netip.Addr
	DNS     []netip.Addr
	PeerMRU int // largest packet the peer accepts (our MTU)
}

// Stats are cumulative counters.
type Stats struct {
	RxPackets, TxPackets uint64
	RxBytes, TxBytes     uint64
	Dropped              uint64
}

// Link is an established PPP session.
type Link struct {
	fc  FrameConn
	cfg Config

	info Info
	up   chan struct{} // closed when IPCP is opened
	in   chan []byte   // inbound IPv4 packets

	ctrl     chan ctrlFrame
	done     chan struct{}
	doneOnce sync.Once
	err      error

	ipUp     atomic.Bool
	lastRecv atomic.Int64 // unix nanos

	rxp, txp, rxb, txb, drop atomic.Uint64
}

type ctrlFrame struct {
	proto uint16
	data  []byte
}

// Start runs LCP and IPCP over fc and returns once IP traffic can flow.
// On error fc is closed.
func Start(ctx context.Context, fc FrameConn, cfg Config) (*Link, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = 3 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 10
	}
	if cfg.EchoFailures == 0 {
		cfg.EchoFailures = 3
	}
	l := &Link{
		fc:   fc,
		cfg:  cfg,
		up:   make(chan struct{}),
		in:   make(chan []byte, 512),
		ctrl: make(chan ctrlFrame, 32),
		done: make(chan struct{}),
		info: Info{PeerMRU: 1500},
	}
	l.lastRecv.Store(time.Now().UnixNano())
	go l.readLoop()
	go l.ctrlLoop()

	select {
	case <-l.up:
		return l, nil
	case <-l.done:
		return nil, l.err
	case <-ctx.Done():
		l.fail(ctx.Err())
		return nil, ctx.Err()
	}
}

// Info returns the negotiated parameters.
func (l *Link) Info() Info { return l.info }

// Done is closed when the link is down; Err tells why.
func (l *Link) Done() <-chan struct{} { return l.done }

// Err returns the reason the link went down (valid after Done is closed).
func (l *Link) Err() error {
	<-l.done
	return l.err
}

// Stats returns traffic counters.
func (l *Link) Stats() Stats {
	return Stats{
		RxPackets: l.rxp.Load(), TxPackets: l.txp.Load(),
		RxBytes: l.rxb.Load(), TxBytes: l.txb.Load(),
		Dropped: l.drop.Load(),
	}
}

// ReadPacket returns the next inbound IPv4 packet.
func (l *Link) ReadPacket() ([]byte, error) {
	select {
	case p := <-l.in:
		return p, nil
	case <-l.done:
		return nil, l.err
	}
}

// WritePacket sends one IPv4 packet.
func (l *Link) WritePacket(p []byte) error {
	select {
	case <-l.done:
		return l.err
	default:
	}
	if len(p) > l.info.PeerMRU {
		l.drop.Add(1)
		return nil // too big for peer; netstack/OS MTU should prevent this
	}
	if err := l.fc.WriteFrame(ProtoIPv4, p); err != nil {
		l.fail(err)
		return err
	}
	l.txp.Add(1)
	l.txb.Add(uint64(len(p)))
	return nil
}

// Close terminates the session politely (LCP Terminate-Request) and closes
// the transport.
func (l *Link) Close() error {
	select {
	case <-l.done:
		return nil
	default:
	}
	_ = l.fc.WriteFrame(ProtoLCP, packet{code: codeTermReq, id: 1}.encode())
	l.fail(errClosed)
	return nil
}

var errClosed = errors.New("connection closed")

func (l *Link) fail(err error) {
	l.doneOnce.Do(func() {
		l.err = err
		close(l.done)
		l.fc.Close()
	})
}

func (l *Link) readLoop() {
	for {
		proto, data, err := l.fc.ReadFrame()
		if err != nil {
			select {
			case <-l.done:
			default:
				l.fail(fmt.Errorf("tunnel read: %w", err))
			}
			return
		}
		l.lastRecv.Store(time.Now().UnixNano())
		if proto == ProtoIPv4 {
			if !l.ipUp.Load() {
				l.drop.Add(1)
				continue
			}
			l.rxp.Add(1)
			l.rxb.Add(uint64(len(data)))
			select {
			case l.in <- data:
			case <-l.done:
				return
			}
			continue
		}
		select {
		case l.ctrl <- ctrlFrame{proto, data}:
		case <-l.done:
			return
		}
	}
}

func randMagic() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		if m := binary.BigEndian.Uint32(b[:]); m != 0 {
			return m
		}
	}
}

func (l *Link) ctrlLoop() {
	magic := randMagic()
	magicOpt := func() option {
		return option{lcpMagic, binary.BigEndian.AppendUint32(nil, magic)}
	}

	lcp := &cp{name: "LCP", proto: ProtoLCP, ours: []option{magicOpt()}}
	lcp.judge = func(opts []option) (nak, rej []option) {
		for _, o := range opts {
			switch o.typ {
			case lcpMRU:
				if len(o.data) != 2 {
					rej = append(rej, o)
				}
			case lcpACCM:
				// meaningless without HDLC framing; accept
			case lcpMagic:
				if len(o.data) != 4 {
					rej = append(rej, o)
				} else if binary.BigEndian.Uint32(o.data) == magic {
					// looped back? ask for a different one
					nak = append(nak, option{lcpMagic, binary.BigEndian.AppendUint32(nil, randMagic())})
				}
			default:
				// auth, PFC, ACFC, callback, ...: we keep the plain framing
				rej = append(rej, o)
			}
		}
		return nak, rej
	}
	lcp.onPeerAck = func(opts []option) {
		for _, o := range opts {
			if o.typ == lcpMRU {
				l.info.PeerMRU = int(binary.BigEndian.Uint16(o.data))
			}
		}
	}
	lcp.onNak = func(opts []option) {
		for _, o := range opts {
			if o.typ == lcpMagic {
				magic = randMagic()
				for i := range lcp.ours {
					if lcp.ours[i].typ == lcpMagic {
						lcp.ours[i] = magicOpt()
					}
				}
			}
		}
	}

	zero4 := []byte{0, 0, 0, 0}
	ipcp := &cp{name: "IPCP", proto: ProtoIPCP, ours: []option{
		{ipcpAddr, zero4}, {ipcpDNS1, zero4}, {ipcpDNS2, zero4},
	}}
	ipcp.judge = func(opts []option) (nak, rej []option) {
		for _, o := range opts {
			if o.typ != ipcpAddr || len(o.data) != 4 {
				rej = append(rej, o) // compression, peer-side DNS, ...
			}
		}
		return nil, rej
	}
	ipcp.onPeerAck = func(opts []option) {
		for _, o := range opts {
			if o.typ == ipcpAddr {
				l.info.PeerIP = netip.AddrFrom4([4]byte(o.data))
			}
		}
	}
	ipcp.onNak = func(opts []option) {
		for _, n := range opts {
			for i := range ipcp.ours {
				if ipcp.ours[i].typ == n.typ && len(n.data) == 4 {
					ipcp.ours[i].data = n.data
				}
			}
		}
	}
	ipcp.onAcked = func(opts []option) {
		l.info.DNS = nil
		for _, o := range opts {
			a := netip.AddrFrom4([4]byte(o.data))
			switch o.typ {
			case ipcpAddr:
				l.info.LocalIP = a
			case ipcpDNS1, ipcpDNS2:
				if !a.IsUnspecified() {
					l.info.DNS = append(l.info.DNS, a)
				}
			}
		}
	}

	send := func(proto uint16, p packet) {
		if err := l.fc.WriteFrame(proto, p.encode()); err != nil {
			l.fail(fmt.Errorf("tunnel write: %w", err))
		}
	}
	lastSent := map[*cp]time.Time{}
	sendReq := func(c *cp) {
		if c.retries >= l.cfg.MaxRetries {
			l.fail(fmt.Errorf("%s: peer is not responding", c.name))
			return
		}
		send(c.proto, c.request())
		lastSent[c] = time.Now()
	}
	ipcpStarted := false
	checkUp := func() {
		if lcp.opened() && !ipcpStarted {
			ipcpStarted = true
			l.cfg.Logf("LCP up (peer MRU %d)", l.info.PeerMRU)
			sendReq(ipcp)
		}
		if ipcp.opened() && !l.ipUp.Load() {
			if !l.info.LocalIP.IsValid() || l.info.LocalIP.IsUnspecified() {
				l.fail(errors.New("IPCP: no IP address assigned"))
				return
			}
			l.cfg.Logf("IPCP up: local %s, peer %s, DNS %v", l.info.LocalIP, l.info.PeerIP, l.info.DNS)
			l.ipUp.Store(true)
			close(l.up)
		}
	}

	sendReq(lcp)
	tick := time.NewTicker(min(time.Second, l.cfg.RetryInterval))
	defer tick.Stop()
	echoOutstanding := 0
	var echoID, rejID byte

	for {
		select {
		case <-l.done:
			return
		case f := <-l.ctrl:
			echoOutstanding = 0
			p, err := parsePacket(f.data)
			if err != nil {
				l.cfg.Logf("malformed control packet (proto %#04x): %v", f.proto, err)
				continue
			}
			var c *cp
			switch f.proto {
			case ProtoLCP:
				c = lcp
				switch p.code {
				case codeEchoReq:
					if lcp.opened() {
						data := binary.BigEndian.AppendUint32(nil, magic)
						if len(p.data) > 4 {
							data = append(data, p.data[4:]...)
						}
						send(ProtoLCP, packet{codeEchoReply, p.id, data})
					}
					continue
				case codeEchoReply, codeDiscard:
					continue
				case codeProtoRej:
					l.cfg.Logf("peer rejected protocol: %x", p.data)
					continue
				}
			case ProtoIPCP:
				c = ipcp
			default:
				// IPv6CP, CCP, ...: Protocol-Reject (only valid once LCP is open)
				if lcp.opened() {
					rej := binary.BigEndian.AppendUint16(nil, f.proto)
					rej = append(rej, f.data...)
					if len(rej) > l.info.PeerMRU-4 {
						rej = rej[:l.info.PeerMRU-4]
					}
					rejID++
					send(ProtoLCP, packet{codeProtoRej, rejID, rej})
				}
				continue
			}
			wasOpen := c.opened()
			replies, restart, err := c.handle(p)
			for _, r := range replies {
				send(c.proto, r)
			}
			if err != nil {
				l.fail(err)
				return
			}
			if restart && (c == lcp || ipcpStarted) {
				sendReq(c)
			}
			if wasOpen && !c.opened() && c == lcp {
				// LCP renegotiation takes IP down until IPCP re-opens; keep
				// it simple and treat it as a link failure.
				l.fail(errors.New("peer requested LCP renegotiation"))
				return
			}
			checkUp()

		case now := <-tick.C:
			for _, c := range []*cp{lcp, ipcp} {
				if c.sent && !c.ackedByPeer && now.Sub(lastSent[c]) >= l.cfg.RetryInterval {
					sendReq(c)
				}
			}
			if l.cfg.EchoInterval > 0 && l.ipUp.Load() {
				silent := now.Sub(time.Unix(0, l.lastRecv.Load()))
				if silent >= l.cfg.EchoInterval*time.Duration(echoOutstanding+1) {
					if echoOutstanding >= l.cfg.EchoFailures {
						l.fail(fmt.Errorf("peer did not answer %d echo requests", echoOutstanding))
						return
					}
					echoID++
					send(ProtoLCP, packet{codeEchoReq, echoID, binary.BigEndian.AppendUint32(nil, magic)})
					echoOutstanding++
				}
			}
			if silent := now.Sub(time.Unix(0, l.lastRecv.Load())); silent < time.Second {
				echoOutstanding = 0
			}
		}
	}
}
