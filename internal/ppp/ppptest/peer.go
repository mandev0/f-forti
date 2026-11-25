// Package ppptest provides a minimal FortiGate-like PPP peer for tests.
package ppptest

import (
	"encoding/binary"
	"net/netip"

	"f-forti/internal/ppp"
)

func pkt(code, id byte, data []byte) []byte {
	b := []byte{code, id, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(4+len(data)))
	return append(b, data...)
}

func opt(typ byte, data []byte) []byte { return append([]byte{typ, byte(2 + len(data))}, data...) }

// Serve answers LCP/IPCP like a FortiGate: it assigns ip and dns via IPCP
// Nak, acks everything else, and passes IPv4 packets to onIPv4. It returns
// when the transport fails or the client terminates.
func Serve(fc ppp.FrameConn, ip netip.Addr, dns []netip.Addr, onIPv4 func([]byte)) error {
	want := map[byte][]byte{3: ip.AsSlice()}
	if len(dns) > 0 {
		want[129] = dns[0].AsSlice()
	}
	if len(dns) > 1 {
		want[131] = dns[1].AsSlice()
	}
	lcpReq := append(opt(1, []byte{0x05, 0xdc}), opt(5, []byte{9, 9, 9, 9})...)
	if err := fc.WriteFrame(ppp.ProtoLCP, pkt(1, 1, lcpReq)); err != nil {
		return err
	}
	for {
		proto, data, err := fc.ReadFrame()
		if err != nil {
			return err
		}
		if proto == ppp.ProtoIPv4 {
			if onIPv4 != nil {
				onIPv4(data)
			}
			continue
		}
		if len(data) < 4 {
			continue
		}
		code, id, body := data[0], data[1], data[4:]
		switch proto {
		case ppp.ProtoLCP:
			switch code {
			case 1: // ConfReq
				fc.WriteFrame(ppp.ProtoLCP, pkt(2, id, body))
				fc.WriteFrame(ppp.ProtoIPCP, pkt(1, 1, opt(3, []byte{192, 0, 2, 1})))
			case 9: // EchoReq
				fc.WriteFrame(ppp.ProtoLCP, pkt(10, id, append([]byte{9, 9, 9, 9}, body[min(4, len(body)):]...)))
			case 5: // TermReq
				fc.WriteFrame(ppp.ProtoLCP, pkt(6, id, nil))
				return nil
			}
		case ppp.ProtoIPCP:
			if code != 1 {
				continue
			}
			var nak []byte
			for b := body; len(b) >= 2 && int(b[1]) <= len(b) && b[1] >= 2; b = b[b[1]:] {
				typ, val := b[0], b[2:b[1]]
				if w, ok := want[typ]; ok && string(w) != string(val) {
					nak = append(nak, opt(typ, w)...)
				}
			}
			if len(nak) > 0 {
				fc.WriteFrame(ppp.ProtoIPCP, pkt(3, id, nak))
			} else {
				fc.WriteFrame(ppp.ProtoIPCP, pkt(2, id, body))
			}
		}
	}
}
