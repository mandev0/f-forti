package ppp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Control protocol packet codes (RFC 1661).
const (
	codeConfReq   = 1
	codeConfAck   = 2
	codeConfNak   = 3
	codeConfRej   = 4
	codeTermReq   = 5
	codeTermAck   = 6
	codeCodeRej   = 7
	codeProtoRej  = 8
	codeEchoReq   = 9
	codeEchoReply = 10
	codeDiscard   = 11
)

type packet struct {
	code byte
	id   byte
	data []byte
}

func parsePacket(b []byte) (packet, error) {
	if len(b) < 4 {
		return packet{}, errors.New("short control packet")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < 4 || n > len(b) {
		return packet{}, fmt.Errorf("invalid control packet length %d", n)
	}
	return packet{code: b[0], id: b[1], data: b[4:n]}, nil
}

func (p packet) encode() []byte {
	b := make([]byte, 4, 4+len(p.data))
	b[0], b[1] = p.code, p.id
	binary.BigEndian.PutUint16(b[2:4], uint16(4+len(p.data)))
	return append(b, p.data...)
}

type option struct {
	typ  byte
	data []byte
}

func parseOptions(b []byte) ([]option, error) {
	var out []option
	for len(b) > 0 {
		if len(b) < 2 || int(b[1]) < 2 || int(b[1]) > len(b) {
			return nil, errors.New("malformed option list")
		}
		n := int(b[1])
		out = append(out, option{typ: b[0], data: append([]byte(nil), b[2:n]...)})
		b = b[n:]
	}
	return out, nil
}

func encodeOptions(opts []option) []byte {
	var b []byte
	for _, o := range opts {
		b = append(b, o.typ, byte(2+len(o.data)))
		b = append(b, o.data...)
	}
	return b
}

// cp is the Configure-Request/Ack/Nak/Reject machinery shared by LCP and
// IPCP. It is simplified for a client talking to a single known peer:
// renegotiation is supported, the full RFC 1661 automaton is not.
type cp struct {
	name  string
	proto uint16

	ours        []option // our current Configure-Request options
	id          byte     // identifier of our outstanding request
	sent        bool     // our request has been sent at least once
	retries     int
	ackedByPeer bool // peer acked our current request
	ackedPeer   bool // we acked the peer's request

	// judge splits the peer's request into rejected and nak'ed options;
	// empty results mean "ack".
	judge func(opts []option) (nak, rej []option)
	// onPeerAck is called with the peer's options when we ack them.
	onPeerAck func(opts []option)
	// onNak adjusts ours according to the peer's suggestions.
	onNak func(opts []option)
	// onAcked is called with our final options when the peer acks them.
	onAcked func(opts []option)
}

func (c *cp) opened() bool { return c.ackedByPeer && c.ackedPeer }

func (c *cp) request() packet {
	c.id++
	c.sent = true
	c.retries++
	return packet{code: codeConfReq, id: c.id, data: encodeOptions(c.ours)}
}

// handle processes one packet and returns replies to send. restart is set
// when our own request must be (re)sent.
func (c *cp) handle(p packet) (replies []packet, restart bool, err error) {
	switch p.code {
	case codeConfReq:
		opts, perr := parseOptions(p.data)
		if perr != nil {
			return nil, false, fmt.Errorf("%s: %w", c.name, perr)
		}
		if c.opened() {
			// Peer renegotiates: start over on our side too.
			c.ackedByPeer = false
			restart = true
		}
		nak, rej := c.judge(opts)
		switch {
		case len(rej) > 0:
			c.ackedPeer = false
			replies = append(replies, packet{codeConfRej, p.id, encodeOptions(rej)})
		case len(nak) > 0:
			c.ackedPeer = false
			replies = append(replies, packet{codeConfNak, p.id, encodeOptions(nak)})
		default:
			c.ackedPeer = true
			if c.onPeerAck != nil {
				c.onPeerAck(opts)
			}
			replies = append(replies, packet{codeConfAck, p.id, p.data})
		}
	case codeConfAck:
		if p.id == c.id && c.sent {
			c.ackedByPeer = true
			c.retries = 0
			if c.onAcked != nil {
				c.onAcked(c.ours)
			}
		}
	case codeConfNak:
		if p.id == c.id {
			opts, perr := parseOptions(p.data)
			if perr != nil {
				return nil, false, fmt.Errorf("%s nak: %w", c.name, perr)
			}
			c.onNak(opts)
			restart = true
		}
	case codeConfRej:
		if p.id == c.id {
			opts, perr := parseOptions(p.data)
			if perr != nil {
				return nil, false, fmt.Errorf("%s reject: %w", c.name, perr)
			}
			rejected := map[byte]bool{}
			for _, o := range opts {
				rejected[o.typ] = true
			}
			kept := c.ours[:0:0]
			for _, o := range c.ours {
				if !rejected[o.typ] {
					kept = append(kept, o)
				}
			}
			c.ours = kept
			restart = true
		}
	case codeTermReq:
		replies = append(replies, packet{codeTermAck, p.id, nil})
		err = fmt.Errorf("%s: peer terminated the link", c.name)
	case codeTermAck, codeCodeRej, codeProtoRej, codeDiscard:
		// nothing to do
	default:
		replies = append(replies, packet{codeCodeRej, p.id, p.encode()})
	}
	return replies, restart, err
}
