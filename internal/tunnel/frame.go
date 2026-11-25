// Package tunnel implements FortiGate SSL-VPN framing over the tunnel TLS
// connection. Each PPP frame (protocol field + information, no HDLC, no
// address/control bytes) is prefixed by a 6-byte header:
//
//	[0:2] total length = payload length + 6 (big endian)
//	[2:4] magic 0x5050
//	[4:6] payload length (big endian)
package tunnel

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

const (
	hdrLen     = 6
	MaxPayload = 0xffff - hdrLen
)

// ErrBadFrame means the stream is out of sync or not a Forti tunnel.
var ErrBadFrame = errors.New("invalid tunnel frame")

// Conn reads and writes framed PPP over a tunnel connection.
type Conn struct {
	c   net.Conn
	r   *bufio.Reader
	wmu sync.Mutex
	wb  []byte
}

// New wraps an established tunnel connection (see forti.Client.DialTunnel).
func New(c net.Conn) *Conn {
	return &Conn{c: c, r: bufio.NewReaderSize(c, 64<<10), wb: make([]byte, 0, 2048)}
}

// ReadFrame returns the next PPP frame split into protocol and information.
// The returned slice is freshly allocated and owned by the caller.
func (t *Conn) ReadFrame() (proto uint16, info []byte, err error) {
	var h [hdrLen]byte
	if _, err := io.ReadFull(t.r, h[:]); err != nil {
		return 0, nil, err
	}
	if string(h[:5]) == "HTTP/" {
		line, _ := t.r.ReadString('\n')
		return 0, nil, fmt.Errorf("gateway refused the tunnel: %s", strings.TrimSpace(string(h[:])+line))
	}
	if h[2] != 0x50 || h[3] != 0x50 {
		return 0, nil, fmt.Errorf("%w: magic %02x%02x", ErrBadFrame, h[2], h[3])
	}
	total := int(binary.BigEndian.Uint16(h[0:2]))
	n := int(binary.BigEndian.Uint16(h[4:6]))
	if total != n+hdrLen || n < 1 {
		return 0, nil, fmt.Errorf("%w: length %d/%d", ErrBadFrame, total, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(t.r, buf); err != nil {
		return 0, nil, err
	}
	// Defensive: tolerate address/control bytes and a compressed protocol
	// field even though we never negotiate ACFC/PFC.
	if len(buf) >= 2 && buf[0] == 0xff && buf[1] == 0x03 {
		buf = buf[2:]
	}
	switch {
	case len(buf) >= 1 && buf[0]&1 == 1:
		return uint16(buf[0]), buf[1:], nil
	case len(buf) >= 2:
		return binary.BigEndian.Uint16(buf[0:2]), buf[2:], nil
	}
	return 0, nil, fmt.Errorf("%w: too short", ErrBadFrame)
}

// WriteFrame sends one PPP frame. Safe for concurrent use.
func (t *Conn) WriteFrame(proto uint16, info []byte) error {
	n := 2 + len(info)
	if n > MaxPayload {
		return fmt.Errorf("frame too large: %d", n)
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	b := t.wb[:0]
	b = binary.BigEndian.AppendUint16(b, uint16(n+hdrLen))
	b = append(b, 0x50, 0x50)
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	b = binary.BigEndian.AppendUint16(b, proto)
	b = append(b, info...)
	t.wb = b[:0]
	_, err := t.c.Write(b)
	return err
}

// Close closes the underlying connection.
func (t *Conn) Close() error { return t.c.Close() }
