package tunnel

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ca, cb := New(a), New(b)
	go ca.WriteFrame(0xc021, []byte{1, 2, 3})
	proto, info, err := cb.ReadFrame()
	if err != nil || proto != 0xc021 || !bytes.Equal(info, []byte{1, 2, 3}) {
		t.Fatalf("%x %x %v", proto, info, err)
	}
}

func TestWireFormat(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go New(a).WriteFrame(0x0021, []byte{0xaa})
	buf := make([]byte, 9)
	n, _ := b.Read(buf)
	want := []byte{0, 9, 0x50, 0x50, 0, 3, 0x00, 0x21, 0xaa}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("got %x want %x", buf[:n], want)
	}
}

func TestHTTPRejection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() { b.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n")); b.Close() }()
	_, _, err := New(a).ReadFrame()
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("403 hatası bekleniyordu: %v", err)
	}
}

func TestBadMagic(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() { b.Write([]byte{0, 8, 0x12, 0x34, 0, 2, 0, 0x21}); b.Close() }()
	if _, _, err := New(a).ReadFrame(); err == nil {
		t.Fatal("bozuk magic kabul edildi")
	}
}
