// Package socks5 is a minimal CONNECT-only, no-auth SOCKS5 server meant for
// loopback use (testing the tunnel through the in-process netstack).
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// DialFunc opens an outbound connection (e.g. netstack.Net.DialContext).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Serve listens on addr, which must be a loopback address, and serves until
// ctx is cancelled.
func Serve(ctx context.Context, addr string, dial DialFunc, logf func(string, ...any)) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("SOCKS may only listen on a loopback address (%s)", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			if err := handle(ctx, c, dial); err != nil && logf != nil {
				logf("socks: %v", err)
			}
		}()
	}
}

func handle(ctx context.Context, c net.Conn, dial DialFunc) error {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 5 {
		return errors.New("not SOCKS5")
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		c.Write([]byte{5, 0xff})
		return errors.New("client does not support no-auth")
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return err
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return err
	}
	if req[0] != 5 || req[1] != 1 { // only CONNECT
		reply(c, 7)
		return fmt.Errorf("unsupported command %d", req[1])
	}
	var host string
	switch req[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return err
		}
		host = netip.AddrFrom4(a).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return err
		}
		host = string(name)
	default:
		reply(c, 8)
		return errors.New("unsupported address type")
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return err
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))))

	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	up, err := dial(dctx, "tcp", target)
	if err != nil {
		reply(c, 5)
		return fmt.Errorf("%s: %w", target, err)
	}
	defer up.Close()
	if err := reply(c, 0); err != nil {
		return err
	}
	_ = c.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); closeWrite(up); done <- struct{}{} }()
	go func() { io.Copy(c, up); closeWrite(c); done <- struct{}{} }()
	select {
	case <-done:
		<-done
	case <-ctx.Done():
	}
	return nil
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

func reply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
