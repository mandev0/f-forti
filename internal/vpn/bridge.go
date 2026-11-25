// Package vpn glues a PPP link to a packet device (Wintun on Windows, or the
// in-process gVisor netstack used for testing without privileges).
package vpn

import (
	"context"
	"errors"

	"golang.zx2c4.com/wireguard/tun"

	"f-forti/internal/ppp"
)

// Bridge copies IPv4 packets between dev and link until ctx is cancelled or
// either side fails. It does not close dev or link.
func Bridge(ctx context.Context, dev tun.Device, link *ppp.Link) error {
	errc := make(chan error, 2)

	go func() { // device -> tunnel
		bs := dev.BatchSize()
		if bs < 1 {
			bs = 1
		}
		bufs := make([][]byte, bs)
		for i := range bufs {
			bufs[i] = make([]byte, 65535)
		}
		sizes := make([]int, bs)
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				errc <- err
				return
			}
			for i := 0; i < n; i++ {
				p := bufs[i][:sizes[i]]
				if len(p) == 0 || p[0]>>4 != 4 {
					continue // IPv6 is not carried by this tunnel
				}
				if err := link.WritePacket(p); err != nil {
					errc <- err
					return
				}
			}
		}
	}()

	go func() { // tunnel -> device
		for {
			p, err := link.ReadPacket()
			if err != nil {
				errc <- err
				return
			}
			if len(p) == 0 || p[0]>>4 != 4 {
				continue
			}
			if _, err := dev.Write([][]byte{p}, 0); err != nil {
				errc <- err
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}
