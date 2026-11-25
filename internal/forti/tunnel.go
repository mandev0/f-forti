package forti

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// DialTunnel opens a new TLS connection to the gateway (with the same
// certificate checks as the HTTPS session) and requests the SSL-VPN tunnel.
// On success the gateway starts sending framed PPP right away; there is no
// HTTP response. A failure shows up as an "HTTP/..." reply on the first read.
func (c *Client) DialTunnel(ctx context.Context) (net.Conn, error) {
	cookie := c.SessionCookie()
	if cookie == "" {
		return nil, errors.New("no session: log in first")
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second},
		Config:    c.tls.Clone(),
	}
	conn, err := d.DialContext(ctx, "tcp", c.base.Host)
	if err != nil {
		return nil, err
	}
	// "Host: sslvpn" is what FortiClient and openfortivpn send.
	req := "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: " +
		sessionCookie + "=" + cookie + "\r\n\r\n"
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetWriteDeadline(time.Time{})
	return conn, nil
}
