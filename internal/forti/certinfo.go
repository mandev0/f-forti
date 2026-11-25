package forti

import "context"

// FetchCert connects to server and returns its certificate details without
// pinning anything. Verified tells whether the system trusts the chain; the
// caller decides whether to pin Fingerprint. Once the TLS handshake has
// produced a certificate, HTTP-level errors are irrelevant here.
func FetchCert(ctx context.Context, server string) (PeerInfo, error) {
	c, err := New(Config{Server: server})
	if err != nil {
		return PeerInfo{}, err
	}
	_, _, err = c.LoginPage(ctx)
	if p := c.Peer(); p.Fingerprint != "" {
		return p, nil
	}
	return PeerInfo{}, err
}
