// Package forti implements the HTTPS (control) part of the FortiGate SSL-VPN
// protocol: login, 2FA, tunnel configuration download and logout.
package forti

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultUserAgent is what openfortivpn sends; FortiGate accepts it.
const DefaultUserAgent = "Mozilla/5.0 SV1"

const sessionCookie = "SVPNCOOKIE"

// Config describes how to reach a FortiGate SSL-VPN portal.
type Config struct {
	Server      string // host or host:port (default port 443)
	Realm       string // optional SSL-VPN realm
	UserAgent   string
	TrustedCert string    // optional hex SHA-256 pin of the server leaf certificate
	Debug       io.Writer // optional HTTP trace (secrets redacted)
}

// CertError is returned when the server certificate cannot be verified.
type CertError struct {
	Fingerprint string // hex SHA-256 of leaf certificate (DER)
	Subject     string
	Issuer      string
	Err         error
}

func (e *CertError) Error() string {
	return fmt.Sprintf("server certificate could not be verified: %v (subject=%q issuer=%q sha256=%s)",
		e.Err, e.Subject, e.Issuer, e.Fingerprint)
}
func (e *CertError) Unwrap() error { return e.Err }

// ErrAuthFailed means the gateway rejected the credentials or the 2FA code.
var ErrAuthFailed = errors.New("authentication failed")

// PeerInfo describes the TLS peer seen during the last handshake.
type PeerInfo struct {
	TLSVersion  uint16
	Subject     string
	Issuer      string
	NotAfter    time.Time
	Fingerprint string
	Verified    bool // chain verified against system roots (not just pinned)
}

// Client talks to one FortiGate portal. Not safe for concurrent logins.
type Client struct {
	cfg  Config
	base *url.URL
	host string
	hc   *http.Client
	jar  http.CookieJar
	pin  string
	tls  *tls.Config

	mu   sync.Mutex
	peer PeerInfo

	// LastRedir holds the "redir" field of the last successful logincheck
	// response; a hostcheck URL here means the gateway requires host checking.
	LastRedir string
}

// New creates a client. No network traffic happens until a method is called.
func New(cfg Config) (*Client, error) {
	if cfg.Server == "" {
		return nil, errors.New("server address is empty")
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	hostport := cfg.Server
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(hostport, "443")
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("invalid server address %q: %w", cfg.Server, err)
	}

	c := &Client{
		cfg:  cfg,
		base: &url.URL{Scheme: "https", Host: hostport},
		host: host,
		pin:  strings.ToLower(strings.ReplaceAll(strings.TrimSpace(cfg.TrustedCert), ":", "")),
	}

	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// Standard verification is replaced by VerifyConnection, which does
		// full chain verification OR exact pin match. Never neither.
		InsecureSkipVerify: true,
		VerifyConnection:   c.verifyConn,
	}
	c.tls = tlsCfg
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		Proxy:                 nil, // VPN gateway is always contacted directly
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second,                                       // FTM push waits for approval
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{}, // HTTP/1.1 only
		MaxIdleConnsPerHost:   2,
	}
	var rt http.RoundTripper = tr
	if cfg.Debug != nil {
		rt = &debugRT{next: tr, w: cfg.Debug}
	}
	jar, _ := cookiejar.New(nil)
	c.jar = jar
	c.hc = &http.Client{
		Transport: rt,
		Jar:       jar,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c, nil
}

func (c *Client) verifyConn(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("server sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	fp := hex.EncodeToString(sum[:])
	info := PeerInfo{
		TLSVersion:  cs.Version,
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		NotAfter:    leaf.NotAfter,
		Fingerprint: fp,
	}
	certErr := func(err error) error {
		return &CertError{Fingerprint: fp, Subject: info.Subject, Issuer: info.Issuer, Err: err}
	}

	inter := x509.NewCertPool()
	for _, ic := range cs.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: c.host, Intermediates: inter})
	info.Verified = verr == nil

	c.mu.Lock()
	c.peer = info
	c.mu.Unlock()

	if c.pin != "" {
		// A pin is strict: it must match even if the chain is valid.
		if subtle.ConstantTimeCompare([]byte(fp), []byte(c.pin)) != 1 {
			return certErr(errors.New("pinned fingerprint does not match"))
		}
		return nil
	}
	if verr != nil {
		return certErr(verr)
	}
	return nil
}

// Peer returns information about the server certificate from the last handshake.
func (c *Client) Peer() PeerInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peer
}

// Host returns host:port of the gateway.
func (c *Client) Host() string { return c.base.Host }

// SessionCookie returns the SVPNCOOKIE value, or "" if not logged in.
func (c *Client) SessionCookie() string {
	for _, ck := range c.jar.Cookies(c.base) {
		if ck.Name == sessionCookie && ck.Value != "" {
			return ck.Value
		}
	}
	return ""
}

type kv struct{ k, v string }

// form is an ordered x-www-form-urlencoded body (FortiGate is picky about
// nothing in particular, but keeping openfortivpn's order removes a variable).
type form []kv

func (f form) encode() string {
	var b strings.Builder
	for i, p := range f {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p.k))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(p.v))
	}
	return b.String()
}

func (c *Client) do(ctx context.Context, method, path string, f form) (*http.Response, []byte, error) {
	ref, err := url.Parse(path)
	if err != nil {
		return nil, nil, err
	}
	var body io.Reader
	if f != nil {
		body = strings.NewReader(f.encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.ResolveReference(ref).String(), body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	if f != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp, b, err
}

// LoginPage fetches the portal login page and returns its HTTP status and
// hints about the authentication methods it advertises.
func (c *Client) LoginPage(ctx context.Context) (int, []string, error) {
	resp, body, err := c.do(ctx, http.MethodGet, "/remote/login?lang=en", nil)
	if err != nil {
		return 0, nil, err
	}
	low := strings.ToLower(string(body))
	var hints []string
	for _, h := range []struct{ needle, label string }{
		{"saml", "SAML login available"},
		{"realm", "realm field present"},
		{"hostcheck", "host-check hint"},
		{"client certificate", "client certificate hint"},
		{"fortitoken", "FortiToken hint"},
	} {
		if strings.Contains(low, h.needle) {
			hints = append(hints, h.label)
		}
	}
	return resp.StatusCode, hints, nil
}

// Challenge is a pending second-factor request.
type Challenge struct {
	Fields  map[string]string // parsed ret=2 fields (reqid, polid, grp, magic, tokeninfo, ...)
	Message string            // text to show the user

	legacy    bool // HTML form based challenge (older FortiOS)
	inputs    []kv
	codeField string
}

// PushAvailable reports whether FortiToken Mobile push can be used.
func (ch *Challenge) PushAvailable() bool {
	return strings.Contains(ch.Fields["tokeninfo"], "ftm_push")
}

// TokenInfo returns the raw tokeninfo value (2FA type hint) if any.
func (ch *Challenge) TokenInfo() string { return ch.Fields["tokeninfo"] }

// Login sends username/password. A nil challenge and nil error means the
// session is established; a non-nil challenge means a 2FA code is required.
func (c *Client) Login(ctx context.Context, user, pass string) (*Challenge, error) {
	// Prime cookies like a browser would; errors here surface on logincheck.
	if _, _, err := c.do(ctx, http.MethodGet, "/remote/login?lang=en", nil); err != nil {
		return nil, err
	}
	f := form{{"ajax", "1"}, {"username", user}, {"realm", c.cfg.Realm}, {"credential", pass}}
	resp, body, err := c.do(ctx, http.MethodPost, "/remote/logincheck", f)
	if err != nil {
		return nil, err
	}
	return c.handleLogin(resp, body, false)
}

// Submit2FA answers a challenge with a code, or with a push request when
// push is true. It may return a new challenge (e.g. multi-step).
func (c *Client) Submit2FA(ctx context.Context, ch *Challenge, user, code string, push bool) (*Challenge, error) {
	var f form
	if ch.legacy {
		for _, in := range ch.inputs {
			v := in.v
			if in.k == ch.codeField {
				v = code
			}
			f = append(f, kv{in.k, v})
		}
	} else {
		f = form{{"username", user}, {"realm", c.cfg.Realm}}
		for _, k := range []string{"reqid", "polid", "grp", "portal", "peer", "magic"} {
			if v, ok := ch.Fields[k]; ok {
				f = append(f, kv{k, v})
			}
		}
		if push {
			f = append(f, kv{"code", ""}, kv{"code2", ""}, kv{"ftmpush", "1"})
		} else {
			f = append(f, kv{"code", code}, kv{"code2", ""})
		}
	}
	resp, body, err := c.do(ctx, http.MethodPost, "/remote/logincheck", f)
	if err != nil {
		return nil, err
	}
	return c.handleLogin(resp, body, true)
}

// handleLogin interprets a logincheck answer. codeStep marks the answer to a
// verification code, where an unrecognised page means the code was refused.
func (c *Client) handleLogin(resp *http.Response, body []byte, codeStep bool) (*Challenge, error) {
	s := strings.TrimSpace(string(body))
	fields := parseRet(s)

	if c.SessionCookie() != "" {
		c.LastRedir = fields["redir"]
		return nil, nil
	}
	switch fields["ret"] {
	case "2":
		msg := fields["chal_msg"]
		if msg == "" {
			msg = "Enter the verification code"
		}
		return &Challenge{Fields: fields, Message: msg}, nil
	case "0":
		return nil, ErrAuthFailed
	case "1":
		return nil, fmt.Errorf("login accepted but no %s received (redir=%q)", sessionCookie, fields["redir"])
	}
	if ch := parseLegacyChallenge(s); ch != nil {
		return ch, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrAuthFailed
	}
	uerr := &UnexpectedResponseError{Status: resp.StatusCode, Summary: htmlSummary(s, 200)}
	if codeStep {
		// FortiGate answers a refused code (e.g. one already used in this
		// 30 s window) with an HTML page instead of ret=0.
		return nil, fmt.Errorf("%w (%v)", ErrCodeRejected, uerr)
	}
	return nil, uerr
}

// ErrCodeRejected means the gateway did not accept the verification code.
var ErrCodeRejected = errors.New("the gateway rejected the verification code")

// UnexpectedResponseError is a logincheck answer we do not understand.
// Summary is the page title and visible text only (no markup, no hidden
// form values).
type UnexpectedResponseError struct {
	Status  int
	Summary string
}

func (e *UnexpectedResponseError) Error() string {
	if e.Summary == "" {
		return fmt.Sprintf("unexpected response from the gateway (HTTP %d)", e.Status)
	}
	return fmt.Sprintf("unexpected response from the gateway (HTTP %d): %s", e.Status, e.Summary)
}

var (
	reHTMLTitle  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reHTMLBlocks = regexp.MustCompile(`(?is)<(script|style|head)\b.*?</(script|style|head)>`)
	reHTMLTags   = regexp.MustCompile(`(?s)<[^>]*>`)
)

// htmlSummary returns "title – visible text" of an HTML page, or a plain
// snippet for non-HTML bodies.
func htmlSummary(s string, n int) string {
	if !strings.Contains(strings.ToLower(s[:min(len(s), 512)]), "<html") && !strings.HasPrefix(strings.TrimSpace(strings.ToLower(s)), "<!doctype") {
		return snippet(s, n)
	}
	title := ""
	if m := reHTMLTitle.FindStringSubmatch(s); m != nil {
		title = strings.TrimSpace(html.UnescapeString(reHTMLTags.ReplaceAllString(m[1], " ")))
	}
	text := reHTMLBlocks.ReplaceAllString(s, " ")
	text = html.UnescapeString(reHTMLTags.ReplaceAllString(text, " "))
	text = snippet(text, n)
	switch {
	case title != "" && text != "":
		return snippet(title+" – "+text, n)
	case title != "":
		return title
	}
	return text
}

// parseRet parses "ret=2,reqid=1,polid=1-1,...,chal_msg=text, with commas".
// Segments without a key are glued back onto the previous value.
func parseRet(s string) map[string]string {
	m := map[string]string{}
	if !strings.HasPrefix(s, "ret=") {
		return m
	}
	last := ""
	for _, part := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(part, "="); ok && isKey(k) {
			m[k] = v
			last = k
			continue
		}
		if last != "" {
			m[last] += "," + part
		}
	}
	return m
}

func isKey(k string) bool {
	if k == "" || len(k) > 32 {
		return false
	}
	for _, r := range k {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// Logout ends the web session (and thereby any tunnel bound to it).
func (c *Client) Logout(ctx context.Context) error {
	if c.SessionCookie() == "" {
		return nil
	}
	_, _, err := c.do(ctx, http.MethodGet, "/remote/logout", nil)
	return err
}

func snippet(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
