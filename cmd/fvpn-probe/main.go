// fvpn-probe logs in to a FortiGate SSL-VPN portal (with 2FA), downloads the
// tunnel configuration, prints a summary and logs out. It opens no tunnel and
// needs no administrator rights.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"f-forti/internal/forti"
)

func main() {
	var (
		server  = flag.String("server", "", "VPN server, host or host:port (required)")
		realm   = flag.String("realm", "", "SSL-VPN realm (if any)")
		user    = flag.String("user", "", "username (prompted if empty)")
		pin     = flag.String("trusted-cert", "", "SHA-256 fingerprint of the server certificate (if it cannot be verified)")
		ua      = flag.String("user-agent", forti.DefaultUserAgent, "HTTP User-Agent")
		redact  = flag.Bool("redact", false, "mask IP addresses and domains in the output (for sharing)")
		debug   = flag.Bool("debug", false, "show the HTTP exchange (password/cookie hidden)")
		showXML = flag.Bool("xml", true, "also print the raw XML")
		outFile = flag.String("out", "", "write the result to this file (only a summary goes to the terminal)")
	)
	flag.Parse()
	if *server == "" {
		fmt.Fprintln(os.Stderr, "usage: fvpn-probe -server vpn.example.com[:port] [-realm R] [-user U] [-redact]")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cfg := forti.Config{Server: *server, Realm: *realm, UserAgent: *ua, TrustedCert: *pin}
	if *debug {
		cfg.Debug = os.Stderr
	}
	c, err := forti.New(cfg)
	if err != nil {
		fatal(err)
	}

	in := bufio.NewReader(os.Stdin)
	out := &strings.Builder{}
	section := func(title string) { fmt.Fprintf(out, "\n== %s ==\n", title) }

	// 1. Login page / TLS
	status, hints, err := c.LoginPage(ctx)
	if err != nil {
		var ce *forti.CertError
		if errors.As(err, &ce) {
			fmt.Fprintf(os.Stderr, "\n%v\n\nIf you recognise the certificate, try again with:\n  -trusted-cert %s\n", ce, ce.Fingerprint)
			os.Exit(1)
		}
		fatal(err)
	}
	p := c.Peer()
	section("Server / TLS")
	fmt.Fprintf(out, "Server        : %s\n", c.Host())
	fmt.Fprintf(out, "TLS           : %s\n", tls.VersionName(p.TLSVersion))
	fmt.Fprintf(out, "Certificate   : %s\n", p.Subject)
	fmt.Fprintf(out, "Issuer        : %s\n", p.Issuer)
	fmt.Fprintf(out, "Valid until   : %s\n", p.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(out, "Chain valid   : %v (sha256=%s)\n", p.Verified, p.Fingerprint)
	fmt.Fprintf(out, "Login page    : HTTP %d", status)
	if len(hints) > 0 {
		fmt.Fprintf(out, "  [%s]", strings.Join(hints, ", "))
	}
	fmt.Fprintln(out)

	// 2. Credentials
	if *user == "" {
		*user = prompt(in, "Username: ")
	}
	pass := readSecret(in, "Password: ")

	ch, err := c.Login(ctx, *user, pass)
	pass = ""
	if err != nil {
		fatal(err)
	}
	section("Authentication")
	fmt.Fprintln(out, "step 1 (username/password): OK")
	step := 2
	for ch != nil {
		fmt.Fprintf(out, "step %d: 2FA requested, tokeninfo=%q, push=%v\n", step, ch.TokenInfo(), ch.PushAvailable())
		fmt.Printf("\n%s\n", ch.Message)
		hint := "Code: "
		if ch.PushAvailable() {
			hint = "Code (leave empty to send a FortiToken push): "
		}
		code := strings.TrimSpace(readSecret(in, hint))
		push := code == "" && ch.PushAvailable()
		if push {
			fmt.Println("Push sent, approve it on your phone…")
		}
		ch, err = c.Submit2FA(ctx, ch, *user, code, push)
		if err != nil {
			fatal(err)
		}
		step++
	}
	fmt.Fprintln(out, "Session established (SVPNCOOKIE received)")
	if c.LastRedir != "" {
		fmt.Fprintf(out, "redir         : %s\n", c.LastRedir)
		if strings.Contains(strings.ToLower(c.LastRedir), "hostcheck") {
			fmt.Fprintln(out, "WARNING       : the gateway seems to require host checking")
		}
	}

	defer func() {
		lctx, lcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer lcancel()
		if err := c.Logout(lctx); err != nil {
			fmt.Fprintf(os.Stderr, "logout error: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "\nLogged out.")
		}
	}()

	// 3. Tunnel config
	raw, tc, err := c.TunnelConfig(ctx)
	if tc != nil {
		summarize(out, tc)
	}
	if err != nil {
		section("Error")
		fmt.Fprintln(out, err)
	}
	if *showXML && len(raw) > 0 {
		section("Raw XML")
		fmt.Fprintln(out, strings.TrimSpace(string(raw)))
	}

	text := out.String()
	if *redact {
		text = redactText(text, c.Host(), tc)
	}
	if *outFile == "" {
		fmt.Println(text)
		return
	}
	if err := os.WriteFile(*outFile, []byte(text), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write the file (%v), printing to the terminal:\n", err)
		fmt.Println(text)
		return
	}
	// Short summary on screen: everything before the raw XML section.
	short, _, _ := strings.Cut(text, "\n== Raw XML ==")
	fmt.Println(short)
	fmt.Printf("\nFull output (including raw XML) written to: %s\n", *outFile)
}

func summarize(out *strings.Builder, tc *forti.TunnelConfig) {
	fmt.Fprintf(out, "\n== Tunnel configuration ==\n")
	f := tc.FOS
	fmt.Fprintf(out, "FortiOS       : %s %s.%s.%s build %s\n", f.Platform, f.Major, f.Minor, f.Patch, f.Build)
	var methods []string
	for _, m := range tc.Methods {
		methods = append(methods, m.Value)
	}
	fmt.Fprintf(out, "Tunnel methods: %s (xml ver=%s)\n", orNone(strings.Join(methods, ", ")), tc.Ver)
	fmt.Fprintf(out, "DTLS          : %s\n", orNone(tc.DTLS))
	fmt.Fprintf(out, "Assigned IP   : %s\n", orNone(tc.IPv4.Assigned.IP))
	fmt.Fprintf(out, "DNS           : %s\n", orNone(strings.Join(tc.DNSServers(), ", ")))
	fmt.Fprintf(out, "DNS search    : %s\n", orNone(strings.Join(tc.SearchDomains(), ", ")))
	for _, s := range tc.IPv4.SplitDNS {
		n := len(strings.FieldsFunc(s.Domains, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }))
		fmt.Fprintf(out, "Split DNS     : %d domains -> %s %s\n                %s\n", n, s.DNS1, s.DNS2, s.Domains)
	}
	raw, _ := tc.Routes()
	uniq := map[netip.Prefix]bool{}
	for _, r := range raw {
		uniq[r] = true
	}
	routes, bad := tc.CompactRoutes()
	fmt.Fprintf(out, "Routes        : %d entries, %d unique, %d after removing covered\n", len(raw), len(uniq), len(routes))
	byBits := map[int]int{}
	for _, r := range routes {
		byBits[r.Bits()]++
	}
	var dist []string
	for b := 0; b <= 32; b++ {
		if byBits[b] > 0 {
			dist = append(dist, fmt.Sprintf("/%d×%d", b, byBits[b]))
		}
	}
	fmt.Fprintf(out, "Distribution  : %s\n", strings.Join(dist, " "))
	mode := "normal (only listed networks via tunnel)"
	if tc.IPv4.Split.Negate != "" && tc.IPv4.Split.Negate != "0" && tc.IPv4.Split.Negate != "false" {
		mode = "NEGATE (everything EXCEPT the listed networks via tunnel)"
	}
	if len(routes) == 0 && len(bad) == 0 {
		mode = "no list → may be full tunnel"
	}
	fmt.Fprintf(out, "Split tunnel  : %d networks, mode: %s\n", len(routes), mode)
	for _, r := range routes {
		fmt.Fprintf(out, "                %s\n", r)
	}
	for _, b := range bad {
		fmt.Fprintf(out, "                (unparsable) %s\n", b)
	}
	fmt.Fprintf(out, "IPv6 block    : %v\n", tc.IPv6 != nil)
	fmt.Fprintf(out, "idle-timeout  : %s  auth-timeout: %s\n", orNone(tc.IdleTimeout.Val), orNone(tc.AuthTimeout.Val))
	a := tc.AuthSes
	fmt.Fprintf(out, "auth-ses      : check-src-ip=%s tun-connect-without-reauth=%s tun-user-ses-timeout=%s\n",
		orNone(a.CheckSrcIP), orNone(a.TunConnectWithoutReauth), orNone(a.TunUserSesTimeout))
	cc := tc.ClientConfig
	fmt.Fprintf(out, "client-config : save-password=%s keep-alive=%s auto-connect=%s\n",
		orNone(cc.SavePassword), orNone(cc.KeepAlive), orNone(cc.AutoConnect))
}

var reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// redactText replaces IPv4 addresses (except netmasks) and known domain names
// with stable placeholders, so network structure stays readable.
func redactText(s, host string, tc *forti.TunnelConfig) string {
	names := map[string]bool{}
	if h := strings.Split(host, ":")[0]; h != "" {
		names[h] = true
	}
	if tc != nil {
		for _, d := range tc.SplitDomains() {
			names[strings.TrimPrefix(d, "*.")] = true
		}
		for _, d := range tc.SearchDomains() {
			names[strings.TrimPrefix(d, "*.")] = true
		}
	}
	list := make([]string, 0, len(names))
	for n := range names {
		if !reIPv4.MatchString(n) {
			list = append(list, n)
		}
	}
	sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
	for i, n := range list {
		s = strings.ReplaceAll(s, n, fmt.Sprintf("domain%d.example", i+1))
	}

	ips := map[string]string{}
	s = reIPv4.ReplaceAllStringFunc(s, func(ip string) string {
		if strings.HasPrefix(ip, "255.") || ip == "0.0.0.0" {
			return ip
		}
		if r, ok := ips[ip]; ok {
			return r
		}
		r := fmt.Sprintf("IP%d", len(ips)+1)
		ips[ip] = r
		return r
	})
	return s
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func prompt(in *bufio.Reader, label string) string {
	fmt.Print(label)
	s, _ := in.ReadString('\n')
	return strings.TrimSpace(s)
}

func readSecret(in *bufio.Reader, label string) string {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return prompt(in, label)
	}
	fmt.Print(label)
	b, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		fatal(err)
	}
	return string(b)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
