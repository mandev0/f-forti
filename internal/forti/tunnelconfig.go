package forti

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// TunnelConfig is the parsed /remote/fortisslvpn_xml document.
type TunnelConfig struct {
	XMLName xml.Name `xml:"sslvpn-tunnel"`
	Ver     string   `xml:"ver,attr"`
	DTLS    string   `xml:"dtls,attr"`
	Patch   string   `xml:"patch,attr"`

	Methods []struct {
		Value string `xml:"value,attr"`
	} `xml:"tunnel-method"`

	FOS struct {
		Platform string `xml:"platform,attr"`
		Major    string `xml:"major,attr"`
		Minor    string `xml:"minor,attr"`
		Patch    string `xml:"patch,attr"`
		Build    string `xml:"build,attr"`
	} `xml:"fos"`

	AuthSes struct {
		CheckSrcIP              string `xml:"check-src-ip,attr"`
		TunConnectWithoutReauth string `xml:"tun-connect-without-reauth,attr"`
		TunUserSesTimeout       string `xml:"tun-user-ses-timeout,attr"`
	} `xml:"auth-ses"`

	ClientConfig struct {
		SavePassword string `xml:"save-password,attr"`
		KeepAlive    string `xml:"keep-alive,attr"`
		AutoConnect  string `xml:"auto-connect,attr"`
	} `xml:"client-config"`

	IdleTimeout struct {
		Val string `xml:"val,attr"`
	} `xml:"idle-timeout"`
	AuthTimeout struct {
		Val string `xml:"val,attr"`
	} `xml:"auth-timeout"`

	IPv4 struct {
		// FortiOS sends both <dns ip='x'/> entries and a <dns domain='a;b'/>
		// entry carrying the DNS search list.
		DNS []struct {
			IP     string `xml:"ip,attr"`
			Domain string `xml:"domain,attr"`
		} `xml:"dns"`
		DNSSuffix string `xml:"dns-suffix"`
		SplitDNS  []struct {
			Domains string `xml:"domains,attr"`
			DNS1    string `xml:"dnsserver1,attr"`
			DNS2    string `xml:"dnsserver2,attr"`
		} `xml:"split-dns"`
		Assigned struct {
			IP string `xml:"ipv4,attr"`
		} `xml:"assigned-addr"`
		Split struct {
			Negate string `xml:"negate,attr"`
			Addrs  []struct {
				IP   string `xml:"ip,attr"`
				Mask string `xml:"mask,attr"`
			} `xml:"addr"`
		} `xml:"split-tunnel-info"`
	} `xml:"ipv4"`

	IPv6 *struct {
		Inner string `xml:",innerxml"`
	} `xml:"ipv6"`
}

// DNSServers returns the tunnel DNS server addresses.
func (t *TunnelConfig) DNSServers() []string {
	var out []string
	for _, d := range t.IPv4.DNS {
		if d.IP != "" {
			out = append(out, d.IP)
		}
	}
	return out
}

// SearchDomains returns the DNS search list (from <dns domain=…> and
// <dns-suffix>).
func (t *TunnelConfig) SearchDomains() []string {
	var out []string
	add := func(s string) {
		out = append(out, strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })...)
	}
	for _, d := range t.IPv4.DNS {
		add(d.Domain)
	}
	add(t.IPv4.DNSSuffix)
	return out
}

// CompactRoutes returns Routes with duplicates and prefixes already covered by
// a broader prefix removed, sorted by address.
func (t *TunnelConfig) CompactRoutes() (routes []netip.Prefix, bad []string) {
	all, bad := t.Routes()
	return CompactPrefixes(all), bad
}

// CompactPrefixes removes duplicates and prefixes contained in another prefix.
func CompactPrefixes(in []netip.Prefix) []netip.Prefix {
	ps := slices.Clone(in)
	// Broadest first; ties by address. A prefix is kept only if no kept
	// prefix (which is at least as broad) contains it.
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if a.Bits() != b.Bits() {
			return a.Bits() - b.Bits()
		}
		return a.Addr().Compare(b.Addr())
	})
	var kept []netip.Prefix
	for _, p := range ps {
		covered := false
		for _, k := range kept {
			if k.Bits() <= p.Bits() && k.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	slices.SortFunc(kept, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return kept
}

// Routes returns the split-tunnel networks as prefixes, exactly as sent
// (duplicates included). Entries that fail to parse are returned in bad.
func (t *TunnelConfig) Routes() (routes []netip.Prefix, bad []string) {
	for _, a := range t.IPv4.Split.Addrs {
		ip, err := netip.ParseAddr(a.IP)
		m := net.ParseIP(a.Mask).To4()
		if err != nil || !ip.Is4() || m == nil {
			bad = append(bad, a.IP+"/"+a.Mask)
			continue
		}
		ones, bits := net.IPMask(m).Size()
		if bits == 0 { // non-contiguous mask
			bad = append(bad, a.IP+"/"+a.Mask)
			continue
		}
		routes = append(routes, netip.PrefixFrom(ip, ones).Masked())
	}
	return routes, bad
}

// SplitDomains returns the list of split-DNS domains across all entries.
func (t *TunnelConfig) SplitDomains() []string {
	var out []string
	for _, s := range t.IPv4.SplitDNS {
		for _, d := range strings.FieldsFunc(s.Domains, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
			out = append(out, d)
		}
	}
	return out
}

// TunnelConfig downloads and parses the tunnel configuration. The raw XML is
// always returned when the HTTP request itself succeeded.
func (c *Client) TunnelConfig(ctx context.Context) ([]byte, *TunnelConfig, error) {
	// openfortivpn touches these first; some FortiOS builds require it.
	if _, _, err := c.do(ctx, http.MethodGet, "/remote/index", nil); err != nil {
		return nil, nil, err
	}
	if _, _, err := c.do(ctx, http.MethodGet, "/remote/fortisslvpn", nil); err != nil {
		return nil, nil, err
	}
	resp, body, err := c.do(ctx, http.MethodGet, "/remote/fortisslvpn_xml", nil)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return body, nil, fmt.Errorf("fortisslvpn_xml HTTP %d (tunnel mode may be disabled)", resp.StatusCode)
	}
	var tc TunnelConfig
	if err := xml.Unmarshal(body, &tc); err != nil {
		return body, nil, fmt.Errorf("cannot parse XML: %w", err)
	}
	return body, &tc, nil
}
