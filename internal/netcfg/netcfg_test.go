package netcfg

import (
	"encoding/xml"
	"net/netip"
	"strings"
	"testing"

	"f-forti/internal/forti"
	"f-forti/internal/ppp"
)

const sample = `<sslvpn-tunnel ver='2'><ipv4>
<split-dns domains='Example.Test,*.example.internal,example.test' dnsserver1='198.18.0.53' dnsserver2='198.18.0.54'/>
<split-dns domains='other.lan' dnsserver1='198.19.0.1' dnsserver2=''/>
<dns domain='example.test;example.internal'/><dns ip='198.18.0.53'/><dns ip='198.18.0.54'/>
<assigned-addr ipv4='198.19.254.32'/>
<split-tunnel-info>
<addr ip='198.18.0.0' mask='255.254.0.0'/><addr ip='198.18.9.41' mask='255.255.255.255'/>
<addr ip='0.0.0.0' mask='0.0.0.0'/><addr ip='198.51.100.0' mask='255.255.255.0'/>
<addr ip='203.0.113.7' mask='255.255.255.255'/>
</split-tunnel-info></ipv4></sslvpn-tunnel>`

func parse(t *testing.T, s string) *forti.TunnelConfig {
	var tc forti.TunnelConfig
	if err := xml.Unmarshal([]byte(s), &tc); err != nil {
		t.Fatal(err)
	}
	return &tc
}

func TestBuild(t *testing.T) {
	info := ppp.Info{LocalIP: netip.MustParseAddr("198.19.254.32"), PeerMRU: 1500,
		DNS: []netip.Addr{netip.MustParseAddr("198.18.0.53")}}
	c, err := Build(parse(t, sample), info, netip.MustParseAddr("203.0.113.7"), DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, r := range c.Routes {
		got = append(got, r.String())
	}
	if strings.Join(got, " ") != "198.18.0.0/15 198.51.100.0/24 203.0.113.7/32" {
		t.Fatalf("rotalar: %v", got)
	}
	if !strings.Contains(strings.Join(c.Warnings, "\n"), "0.0.0.0/0") {
		t.Fatalf("default rota reddedilmeliydi: %v", c.Warnings)
	}
	if len(c.DNSRules) != 2 || strings.Join(c.DNSRules[0].Domains, ",") != "example.test,example.internal" {
		t.Fatalf("dns kuralları: %+v", c.DNSRules)
	}
	if len(c.DNSRules[1].Servers) != 1 || c.DNSRules[1].Servers[0].String() != "198.19.0.1" {
		t.Fatalf("2. grup: %+v", c.DNSRules[1])
	}
	if len(c.DNSServers) == 0 || c.DNSServers[0].String() != "198.18.0.53" {
		t.Fatalf("adaptör DNS: %v", c.DNSServers)
	}
	if !c.GatewayInRoutes() {
		t.Fatal("gateway rotaların içinde olmalı")
	}
	ov := c.LocalOverlaps([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/25")})
	if len(ov) != 1 || !strings.Contains(ov[0], "unreachable") {
		t.Fatalf("çakışma: %v", ov)
	}
	// DNS 198.19.0.1 is inside 198.18/15 → no warning about unreachable DNS
	for _, w := range c.Warnings {
		if strings.Contains(w, "DNS server") {
			t.Fatalf("beklenmeyen uyarı: %s", w)
		}
	}
}

func TestAllowedPolicy(t *testing.T) {
	info := ppp.Info{LocalIP: netip.MustParseAddr("198.19.254.32"), PeerMRU: 1500}
	pol := Policy{MinPrefixBits: 8, Allowed: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")}}
	c, err := Build(parse(t, sample), info, netip.Addr{}, pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Routes) != 1 || c.Routes[0].String() != "198.18.0.0/15" {
		t.Fatalf("rotalar: %v", c.Routes)
	}
}

func TestNegateRefused(t *testing.T) {
	x := strings.Replace(sample, "<split-tunnel-info>", "<split-tunnel-info negate='1'>", 1)
	_, err := Build(parse(t, x), ppp.Info{LocalIP: netip.MustParseAddr("198.18.1.1")}, netip.Addr{}, DefaultPolicy)
	if err == nil {
		t.Fatal("negate reddedilmeliydi")
	}
}
