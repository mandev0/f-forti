// Package netcfg turns what the gateway sent (XML + IPCP) into a validated,
// platform-independent network plan that an OS backend can apply.
package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"f-forti/internal/forti"
	"f-forti/internal/ppp"
)

// DNSRule sends queries for Domains to Servers (NRPT rule on Windows).
type DNSRule struct {
	Domains []string
	Servers []netip.Addr
}

// Config is the network plan for one tunnel session.
type Config struct {
	LocalIP  netip.Addr
	MTU      int
	Routes   []netip.Prefix // compacted split-tunnel routes, IPv4 only
	DNSRules []DNSRule
	// DNSServers go on the tunnel adapter itself (as FortiClient does), so
	// internal names resolve even where NRPT is not honoured. Queries for
	// other names go to them too while connected.
	DNSServers    []netip.Addr
	SearchDomains []string
	Gateway       netip.Addr // public IP of the VPN gateway (for a host route if needed)
	Warnings      []string
}

// Policy limits what a gateway may push.
type Policy struct {
	// MinPrefixBits rejects routes broader than this (e.g. 8 = nothing wider
	// than a /8). A default route (/0) is never accepted.
	MinPrefixBits int
	// Allowed, if non-empty, restricts routes to these networks.
	Allowed []netip.Prefix
}

// DefaultPolicy refuses default/huge routes; anything /8 or narrower is OK.
var DefaultPolicy = Policy{MinPrefixBits: 8}

// Build creates the plan. It fails only when the session is unusable.
func Build(tc *forti.TunnelConfig, info ppp.Info, gateway netip.Addr, pol Policy) (*Config, error) {
	if !info.LocalIP.Is4() || info.LocalIP.IsUnspecified() {
		return nil, errors.New("no valid tunnel IP")
	}
	c := &Config{LocalIP: info.LocalIP, Gateway: gateway, MTU: info.PeerMRU}
	if c.MTU < 576 || c.MTU > 1500 {
		c.MTU = 1400
	}

	if tc.IPv4.Split.Negate != "" && tc.IPv4.Split.Negate != "0" && tc.IPv4.Split.Negate != "false" {
		return nil, errors.New("negated split tunnel is not supported yet")
	}
	// Filter first, then compact: a rejected broad route must not swallow
	// the narrower ones during compaction.
	routes, bad := tc.Routes()
	for _, b := range bad {
		c.Warnings = append(c.Warnings, "skipped unparsable route: "+b)
	}
	if len(routes) == 0 {
		return nil, errors.New("the gateway sent no split-tunnel routes (full tunnel is not supported in this version)")
	}
	var accepted []netip.Prefix
	rejected := map[netip.Prefix]bool{}
	for _, r := range routes {
		if !r.Addr().Is4() || rejected[r] {
			continue
		}
		if r.Bits() == 0 || r.Bits() < pol.MinPrefixBits {
			rejected[r] = true
			c.Warnings = append(c.Warnings, fmt.Sprintf("rejected overly broad route: %s", r))
			continue
		}
		if len(pol.Allowed) > 0 && !within(r, pol.Allowed) {
			rejected[r] = true
			c.Warnings = append(c.Warnings, fmt.Sprintf("rejected route outside allowed networks: %s", r))
			continue
		}
		accepted = append(accepted, r)
	}
	c.Routes = forti.CompactPrefixes(accepted)
	if len(c.Routes) == 0 {
		return nil, errors.New("no routes left after applying the policy")
	}

	// DNS: split-DNS groups become rules. Servers from IPCP/XML are only
	// used as fallback servers for groups that name none.
	fallback := slices.Clone(info.DNS)
	for _, s := range tc.DNSServers() {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() && !slices.Contains(fallback, a) {
			fallback = append(fallback, a)
		}
	}
	for _, g := range tc.IPv4.SplitDNS {
		var rule DNSRule
		for _, d := range splitList(g.Domains) {
			if d = normDomain(d); d != "" && !slices.Contains(rule.Domains, d) {
				rule.Domains = append(rule.Domains, d)
			}
		}
		for _, s := range []string{g.DNS1, g.DNS2} {
			if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && a.Is4() && !a.IsUnspecified() {
				rule.Servers = append(rule.Servers, a)
			}
		}
		if len(rule.Servers) == 0 {
			rule.Servers = fallback
		}
		if len(rule.Domains) == 0 || len(rule.Servers) == 0 {
			continue
		}
		c.DNSRules = append(c.DNSRules, rule)
	}
	for _, d := range tc.SearchDomains() {
		if d = normDomain(d); d != "" && !slices.Contains(c.SearchDomains, d) {
			c.SearchDomains = append(c.SearchDomains, d)
		}
	}
	c.DNSServers = fallback
	if len(c.DNSServers) == 0 && len(c.DNSRules) > 0 {
		c.DNSServers = slices.Clone(c.DNSRules[0].Servers)
	}
	if len(c.DNSRules) == 0 && len(c.DNSServers) == 0 {
		c.Warnings = append(c.Warnings, "the gateway sent no DNS servers; internal names may not resolve")
	}
	seen := map[netip.Addr]bool{}
	check := func(s netip.Addr) {
		if !seen[s] && !anyContains(c.Routes, s) {
			c.Warnings = append(c.Warnings, fmt.Sprintf("DNS server %s is not covered by any tunnel route", s))
		}
		seen[s] = true
	}
	for _, s := range c.DNSServers {
		check(s)
	}
	for _, r := range c.DNSRules {
		for _, s := range r.Servers {
			check(s)
		}
	}
	return c, nil
}

// GatewayInRoutes reports whether traffic to the gateway itself would be
// captured by the tunnel routes (which needs a host route to avoid a loop).
func (c *Config) GatewayInRoutes() bool {
	return c.Gateway.IsValid() && anyContains(c.Routes, c.Gateway)
}

// LocalOverlaps describes conflicts between tunnel routes and directly
// connected local networks.
func (c *Config) LocalOverlaps(local []netip.Prefix) []string {
	var out []string
	for _, l := range local {
		for _, r := range c.Routes {
			if !r.Overlaps(l) {
				continue
			}
			if r.Bits() <= l.Bits() {
				out = append(out, fmt.Sprintf("local network %s is inside tunnel route %s: tunnel hosts in that range may be unreachable", l, r))
			} else {
				out = append(out, fmt.Sprintf("tunnel route %s is inside local network %s: local devices at those addresses will be reached through the tunnel", r, l))
			}
		}
	}
	return out
}

func within(p netip.Prefix, allowed []netip.Prefix) bool {
	for _, a := range allowed {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func anyContains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
}

// normDomain lowercases, strips "*." and dots, and rejects junk.
func normDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	d = strings.Trim(d, ".")
	if d == "" || len(d) > 253 {
		return ""
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return ""
		}
	}
	return d
}
