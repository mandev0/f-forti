//go:build windows

// Package winnet applies a netcfg.Config on Windows: Wintun adapter, address,
// routes, gateway host route, NRPT split-DNS rules and DNS search list, and
// undoes all of it (including leftovers from a crash).
package winnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"f-forti/internal/netcfg"
)

const (
	adapterName   = "FVPN"
	tunnelType    = "FVPN"
	interfaceMetr = 5
)

// Fixed GUID so a stale adapter is replaced rather than duplicated.
var adapterGUID = windows.GUID{Data1: 0x6f1e4a3b, Data2: 0x52c1, Data3: 0x4d7e, Data4: [8]byte{0x9a, 0x0b, 0x46, 0x56, 0x50, 0x4e, 0x00, 0x01}}

// leftover is persisted while connected so a crashed service can clean up.
type leftover struct {
	HostRoute *hostRoute `json:"hostRoute,omitempty"`
	NRPT      bool       `json:"nrpt,omitempty"`
}

type hostRoute struct {
	LUID    uint64 `json:"luid"`
	Dest    string `json:"dest"`
	NextHop string `json:"nextHop"`
}

// Net is the Windows backend. Not safe for concurrent Up/Down.
type Net struct {
	logf      func(string, ...any)
	statePath string

	dev  tun.Device
	luid winipcfg.LUID
	st   leftover
}

// New creates a backend persisting crash-recovery state in stateDir.
func New(stateDir string, logf func(string, ...any)) *Net {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Net{logf: logf, statePath: filepath.Join(stateDir, "netstate.json")}
}

// CleanupStale removes leftovers of a previous run (call at service start).
func (n *Net) CleanupStale() {
	b, err := os.ReadFile(n.statePath)
	if err == nil {
		var st leftover
		if json.Unmarshal(b, &st) == nil {
			n.st = st
		}
	}
	// NRPT rules are always swept by prefix, state or not.
	n.st.NRPT = true
	n.undo()
}

// Up creates the adapter and applies cfg. On error everything is rolled back.
func (n *Net) Up(cfg *netcfg.Config) (dev tun.Device, warnings []string, err error) {
	if n.dev != nil {
		return nil, nil, errors.New("network already configured")
	}
	defer func() {
		if err != nil {
			n.Down()
		}
	}()

	tun.WintunTunnelType = tunnelType
	d, err := tun.CreateTUNWithRequestedGUID(adapterName, &adapterGUID, cfg.MTU)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create the Wintun adapter: %w", err)
	}
	n.dev = d
	n.luid = winipcfg.LUID(d.(*tun.NativeTun).LUID())

	// Address /32 on a point-to-point adapter; routes are on-link.
	if err := n.luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{netip.PrefixFrom(cfg.LocalIP, 32)}); err != nil {
		return nil, nil, fmt.Errorf("could not assign the IP address: %w", err)
	}
	if ifc, err := n.luid.IPInterface(windows.AF_INET); err == nil {
		ifc.UseAutomaticMetric = false
		ifc.Metric = interfaceMetr
		ifc.NLMTU = uint32(cfg.MTU)
		ifc.DadTransmits = 0
		ifc.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		if err := ifc.Set(); err != nil {
			warnings = append(warnings, fmt.Sprintf("interface settings: %v", err))
		}
	}
	// No IPv6 over this tunnel.
	_ = n.luid.FlushIPAddresses(windows.AF_INET6)
	_ = n.luid.FlushRoutes(windows.AF_INET6)
	_ = n.luid.FlushDNS(windows.AF_INET6)

	local, err := localNetworks(n.luid)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("could not read local networks: %v", err))
	}
	warnings = append(warnings, cfg.LocalOverlaps(local)...)

	if cfg.GatewayInRoutes() {
		if err := n.addHostRoute(cfg.Gateway); err != nil {
			return nil, nil, fmt.Errorf("gateway %s is inside the tunnel routes and its host route could not be added: %w", cfg.Gateway, err)
		}
	}

	rd := make([]*winipcfg.RouteData, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		rd = append(rd, &winipcfg.RouteData{Destination: r, NextHop: netip.IPv4Unspecified(), Metric: 0})
	}
	if err := n.luid.SetRoutesForFamily(windows.AF_INET, rd); err != nil {
		return nil, nil, fmt.Errorf("could not add routes: %w", err)
	}

	// DNS: tunnel servers on the adapter (its low metric makes them the
	// first choice; some machines, e.g. with smart name resolution disabled
	// by GPO, ignore NRPT entirely), plus NRPT for the per-domain servers
	// where it works, plus the search list for short names.
	if err := n.luid.SetDNS(windows.AF_INET, cfg.DNSServers, cfg.SearchDomains); err != nil {
		warnings = append(warnings, fmt.Sprintf("DNS servers: %v", err))
	}
	if len(cfg.DNSRules) > 0 {
		n.st.NRPT = true
		n.saveState()
		if w, err := writeNRPT(cfg.DNSRules); err != nil {
			return nil, nil, fmt.Errorf("could not write NRPT rules: %w", err)
		} else {
			warnings = append(warnings, w...)
		}
	}
	flushDNSCache()
	n.saveState()
	n.logf("network up: %s/32, %d routes, DNS %v, %d NRPT rules, metric %d", cfg.LocalIP, len(cfg.Routes), cfg.DNSServers, len(cfg.DNSRules), interfaceMetr)
	return d, warnings, nil
}

// Down removes everything Up created. Safe to call repeatedly.
func (n *Net) Down() error {
	n.undo()
	if n.dev != nil {
		// Closing the Wintun device deletes the adapter and with it the
		// address, routes and interface DNS settings.
		n.dev.Close()
		n.dev = nil
	}
	flushDNSCache()
	return nil
}

func (n *Net) undo() {
	if n.st.NRPT {
		if err := deleteNRPT(); err != nil {
			n.logf("NRPT cleanup: %v", err)
		}
	}
	if hr := n.st.HostRoute; hr != nil {
		dst, err1 := netip.ParsePrefix(hr.Dest)
		nh, err2 := netip.ParseAddr(hr.NextHop)
		if err1 == nil && err2 == nil {
			if err := winipcfg.LUID(hr.LUID).DeleteRoute(dst, nh); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
				n.logf("could not delete host route: %v", err)
			}
		}
	}
	n.st = leftover{}
	_ = os.Remove(n.statePath)
}

func (n *Net) saveState() {
	b, _ := json.Marshal(n.st)
	tmp := n.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, n.statePath)
	}
}

// addHostRoute pins the gateway to the current best default route.
func (n *Net) addHostRoute(gw netip.Addr) error {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return err
	}
	type cand struct {
		luid   winipcfg.LUID
		nh     netip.Addr
		metric uint32
	}
	var cs []cand
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.Prefix().Bits() != 0 || r.InterfaceLUID == n.luid {
			continue
		}
		m := r.Metric
		if ifc, err := r.InterfaceLUID.IPInterface(windows.AF_INET); err == nil {
			if !ifc.Connected {
				continue
			}
			m += ifc.Metric
		}
		cs = append(cs, cand{r.InterfaceLUID, r.NextHop.Addr(), m})
	}
	if len(cs) == 0 {
		return errors.New("no default route found")
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].metric < cs[j].metric })
	best := cs[0]
	dst := netip.PrefixFrom(gw, 32)
	if err := best.luid.AddRoute(dst, best.nh, 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return err
	}
	n.st.HostRoute = &hostRoute{LUID: uint64(best.luid), Dest: dst.String(), NextHop: best.nh.String()}
	n.saveState()
	n.logf("gateway host route: %s -> %s", dst, best.nh)
	return nil
}

// localNetworks returns on-link IPv4 networks of other interfaces.
func localNetworks(self winipcfg.LUID) ([]netip.Prefix, error) {
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for i := range rows {
		r := &rows[i]
		if r.InterfaceLUID == self {
			continue
		}
		a := r.Address.Addr()
		if !a.Is4() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		p, err := a.Prefix(int(r.OnLinkPrefixLength))
		if err == nil && p.Bits() > 0 {
			out = append(out, p)
		}
	}
	return out, nil
}

var procFlush = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

func flushDNSCache() {
	if procFlush.Find() == nil {
		procFlush.Call()
	}
}
