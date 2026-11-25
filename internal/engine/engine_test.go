package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"f-forti/internal/config"
	"f-forti/internal/ipc"
	"f-forti/internal/netcfg"
	"f-forti/internal/ppp/ppptest"
	"f-forti/internal/tunnel"
)

const xmlCfg = `<?xml version='1.0' encoding='utf-8'?><sslvpn-tunnel ver='2' dtls='1'>
<ipv4><split-dns domains='example.test' dnsserver1='198.18.0.53' dnsserver2='198.18.0.54'/>
<dns domain='example.test'/><dns ip='198.18.0.53'/><assigned-addr ipv4='192.0.2.10'/>
<split-tunnel-info><addr ip='198.18.0.0' mask='255.254.0.0'/><addr ip='198.18.9.41' mask='255.255.255.255'/><addr ip='198.51.100.0' mask='255.255.255.0'/></split-tunnel-info>
</ipv4><idle-timeout val='300'/><auth-timeout val='28800'/></sslvpn-tunnel>`

type gate struct {
	srv      *httptest.Server
	logouts  atomic.Int32
	tunnels  atomic.Int32
	mu       sync.Mutex
	dropTunn chan struct{}
}

func newGate(t *testing.T) *gate {
	g := &gate{dropTunn: make(chan struct{})}
	authed := func(r *http.Request) bool {
		ck, err := r.Cookie("SVPNCOOKIE")
		return err == nil && ck.Value == "sess"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/remote/login", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/remote/logincheck", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch {
		case r.Form.Get("credential") == "pw":
			fmt.Fprint(w, "ret=2,reqid=7,polid=1-1-1,grp=vpn,magic=1-m,tokeninfo=,chal_msg=Kodu girin")
		case r.Form.Get("reqid") == "7" && r.Form.Get("code") == "123456":
			http.SetCookie(w, &http.Cookie{Name: "SVPNCOOKIE", Value: "sess", Path: "/", Secure: true})
			fmt.Fprint(w, "ret=1,redir=/remote/fortisslvpn_xml")
		default:
			w.WriteHeader(401)
			fmt.Fprint(w, "ret=0")
		}
	})
	for _, p := range []string{"/remote/index", "/remote/fortisslvpn"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {})
	}
	mux.HandleFunc("/remote/fortisslvpn_xml", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(403)
			return
		}
		fmt.Fprint(w, xmlCfg)
	})
	mux.HandleFunc("/remote/logout", func(w http.ResponseWriter, r *http.Request) { g.logouts.Add(1) })
	mux.HandleFunc("/remote/sslvpn-tunnel", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) || r.Host != "sslvpn" {
			w.WriteHeader(403)
			return
		}
		raw, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		// keep bytes the HTTP server already buffered (the client's first
		// LCP frame follows the request immediately)
		conn := bufConn{raw, brw.Reader}
		g.tunnels.Add(1)
		fc := tunnel.New(conn)
		go func() { <-g.dropTunn; conn.Close() }()
		ppptest.Serve(fc, netip.MustParseAddr("192.0.2.10"),
			[]netip.Addr{netip.MustParseAddr("198.18.0.53"), netip.MustParseAddr("198.18.0.54")}, nil)
		conn.Close()
	})
	g.srv = httptest.NewTLSServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *gate) pin() string {
	s := sha256.Sum256(g.srv.Certificate().Raw)
	return hex.EncodeToString(s[:])
}

type bufConn struct {
	net.Conn
	r io.Reader
}

func (b bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

type fakeNet struct {
	mu    sync.Mutex
	up    []*netcfg.Config
	downs int
	dev   tun.Device
}

func (f *fakeNet) Up(c *netcfg.Config) (tun.Device, []string, error) {
	dev, _, err := netstack.CreateNetTUN([]netip.Addr{c.LocalIP}, nil, c.MTU)
	if err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	f.up = append(f.up, c)
	f.dev = dev
	f.mu.Unlock()
	return dev, []string{"test uyarısı"}, nil
}

func (f *fakeNet) Down() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downs++
	if f.dev != nil {
		f.dev.Close()
		f.dev = nil
	}
	return nil
}

func newEngine(t *testing.T, g *gate, fn *fakeNet) *Engine {
	cfg := &config.Config{Profiles: []config.Profile{{ID: "main", Name: "Test", Server: g.srv.Listener.Addr().String(), TrustedCert: g.pin()}}}
	return newEngineCfg(t, cfg, fn)
}

// newEngineCfg uses an in-memory config store (deep-copied like a file).
func newEngineCfg(t *testing.T, cfg *config.Config, fn *fakeNet) *Engine {
	var mu sync.Mutex
	load := func() (*config.Config, error) {
		mu.Lock()
		defer mu.Unlock()
		c := *cfg
		c.Profiles = append([]config.Profile(nil), cfg.Profiles...)
		return &c, nil
	}
	save := func(c *config.Config) error {
		if err := c.Validate(); err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		*cfg = *c
		return nil
	}
	return New(Options{Network: fn, Config: load, Save: save, Logf: t.Logf, Pending: 300 * time.Millisecond})
}

func waitState(t *testing.T, e *Engine, want ipc.State) ipc.Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := e.Status()
		if s.State == want {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("durum %s beklendi, son: %+v", want, e.Status())
	return ipc.Status{}
}

func TestConnectDisconnect(t *testing.T) {
	g := newGate(t)
	fn := &fakeNet{}
	e := newEngine(t, g, fn)

	if err := e.Connect("main", "u", "pw"); err != nil {
		t.Fatal(err)
	}
	s := e.Status()
	if s.State != ipc.StateNeed2FA || s.Message != "Kodu girin" {
		t.Fatalf("2FA bekleniyordu: %+v", s)
	}
	if err := e.Connect("main", "u", "pw"); err == nil {
		t.Fatal("meşgulken ikinci connect kabul edildi")
	}
	if err := e.Submit2FA("123456"); err != nil {
		t.Fatal(err)
	}
	s = waitState(t, e, ipc.StateConnected)
	if s.LocalIP != "192.0.2.10" || s.Routes != 2 || len(s.DNSRules) != 1 || s.ExpiresAt.IsZero() {
		t.Fatalf("status: %+v", s)
	}
	if !strings.Contains(strings.Join(s.Warnings, "|"), "test uyarısı") {
		t.Fatalf("uyarılar: %v", s.Warnings)
	}
	fn.mu.Lock()
	plan := fn.up[0]
	fn.mu.Unlock()
	if plan.Routes[0].String() != "198.18.0.0/15" || plan.DNSRules[0].Domains[0] != "example.test" {
		t.Fatalf("plan: %+v", plan)
	}

	e.Disconnect()
	if st := e.Status(); st.State != ipc.StateIdle {
		t.Fatalf("idle bekleniyordu: %+v", st)
	}
	if fn.downs == 0 || g.logouts.Load() != 1 {
		t.Fatalf("temizlik eksik: downs=%d logouts=%d", fn.downs, g.logouts.Load())
	}
}

func TestWrongCode(t *testing.T) {
	g := newGate(t)
	e := newEngine(t, g, &fakeNet{})
	e.Connect("main", "u", "pw")
	if err := e.Submit2FA("000000"); err == nil {
		t.Fatal("yanlış kod kabul edildi")
	}
	if s := e.Status(); s.State != ipc.StateError || !strings.Contains(s.LastError, "Invalid") {
		t.Fatalf("hata durumu bekleniyordu: %+v", s)
	}
	// error state allows a new attempt
	if err := e.Connect("main", "u", "pw"); err != nil {
		t.Fatal(err)
	}
	e.Disconnect()
	if s := e.Status(); s.State != ipc.StateIdle {
		t.Fatalf("%+v", s)
	}
}

func TestPendingTimeout(t *testing.T) {
	g := newGate(t)
	e := newEngine(t, g, &fakeNet{})
	e.Connect("main", "u", "pw")
	s := waitState(t, e, ipc.StateError)
	if !strings.Contains(s.LastError, "in time") {
		t.Fatalf("%+v", s)
	}
	if err := e.Submit2FA("123456"); err == nil {
		t.Fatal("süresi dolmuş challenge kabul edildi")
	}
}

func TestTunnelDrop(t *testing.T) {
	g := newGate(t)
	fn := &fakeNet{}
	e := newEngine(t, g, fn)
	e.Connect("main", "u", "pw")
	e.Submit2FA("123456")
	waitState(t, e, ipc.StateConnected)
	close(g.dropTunn)
	s := waitState(t, e, ipc.StateError)
	if !strings.Contains(s.LastError, "Tunnel closed") {
		t.Fatalf("%+v", s)
	}
	fn.mu.Lock()
	defer fn.mu.Unlock()
	if fn.downs == 0 {
		t.Fatal("ağ kaldırılmadı")
	}
}

func TestUnknownProfile(t *testing.T) {
	g := newGate(t)
	e := newEngine(t, g, &fakeNet{})
	if err := e.Connect("yok", "u", "pw"); err == nil {
		t.Fatal("olmayan profil kabul edildi")
	}
	if e.Status().State != ipc.StateIdle {
		t.Fatal("durum değişmemeliydi")
	}
}

func TestProfileEditing(t *testing.T) {
	g := newGate(t)
	cfg := &config.Config{}
	e := newEngineCfg(t, cfg, &fakeNet{})

	id, err := e.SaveProfile(ipc.ProfileEdit{Name: " Örnek ", Server: g.srv.Listener.Addr().String(), TrustedCert: strings.ToUpper(g.pin())})
	if err != nil || id == "" {
		t.Fatal(id, err)
	}
	r := e.Handle(ipc.Request{Op: ipc.OpProfiles})
	if !r.OK || len(r.Profiles) != 1 || r.Profiles[0].Name != "Örnek" || r.Profiles[0].TrustedCert != g.pin() || r.Locked {
		t.Fatalf("%+v", r)
	}
	// invalid input is refused by the service, not just the GUI
	for _, bad := range []ipc.ProfileEdit{
		{Name: "x", Server: "noport"},
		{Name: "x", Server: "h:99999"},
		{Name: "", Server: "h:1"},
		{Name: "x", Server: "h:1", TrustedCert: "zz"},
		{ID: "nope", Name: "x", Server: "h:1"},
	} {
		if _, err := e.SaveProfile(bad); err == nil {
			t.Errorf("kabul edilmemeliydi: %+v", bad)
		}
	}
	// in use: cannot edit or delete
	if err := e.Connect(id, "u", "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SaveProfile(ipc.ProfileEdit{ID: id, Name: "y", Server: "h:1"}); err == nil {
		t.Fatal("kullanımdaki profil değiştirildi")
	}
	if err := e.DeleteProfile(id); err == nil {
		t.Fatal("kullanımdaki profil silindi")
	}
	e.Disconnect()
	if _, err := e.SaveProfile(ipc.ProfileEdit{ID: id, Name: "Yeni ad", Server: "vpn.example.com:10443"}); err != nil {
		t.Fatal(err)
	}
	if p, _ := cfg.Find(id); p.Name != "Yeni ad" || p.TrustedCert != "" {
		t.Fatalf("%+v", p)
	}
	if err := e.DeleteProfile(id); err != nil || len(cfg.Profiles) != 0 {
		t.Fatal(err, cfg.Profiles)
	}
	// admin lock
	cfg.LockProfiles = true
	if _, err := e.SaveProfile(ipc.ProfileEdit{Name: "x", Server: "h:1"}); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("kilit uygulanmadı: %v", err)
	}
	if r := e.Handle(ipc.Request{Op: ipc.OpProfiles}); !r.Locked {
		t.Fatal("locked bildirilmedi")
	}
}
