package forti

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

const testXML = `<?xml version="1.0" encoding="utf-8"?>
<sslvpn-tunnel ver="2" dtls="1" patch="1">
<tunnel-method value="ppp"/><tunnel-method value="tun"/>
<fos platform="FG100F" major="7" minor="04" patch="4" build="2662" branch="2662"/>
<auth-ses check-src-ip="true" tun-connect-without-reauth="false" tun-user-ses-timeout="30"/>
<ipv4><dns ip="198.18.1.53"/><dns-suffix>example.test</dns-suffix>
<split-dns domains="example.test,example.internal" dnsserver1="198.18.1.53" dnsserver2=""/>
<assigned-addr ipv4="192.0.2.10"/>
<split-tunnel-info><addr ip="198.18.0.0" mask="255.255.0.0"/><addr ip="198.51.100.0" mask="255.255.255.0"/></split-tunnel-info>
</ipv4>
<idle-timeout val="300"/><auth-timeout val="28800"/>
</sslvpn-tunnel>`

func fakeGate(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/remote/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><form>realm</form></html>`)
	})
	mux.HandleFunc("/remote/logincheck", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		switch {
		case r.Form.Get("credential") == "pw" && r.Form.Get("username") == "u":
			fmt.Fprint(w, "ret=2,reqid=42,polid=1-1-1,grp=vpn,portal=full,magic=1-abc,tokeninfo=ftm_push,chal_msg=Enter code, please")
		case r.Form.Get("reqid") == "42" && r.Form.Get("magic") == "1-abc" && r.Form.Get("code") == "123456":
			http.SetCookie(w, &http.Cookie{Name: "SVPNCOOKIE", Value: "sess", Path: "/", Secure: true})
			fmt.Fprint(w, "ret=1,redir=/remote/fortisslvpn_xml")
		default:
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "ret=0,redir=/remote/login")
		}
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if ck, err := r.Cookie("SVPNCOOKIE"); err != nil || ck.Value != "sess" {
				http.Error(w, "no", http.StatusForbidden)
				return
			}
			h(w, r)
		}
	}
	ok := func(w http.ResponseWriter, r *http.Request) {}
	mux.HandleFunc("/remote/index", authed(ok))
	mux.HandleFunc("/remote/fortisslvpn", authed(ok))
	mux.HandleFunc("/remote/fortisslvpn_xml", authed(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, testXML)
	}))
	mux.HandleFunc("/remote/logout", authed(ok))
	return httptest.NewTLSServer(mux)
}

func pinOf(s *httptest.Server) string {
	sum := sha256.Sum256(s.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func TestUnpinnedSelfSignedRejected(t *testing.T) {
	s := fakeGate(t)
	defer s.Close()
	c, _ := New(Config{Server: s.Listener.Addr().String()})
	_, _, err := c.LoginPage(context.Background())
	var ce *CertError
	if !errors.As(err, &ce) {
		t.Fatalf("CertError bekleniyordu, gelen: %v", err)
	}
	if ce.Fingerprint != pinOf(s) {
		t.Fatalf("fingerprint yanlış")
	}
}

func TestWrongPinRejected(t *testing.T) {
	s := fakeGate(t)
	defer s.Close()
	c, _ := New(Config{Server: s.Listener.Addr().String(), TrustedCert: strings.Repeat("00", 32)})
	if _, _, err := c.LoginPage(context.Background()); err == nil {
		t.Fatal("yanlış pin kabul edildi")
	}
}

func TestFullFlow(t *testing.T) {
	s := fakeGate(t)
	defer s.Close()
	ctx := context.Background()
	c, _ := New(Config{Server: s.Listener.Addr().String(), TrustedCert: pinOf(s)})

	if _, err := c.Login(ctx, "u", "bad"); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("hatalı şifre: %v", err)
	}
	ch, err := c.Login(ctx, "u", "pw")
	if err != nil || ch == nil {
		t.Fatalf("challenge bekleniyordu: %v %v", ch, err)
	}
	if !ch.PushAvailable() || ch.Message != "Enter code, please" {
		t.Fatalf("challenge çözümü yanlış: %+v", ch.Fields)
	}
	if _, err := c.Submit2FA(ctx, ch, "u", "000000", false); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("hatalı kod: %v", err)
	}
	ch2, err := c.Submit2FA(ctx, ch, "u", "123456", false)
	if err != nil || ch2 != nil {
		t.Fatalf("2FA başarısız: %v %v", ch2, err)
	}
	if c.SessionCookie() != "sess" {
		t.Fatal("cookie yok")
	}
	_, tc, err := c.TunnelConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	routes, bad := tc.Routes()
	if len(bad) != 0 || len(routes) != 2 || routes[0].String() != "198.18.0.0/16" || routes[1].String() != "198.51.100.0/24" {
		t.Fatalf("rotalar: %v %v", routes, bad)
	}
	if d := tc.SplitDomains(); len(d) != 2 || d[1] != "example.internal" {
		t.Fatalf("split dns: %v", d)
	}
	if tc.IPv4.Assigned.IP != "192.0.2.10" || len(tc.Methods) != 2 || tc.FOS.Minor != "04" {
		t.Fatalf("xml: %+v", tc)
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestParseRet(t *testing.T) {
	m := parseRet("ret=2,reqid=1,chal_msg=a, b=c, d")
	if m["ret"] != "2" || m["reqid"] != "1" {
		t.Fatal(m)
	}
	// "b" looks like a key, so it is split off; acceptable, but chal_msg keeps "a".
	if !strings.HasPrefix(m["chal_msg"], "a") {
		t.Fatal(m)
	}
}

func TestCompactPrefixes(t *testing.T) {
	var in []netip.Prefix
	for _, s := range []string{"198.18.0.0/15", "198.18.1.3/32", "198.18.1.3/32", "198.51.100.64/26", "198.51.100.0/24", "203.0.113.4/31", "203.0.113.5/32", "8.8.8.8/32", "8.8.8.8/32"} {
		in = append(in, netip.MustParsePrefix(s))
	}
	got := CompactPrefixes(in)
	want := []string{"8.8.8.8/32", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.4/31"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v", got)
		}
	}
}

func TestDNSDomainAttr(t *testing.T) {
	var tc TunnelConfig
	x := `<sslvpn-tunnel><ipv4><dns domain='a.local;b.local'/><dns ip='198.18.0.1'/><dns ip='198.18.0.2'/></ipv4></sslvpn-tunnel>`
	if err := xml.Unmarshal([]byte(x), &tc); err != nil {
		t.Fatal(err)
	}
	if s := tc.DNSServers(); len(s) != 2 || s[0] != "198.18.0.1" {
		t.Fatalf("dns: %v", s)
	}
	if d := tc.SearchDomains(); len(d) != 2 || d[1] != "b.local" {
		t.Fatalf("search: %v", d)
	}
}

func TestRejectedCodeHTML(t *testing.T) {
	page := `<!DOCTYPE html><html><head><meta http-equiv="Pragma" content="no-cache"><title>Error</title>
<script>var x = 1;</script><style>p{}</style></head><body><form><input type="hidden" name="magic" value="SECRET-MAGIC">
<p>Token code already used, &amp; please wait.</p></form></body></html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/remote/login", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/remote/logincheck", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("credential") == "pw" {
			fmt.Fprint(w, "ret=2,reqid=1,polid=1,grp=g,magic=m,chal_msg=code")
			return
		}
		fmt.Fprint(w, page) // code step answered with an HTML page
	})
	s := httptest.NewTLSServer(mux)
	defer s.Close()
	c, _ := New(Config{Server: s.Listener.Addr().String(), TrustedCert: pinOf(s)})
	ch, err := c.Login(context.Background(), "u", "pw")
	if err != nil || ch == nil {
		t.Fatal(ch, err)
	}
	_, err = c.Submit2FA(context.Background(), ch, "u", "123456", false)
	if !errors.Is(err, ErrCodeRejected) {
		t.Fatalf("ErrCodeRejected expected: %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "SECRET-MAGIC") || strings.Contains(msg, "<") || strings.Contains(msg, "var x") {
		t.Fatalf("summary leaks markup or hidden values: %s", msg)
	}
	if !strings.Contains(msg, "Error – Token code already used, & please wait.") {
		t.Fatalf("summary: %s", msg)
	}
}

func TestUnexpectedPasswordStep(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/remote/login", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/remote/logincheck", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><head><title>Maintenance</title></head><body>Back soon</body></html>")
	})
	s := httptest.NewTLSServer(mux)
	defer s.Close()
	c, _ := New(Config{Server: s.Listener.Addr().String(), TrustedCert: pinOf(s)})
	_, err := c.Login(context.Background(), "u", "pw")
	var ue *UnexpectedResponseError
	if !errors.As(err, &ue) || errors.Is(err, ErrCodeRejected) || ue.Summary != "Maintenance – Back soon" {
		t.Fatalf("%v", err)
	}
}
