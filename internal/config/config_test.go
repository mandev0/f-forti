package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	good := Profile{ID: "main", Name: "Örnek", Server: "vpn.example.com:10443", TrustedCert: strings.Repeat("ab", 32)}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Profile{
		{ID: "Main", Server: "a:1"},
		{ID: "x", Server: "noport"},
		{ID: "x", Server: "user@host:1"},
		{ID: "x", Server: "h:1", TrustedCert: "abcd"},
		{ID: "x", Server: "h:1", Realm: "a/b"},
		{ID: "x", Server: "h:1", AllowedNetworks: []string{"198.18.0.0"}},
	} {
		if bad.Validate() == nil {
			t.Errorf("kabul edilmemeliydi: %+v", bad)
		}
	}
	c := Config{AllowedUsers: []string{"S-1-5-21-1-2-3-1001"}, Profiles: []Profile{good, good}}
	if c.Validate() == nil {
		t.Error("tekrarlanan id kabul edildi")
	}
	c.AllowedUsers = []string{"Everyone"}
	c.Profiles = c.Profiles[:1]
	if c.Validate() == nil {
		t.Error("SID olmayan kullanıcı kabul edildi")
	}
}

func TestLoadSave(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c, err := Load(p)
	if err != nil || len(c.Profiles) != 0 {
		t.Fatal(c, err)
	}
	c.Profiles = []Profile{{ID: "main", Server: "h:443"}}
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(p)
	if err != nil || c2.Profiles[0].Server != "h:443" {
		t.Fatal(c2, err)
	}
	os.WriteFile(p, []byte(`{"profiles":[],"extra":1}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("bilinmeyen alan kabul edildi")
	}
}
