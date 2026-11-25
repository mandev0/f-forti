package opcli

import (
	"strings"
	"testing"
)

// Shape of `op item get <login> --format json --reveal` (values made up).
const item = `{"id":"abc","title":"FortiVPN","category":"LOGIN","fields":[
 {"id":"username","type":"STRING","purpose":"USERNAME","label":"username","value":"jdoe","reference":"op://Vault/VPN/username"},
 {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"p,a\"ss","reference":"op://Vault/VPN/password"},
 {"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain"},
 {"id":"x1","section":{"id":"add more"},"type":"OTP","label":"one-time password","value":"otpauth://totp/x?secret=AAAA","totp":"123456"}]}`

func TestParseItem(t *testing.T) {
	c, err := ParseItem([]byte(item))
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "jdoe" || c.Password != `p,a"ss` || !c.HasOTP {
		t.Fatalf("%+v", c)
	}
	c, _ = ParseItem([]byte(`{"fields":[{"id":"username","value":"u"},{"id":"password","value":"p"}]}`))
	if c.Username != "u" || c.Password != "p" || c.HasOTP {
		t.Fatalf("fallback by id: %+v", c)
	}
	if _, err := ParseItem([]byte("not json")); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestArgsAndValidate(t *testing.T) {
	r := Ref{Item: "FortiVPN", Vault: "Private"}
	if got := strings.Join(r.Args("--otp"), " "); got != "item get FortiVPN --vault Private --otp" {
		t.Fatal(got)
	}
	for _, bad := range []Ref{{Item: ""}, {Item: "--reveal"}, {Item: "x", Vault: "-v"}, {Item: "a\nb"}, {Item: strings.Repeat("a", 200)}} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if (Ref{Item: "Forti VPN (work)", Account: "my.1password.com"}).Validate() != nil {
		t.Error("valid ref rejected")
	}
}

func TestOTP(t *testing.T) {
	if c, err := ParseOTP([]byte("123456\n")); err != nil || c != "123456" {
		t.Fatal(c, err)
	}
	if _, err := ParseOTP([]byte("\n")); err == nil {
		t.Fatal("empty accepted")
	}
	if WaitBeforeOTP(1700000010) != 0 || WaitBeforeOTP(1700000008) != 2 || WaitBeforeOTP(1700000009) != 1 {
		t.Fatal(WaitBeforeOTP(1700000008), WaitBeforeOTP(1700000009))
	}
}

func TestErrorText(t *testing.T) {
	if got := ErrorText("[ERROR] 2026/11/23 19:00:01 \"FortiVPN\" isn't an item. Specify the item with its UUID, name, or domain.\n", "x"); got != `"FortiVPN" isn't an item. Specify the item with its UUID, name, or domain.` {
		t.Fatal(got)
	}
	if got := ErrorText("[ERROR] authorization prompt dismissed, please try again", "x"); got != "authorization prompt dismissed, please try again" {
		t.Fatal(got)
	}
	if got := ErrorText("", "exit status 1"); got != "exit status 1" {
		t.Fatal(got)
	}
}

func TestSignerOK(t *testing.T) {
	// Values from op_windows_amd64_v2.42.0.zip (cache.agilebits.com).
	real := Signer{CN: "Agilebits", O: "Agilebits", C: "CA", IssuerCN: "Microsoft ID Verified CS AOC CA 03", IssuerO: "Microsoft Corporation"}
	if !SignerOK(real) {
		t.Fatal("official op.exe rejected")
	}
	other := real
	other.IssuerCN = "Microsoft ID Verified CS EOC CA 01"
	if !SignerOK(other) {
		t.Fatal("rotated Trusted Signing CA rejected")
	}
	legacy := Signer{CN: "AgileBits Inc.", O: "AgileBits Inc.", C: "CA", IssuerCN: "DigiCert EV Code Signing CA (SHA2)", IssuerO: "DigiCert Inc"}
	if !SignerOK(legacy) {
		t.Fatal("legacy signature rejected")
	}
	for _, bad := range []Signer{
		{CN: "Agilebits", O: "Evil Corp", C: "CA", IssuerCN: real.IssuerCN, IssuerO: real.IssuerO},
		{CN: "Agilebits", O: "Agilebits", C: "US", IssuerCN: real.IssuerCN, IssuerO: real.IssuerO},
		{CN: "Agilebits", O: "Agilebits", C: "CA", IssuerCN: "Some Other CA", IssuerO: "Sectigo"},
		{CN: "agilebits", O: "agilebits", C: "CA", IssuerCN: real.IssuerCN, IssuerO: real.IssuerO},
		{CN: "AgileBits Inc.", O: "Someone", C: "CA"},
	} {
		if SignerOK(bad) {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestConfig(t *testing.T) {
	c := Config{Enabled: true, Item: " VPN ", Vault: "Work"}.Trimmed()
	if c.Item != "VPN" || c.SeparateOTP() || c.OTPRef() != c.CredRef() {
		t.Fatalf("single item: %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.OTPItem, c.OTPVault = "VPN code", "Codes"
	if !c.SeparateOTP() || c.OTPRef() != (Ref{Item: "VPN code", Vault: "Codes"}) {
		t.Fatalf("separate: %+v", c.OTPRef())
	}
	if got := strings.Join(c.OTPRef().Args("--otp"), " "); got != "item get VPN code --vault Codes --otp" {
		t.Fatal(got)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Config{
		{Enabled: true, Item: "VPN", OTPVault: "Codes"},                         // vault without item
		{Enabled: true, Item: "VPN", OTPItem: "--reveal"},                       // flag injection
		{Enabled: true, Item: "VPN", Vault: "W", OTPItem: "VPN", OTPVault: "W"}, // same item twice
		{Enabled: true, Item: "", OTPItem: "code"},                              // no login item
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if !(Config{}).Empty() || (Config{}).Validate() != nil {
		t.Error("empty config must be valid")
	}
}
