// Package opcli holds the pure parts of the 1Password CLI integration
// (argument building, output parsing, error cleanup) so they can be tested
// without Windows or op.exe.
package opcli

import (
	"encoding/json"
	"errors"
	"strings"
)

// Ref points at a 1Password item. It contains names only, never secrets.
type Ref struct {
	Item    string
	Vault   string
	Account string
}

// Validate rejects values op could misread as flags and other junk.
func (r Ref) Validate() error {
	for _, v := range []string{r.Item, r.Vault, r.Account} {
		if len(v) > 128 || strings.HasPrefix(v, "-") || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("invalid 1Password item, vault or account")
		}
	}
	if strings.TrimSpace(r.Item) == "" {
		return errors.New("enter the 1Password item name")
	}
	return nil
}

// Args builds "item get <item> [--vault V] [--account A] extra...".
func (r Ref) Args(extra ...string) []string {
	a := []string{"item", "get", r.Item}
	if r.Vault != "" {
		a = append(a, "--vault", r.Vault)
	}
	if r.Account != "" {
		a = append(a, "--account", r.Account)
	}
	return append(a, extra...)
}

// Config is the per-profile 1Password setting (names only, no secrets).
// Username and password come from Item. The one-time password comes from
// OTPItem when it is set, otherwise from Item too. Keeping the TOTP seed in
// another item (ideally another vault) keeps the two factors apart: access
// to one item no longer gives both.
type Config struct {
	Enabled bool   `json:"enabled"`
	Item    string `json:"item"`              // item name or ID
	Vault   string `json:"vault,omitempty"`   // optional
	Account string `json:"account,omitempty"` // optional, when several accounts are signed in

	OTPItem    string `json:"otpItem,omitempty"`
	OTPVault   string `json:"otpVault,omitempty"`
	OTPAccount string `json:"otpAccount,omitempty"`
}

// Trimmed returns c with surrounding spaces removed from every name.
func (c Config) Trimmed() Config {
	for _, p := range []*string{&c.Item, &c.Vault, &c.Account, &c.OTPItem, &c.OTPVault, &c.OTPAccount} {
		*p = strings.TrimSpace(*p)
	}
	return c
}

// CredRef points at the item with the username and password.
func (c Config) CredRef() Ref { return Ref{Item: c.Item, Vault: c.Vault, Account: c.Account} }

// SeparateOTP reports whether the one-time password lives in another item.
func (c Config) SeparateOTP() bool { return c.OTPItem != "" || c.OTPVault != "" || c.OTPAccount != "" }

// OTPRef points at the item with the one-time password.
func (c Config) OTPRef() Ref {
	if !c.SeparateOTP() {
		return c.CredRef()
	}
	return Ref{Item: c.OTPItem, Vault: c.OTPVault, Account: c.OTPAccount}
}

// Empty reports whether nothing is configured.
func (c Config) Empty() bool {
	return !c.Enabled && c.Item == "" && c.Vault == "" && c.Account == "" && !c.SeparateOTP()
}

// Validate checks both references. A disabled, empty config is valid.
func (c Config) Validate() error {
	if c.Empty() {
		return nil
	}
	if err := c.CredRef().Validate(); err != nil {
		return err
	}
	if c.SeparateOTP() {
		if err := c.OTPRef().Validate(); err != nil {
			return errors.New("one-time password: " + err.Error())
		}
		if c.OTPRef() == c.CredRef() {
			return errors.New("the one-time password item is the same as the login item")
		}
	}
	return nil
}

// Credentials is what an item provides.
type Credentials struct {
	Username string
	Password string
	HasOTP   bool
}

// ParseItem reads `op item get --format json --reveal` output.
func ParseItem(out []byte) (Credentials, error) {
	var it struct {
		Fields []struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Purpose string `json:"purpose"`
			Value   string `json:"value"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(out, &it); err != nil {
		return Credentials{}, errors.New("unexpected output from 1Password CLI")
	}
	var c Credentials
	for _, f := range it.Fields {
		switch {
		case f.Purpose == "USERNAME":
			c.Username = f.Value
		case f.Purpose == "PASSWORD":
			c.Password = f.Value
		case f.ID == "username" && c.Username == "":
			c.Username = f.Value
		case f.ID == "password" && c.Password == "":
			c.Password = f.Value
		case f.Type == "OTP":
			c.HasOTP = true
		}
	}
	return c, nil
}

// ParseOTP validates `op item get --otp` output.
func ParseOTP(out []byte) (string, error) {
	code := strings.TrimSpace(string(out))
	if code == "" || len(code) > 12 || strings.ContainsAny(code, " \t") {
		return "", errors.New("the item has no usable one-time password")
	}
	return code, nil
}

// WaitBeforeOTP returns how long to wait so a fresh code is not about to
// expire (30-second TOTP; skip the last 2 seconds of a window).
func WaitBeforeOTP(unixSec int64) int64 {
	if s := unixSec % 30; s >= 28 {
		return 30 - s
	}
	return 0
}

// ErrorText turns op's "[ERROR] 2026/11/23 19:00:00 message" into "message".
func ErrorText(stderr, fallback string) string {
	for _, l := range strings.Split(strings.TrimSpace(stderr), "\n") {
		l = strings.TrimSpace(l)
		if i := strings.Index(l, "[ERROR]"); i >= 0 {
			l = strings.TrimSpace(l[i+len("[ERROR]"):])
			if f := strings.Fields(l); len(f) > 2 && strings.Count(f[0], "/") == 2 && strings.Count(f[1], ":") == 2 {
				l = strings.Join(f[2:], " ")
			}
			return l
		}
	}
	if s := strings.TrimSpace(stderr); s != "" {
		return s
	}
	return fallback
}

// Signer holds the attributes of the certificate that actually signed op.exe.
type Signer struct {
	CN, O, C          string // subject
	IssuerCN, IssuerO string
}

// SignerOK accepts 1Password CLI signatures:
//   - current builds: Microsoft Trusted Signing (subject CN=O=Agilebits, C=CA,
//     issued by "Microsoft ID Verified CS ..." CAs, rotated frequently);
//   - older builds: classic certificate issued to "AgileBits Inc.", C=CA.
//
// The Authenticode signature and chain must already be verified by Windows.
func SignerOK(s Signer) bool {
	switch {
	case s.CN == "Agilebits" && s.O == "Agilebits" && s.C == "CA":
		return s.IssuerO == "Microsoft Corporation" && strings.HasPrefix(s.IssuerCN, "Microsoft ID Verified CS ")
	case s.CN == "AgileBits Inc." && s.O == "AgileBits Inc." && s.C == "CA":
		return true
	}
	return false
}
