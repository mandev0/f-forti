// Package config holds the service configuration: VPN profiles and the users
// allowed to control the service. The file lives in an admin-only directory;
// the GUI can only select a profile by ID, never define one.
package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Profile is one VPN gateway.
type Profile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Server      string `json:"server"` // host:port
	Realm       string `json:"realm,omitempty"`
	TrustedCert string `json:"trustedCert,omitempty"` // SHA-256 hex pin
	// AllowedNetworks optionally restricts which routes the gateway may push.
	AllowedNetworks []string `json:"allowedNetworks,omitempty"`
}

// Config is the whole file.
type Config struct {
	// AllowedUsers are Windows SIDs that may talk to the service pipe
	// (SYSTEM and elevated Administrators always can).
	AllowedUsers []string `json:"allowedUsers"`
	// LockProfiles forbids profile changes over the pipe (GUI); only an
	// administrator can then edit profiles with fvpn-svc.
	LockProfiles bool      `json:"lockProfiles,omitempty"`
	Profiles     []Profile `json:"profiles"`
}

// MaxProfiles bounds the number of profiles.
const MaxProfiles = 32

var (
	reID  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	reSID = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,14}$`)
)

// Validate checks every field; the service refuses to start on a bad file.
func (c *Config) Validate() error {
	for _, s := range c.AllowedUsers {
		if !reSID.MatchString(s) {
			return fmt.Errorf("invalid SID: %q", s)
		}
	}
	if len(c.Profiles) > MaxProfiles {
		return fmt.Errorf("at most %d profiles are allowed", MaxProfiles)
	}
	seen := map[string]bool{}
	for i, p := range c.Profiles {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("profile %d (%s): %w", i, p.ID, err)
		}
		if seen[p.ID] {
			return fmt.Errorf("duplicate profile id: %s", p.ID)
		}
		seen[p.ID] = true
	}
	return nil
}

// Validate checks one profile.
func (p *Profile) Validate() error {
	if !reID.MatchString(p.ID) {
		return errors.New("id must be lowercase letters/digits/-/_ (max 32)")
	}
	if len(p.Name) > 64 || strings.ContainsAny(p.Name, "\x00\r\n") {
		return errors.New("name is invalid or too long")
	}
	host, port, err := net.SplitHostPort(p.Server)
	if err != nil || host == "" || port == "" {
		return errors.New("server must be host:port")
	}
	if strings.ContainsAny(host, "/\\ @?#") || len(p.Server) > 255 {
		return errors.New("server contains invalid characters")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("invalid port")
	}
	if len(p.Realm) > 64 || strings.ContainsAny(p.Realm, "/\\ ?&#") {
		return errors.New("invalid realm")
	}
	if p.TrustedCert != "" {
		pin := strings.ReplaceAll(p.TrustedCert, ":", "")
		if b, err := hex.DecodeString(pin); err != nil || len(b) != 32 {
			return errors.New("trustedCert must be a 64-digit SHA-256 hex")
		}
	}
	for _, n := range p.AllowedNetworks {
		if _, err := netip.ParsePrefix(n); err != nil {
			return fmt.Errorf("allowedNetworks: %w", err)
		}
	}
	return nil
}

// Allowed returns AllowedNetworks parsed.
func (p *Profile) Allowed() []netip.Prefix {
	var out []netip.Prefix
	for _, n := range p.AllowedNetworks {
		if pr, err := netip.ParsePrefix(n); err == nil {
			out = append(out, pr.Masked())
		}
	}
	return out
}

// Find returns the profile with id.
func (c *Config) Find(id string) (*Profile, bool) {
	for i := range c.Profiles {
		if c.Profiles[i].ID == id {
			return &c.Profiles[i], true
		}
	}
	return nil, false
}

// Load reads and validates the file. A missing file yields an empty config.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("config file too large")
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Save validates and writes atomically. The directory ACL is the caller's
// responsibility (see the Windows installer).
func Save(path string, c *Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), ".config.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
