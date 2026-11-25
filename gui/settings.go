//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Settings are per-user GUI conveniences. Only usernames are remembered:
// the gateway policy says save-password=off, and passwords never touch disk.
type Settings struct {
	mu          sync.Mutex
	path        string
	LastProfile string            `json:"lastProfile"`
	Users       map[string]string `json:"users"`
	// AutostartInit: the first-run autostart default has been applied (or
	// the user chose); never re-enable behind the user's back.
	AutostartInit bool `json:"autostartInit"`
	// OP holds per-profile 1Password references (item/vault/account names,
	// never secrets).
	OP map[string]OPConfig `json:"onePassword,omitempty"`
	// OPOn turns the 1Password integration on. Off by default; nil means
	// "never chosen" (settings from before the switch existed).
	OPOn *bool `json:"onePasswordOn,omitempty"`
}

// OnePasswordOn reports whether the 1Password integration is on. Users who
// set up 1Password before the switch existed keep it on.
func (s *Settings) OnePasswordOn() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.OPOn != nil {
		return *s.OPOn
	}
	for _, c := range s.OP {
		if c.Enabled {
			return true
		}
	}
	return false
}

// SetOnePasswordOn turns the 1Password integration on or off.
func (s *Settings) SetOnePasswordOn(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.OPOn = &on
	s.saveLocked()
}

// OnePassword returns the 1Password settings of a profile.
func (s *Settings) OnePassword(profile string) OPConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.OP[profile]
}

// OnePasswordAll returns a copy of all 1Password settings.
func (s *Settings) OnePasswordAll() map[string]OPConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]OPConfig, len(s.OP))
	for k, v := range s.OP {
		out[k] = v
	}
	return out
}

// SetOnePassword stores (or with an empty item, removes) a profile's settings.
func (s *Settings) SetOnePassword(profile string, c OPConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(profile) > 32 {
		return
	}
	if s.OP == nil {
		s.OP = map[string]OPConfig{}
	}
	if c.Empty() {
		delete(s.OP, profile)
	} else {
		s.OP[profile] = c
	}
	s.saveLocked()
}

func LoadSettings() *Settings {
	s := &Settings{Users: map[string]string{}}
	dir, err := os.UserConfigDir()
	if err != nil {
		return s
	}
	s.path = filepath.Join(dir, "FVPN", "gui.json")
	if b, err := os.ReadFile(s.path); err == nil && len(b) < 64<<10 {
		_ = json.Unmarshal(b, s)
		if s.Users == nil {
			s.Users = map[string]string{}
		}
	}
	return s
}

// Remember stores the last profile and its username.
func (s *Settings) Remember(profile, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(profile) > 32 || len(user) > 128 {
		return
	}
	s.LastProfile = profile
	s.Users[profile] = user
	s.saveLocked()
}

// MarkAutostartInit records that the autostart default was applied.
func (s *Settings) MarkAutostartInit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AutostartInit = true
	s.saveLocked()
}

func (s *Settings) saveLocked() {
	if s.path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.path), 0o700)
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(s.path, b, 0o600)
}
