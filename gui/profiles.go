//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"f-forti/internal/forti"
	"f-forti/internal/ipc"
)

// ProfilesInfo is the profile list for the management view.
type ProfilesInfo struct {
	Profiles []ipc.ProfileInfo `json:"profiles"`
	Locked   bool              `json:"locked"`
}

// CertInfo describes a gateway certificate for the user to judge.
type CertInfo struct {
	Server      string `json:"server"` // normalised host:port
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotAfter    string `json:"notAfter"`
	Fingerprint string `json:"fingerprint"`
	Verified    bool   `json:"verified"` // trusted by Windows
}

// Profiles returns all profiles.
func (a *App) Profiles() (ProfilesInfo, error) {
	resp, err := a.call(ipc.Request{Op: ipc.OpProfiles}, 5*time.Second)
	if err != nil {
		return ProfilesInfo{}, friendlyErr(err)
	}
	return ProfilesInfo{Profiles: resp.Profiles, Locked: resp.Locked}, nil
}

// SaveProfile creates (empty id) or updates a profile; returns its id.
func (a *App) SaveProfile(ed ipc.ProfileEdit) (string, error) {
	srv, err := normalizeServer(ed.Server)
	if err != nil {
		return "", err
	}
	ed.Server = srv
	resp, err := a.call(ipc.Request{Op: ipc.OpProfileSet, Edit: &ed}, 10*time.Second)
	if err != nil {
		return "", friendlyErr(err)
	}
	return resp.ID, nil
}

// DeleteProfile removes a profile.
func (a *App) DeleteProfile(id string) error {
	_, err := a.call(ipc.Request{Op: ipc.OpProfileDel, Profile: id}, 10*time.Second)
	return friendlyErr(err)
}

// CheckCert connects to the server (as the current user) and reports its
// certificate, so the user can decide whether to pin it.
func (a *App) CheckCert(server string) (CertInfo, error) {
	srv, err := normalizeServer(server)
	if err != nil {
		return CertInfo{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, err := forti.FetchCert(ctx, srv)
	if err != nil {
		return CertInfo{}, errors.New("Could not reach the server: " + err.Error())
	}
	return CertInfo{
		Server:      srv,
		Subject:     p.Subject,
		Issuer:      p.Issuer,
		NotAfter:    p.NotAfter.Local().Format("Jan 2, 2006"),
		Fingerprint: p.Fingerprint,
		Verified:    p.Verified,
	}, nil
}

// normalizeServer accepts "host", "host:port" or a pasted URL.
func normalizeServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "", errors.New("Server address is required")
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		s = net.JoinHostPort(strings.Trim(s, "[]"), "443")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" || strings.ContainsAny(host, " @\\") {
		return "", errors.New("Invalid server address (example: vpn.example.com:10443)")
	}
	return s, nil
}

// capFirst upper-cases the first letter (sentence case for messages).
func capFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}
