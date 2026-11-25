// Package engine is the connection state machine of the service:
// login → (2FA) → tunnel → PPP → network plan → OS network → bridge, and the
// reverse on disconnect or failure. It is OS independent; the OS network
// backend is injected.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"f-forti/internal/config"
	"f-forti/internal/forti"
	"f-forti/internal/ipc"
	"f-forti/internal/netcfg"
	"f-forti/internal/ppp"
	"f-forti/internal/tunnel"
	"f-forti/internal/vpn"
)

// Network is the OS backend (winnet on Windows).
type Network interface {
	Up(cfg *netcfg.Config) (tun.Device, []string, error)
	Down() error
}

// Options configure the engine.
type Options struct {
	Network  Network
	Config   func() (*config.Config, error) // re-read on each connect
	Save     func(*config.Config) error     // persists profile edits; nil = read-only
	Logf     func(string, ...any)
	Echo     time.Duration // LCP echo after silence; 0 = off
	Pending  time.Duration // how long a 2FA prompt stays valid
	LoginTTL time.Duration // timeout for one login/2FA HTTP exchange
}

// Engine is safe for concurrent use.
type Engine struct {
	opt   Options
	cfgMu sync.Mutex // serialises profile edits

	mu       sync.Mutex
	st       ipc.Status
	client   *forti.Client
	chal     *forti.Challenge
	chalT    *time.Timer
	profile  *config.Profile
	cancel   context.CancelFunc
	sessDone chan struct{}
	link     *ppp.Link
	userStop bool
}

// New creates an idle engine.
func New(opt Options) *Engine {
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.Pending == 0 {
		opt.Pending = 3 * time.Minute
	}
	if opt.LoginTTL == 0 {
		opt.LoginTTL = 90 * time.Second
	}
	return &Engine{opt: opt, st: ipc.Status{State: ipc.StateIdle}}
}

// Handle dispatches a validated IPC request.
func (e *Engine) Handle(r ipc.Request) ipc.Response {
	switch r.Op {
	case ipc.OpStatus:
		s := e.Status()
		return ipc.Response{OK: true, Status: &s}
	case ipc.OpProfiles:
		cfg, err := e.opt.Config()
		if err != nil {
			return ipc.Response{Error: "cannot read the profile file"}
		}
		var out []ipc.ProfileInfo
		for _, p := range cfg.Profiles {
			out = append(out, ipc.ProfileInfo{ID: p.ID, Name: p.Name, Server: p.Server, Realm: p.Realm, TrustedCert: p.TrustedCert})
		}
		return ipc.Response{OK: true, Profiles: out, Locked: cfg.LockProfiles || e.opt.Save == nil}
	case ipc.OpProfileSet:
		id, err := e.SaveProfile(*r.Edit)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		return ipc.Response{OK: true, ID: id}
	case ipc.OpProfileDel:
		if err := e.DeleteProfile(r.Profile); err != nil {
			return ipc.Response{Error: err.Error()}
		}
		return ipc.Response{OK: true}
	case ipc.OpConnect:
		return e.reply(e.Connect(r.Profile, r.Username, r.Password))
	case ipc.OpSubmit2FA:
		return e.reply(e.Submit2FA(r.Code))
	case ipc.OpDisconnect:
		e.Disconnect()
		return e.reply(nil)
	}
	return ipc.Response{Error: "unsupported operation"}
}

func (e *Engine) reply(err error) ipc.Response {
	s := e.Status()
	if err != nil {
		return ipc.Response{Error: err.Error(), Status: &s}
	}
	return ipc.Response{OK: true, Status: &s}
}

// Status returns a snapshot (with live counters).
func (e *Engine) Status() ipc.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.st
	s.Warnings = append([]string(nil), s.Warnings...)
	s.DNSRules = append([]string(nil), s.DNSRules...)
	if e.link != nil {
		st := e.link.Stats()
		s.RxBytes, s.TxBytes = st.RxBytes, st.TxBytes
	}
	return s
}

func (e *Engine) busy() bool {
	switch e.st.State {
	case ipc.StateIdle, ipc.StateError:
		return false
	}
	return true
}

// Connect starts a session. It returns once the password step is done:
// state is then need_2fa, connecting, or error.
func (e *Engine) Connect(profileID, user, pass string) error {
	cfg, err := e.opt.Config()
	if err != nil {
		return errors.New("cannot read the profile file")
	}
	p, ok := cfg.Find(profileID)
	if !ok {
		return fmt.Errorf("profile not found: %s", profileID)
	}
	prof := *p

	e.mu.Lock()
	if e.busy() {
		e.mu.Unlock()
		return fmt.Errorf("busy: %s", e.st.State)
	}
	c, err := forti.New(forti.Config{Server: prof.Server, Realm: prof.Realm, TrustedCert: prof.TrustedCert})
	if err != nil {
		e.mu.Unlock()
		return err
	}
	e.client, e.profile, e.chal = c, &prof, nil
	e.st = ipc.Status{State: ipc.StateConnecting, Profile: prof.ID, Username: user, Message: "Signing in"}
	e.mu.Unlock()

	e.opt.Logf("connect: profile %s, user %s, server %s", prof.ID, user, prof.Server)
	ctx, cancel := context.WithTimeout(context.Background(), e.opt.LoginTTL)
	ch, err := c.Login(ctx, user, pass)
	cancel()
	return e.afterAuth(c, ch, err)
}

// Submit2FA answers the pending challenge.
func (e *Engine) Submit2FA(code string) error {
	e.mu.Lock()
	if e.st.State != ipc.StateNeed2FA || e.chal == nil {
		e.mu.Unlock()
		return errors.New("no pending verification request")
	}
	c, ch, user := e.client, e.chal, e.st.Username
	e.chal = nil
	if e.chalT != nil {
		e.chalT.Stop()
	}
	e.st.State, e.st.Message = ipc.StateConnecting, "Verifying code"
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), e.opt.LoginTTL)
	next, err := c.Submit2FA(ctx, ch, user, code, false)
	cancel()
	return e.afterAuth(c, next, err)
}

func (e *Engine) afterAuth(c *forti.Client, ch *forti.Challenge, err error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client != c || e.st.State != ipc.StateConnecting {
		if err == nil && ch == nil { // logged in after the user gave up
			go func() {
				lctx, lc := context.WithTimeout(context.Background(), 5*time.Second)
				defer lc()
				c.Logout(lctx)
			}()
		}
		return errors.New("operation cancelled")
	}
	if err != nil {
		msg := err.Error()
		var ce *forti.CertError
		switch {
		case errors.Is(err, forti.ErrAuthFailed):
			msg = "Invalid username, password or code"
		case errors.Is(err, forti.ErrCodeRejected):
			msg = "The gateway rejected the verification code. A code can be used only once; wait for the next one and try again"
		case errors.As(err, &ce):
			msg = "Server certificate could not be verified (sha256 " + ce.Fingerprint + ")"
		}
		e.opt.Logf("authentication error: %v", err)
		e.failLocked(msg)
		return errors.New(msg)
	}
	if ch != nil {
		e.chal = ch
		e.st.State, e.st.Message = ipc.StateNeed2FA, ch.Message
		e.chalT = time.AfterFunc(e.opt.Pending, func() {
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.client == c && e.st.State == ipc.StateNeed2FA {
				e.opt.Logf("verification code timed out")
				e.failLocked("The verification code was not entered in time")
			}
		})
		e.opt.Logf("verification code requested")
		return nil
	}
	e.opt.Logf("authenticated")
	e.st.Message = "Setting up tunnel"
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.sessDone = make(chan struct{})
	e.userStop = false
	go e.run(ctx, c, *e.profile, e.sessDone)
	return nil
}

func (e *Engine) failLocked(msg string) {
	e.st = ipc.Status{State: ipc.StateError, Profile: e.st.Profile, Username: e.st.Username, LastError: msg}
	e.client, e.chal, e.link = nil, nil, nil
}

// run owns one established session until it ends.
func (e *Engine) run(ctx context.Context, c *forti.Client, prof config.Profile, done chan struct{}) {
	defer close(done)
	var (
		link  *ppp.Link
		dev   tun.Device
		netUp bool
	)
	teardown := func() {
		if link != nil {
			link.Close()
		}
		if netUp {
			if err := e.opt.Network.Down(); err != nil {
				e.opt.Logf("network teardown: %v", err)
			}
		}
		lctx, lc := context.WithTimeout(context.Background(), 5*time.Second)
		if err := c.Logout(lctx); err != nil {
			e.opt.Logf("logout: %v", err)
		}
		lc()
	}
	finish := func(err error) {
		teardown()
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.userStop || err == nil {
			e.opt.Logf("connection closed")
			e.st = ipc.Status{State: ipc.StateIdle}
		} else {
			e.opt.Logf("connection error: %v", err)
			e.failLocked(err.Error())
		}
		e.client, e.link, e.cancel = nil, nil, nil
	}

	step := func(msg string) {
		e.mu.Lock()
		e.st.Message = msg
		e.mu.Unlock()
	}

	sctx, scancel := context.WithTimeout(ctx, 45*time.Second)
	defer scancel()

	step("Fetching tunnel settings")
	_, tc, err := c.TunnelConfig(sctx)
	if err != nil {
		finish(fmt.Errorf("Could not fetch tunnel settings: %w", err))
		return
	}
	step("Opening tunnel")
	conn, err := c.DialTunnel(sctx)
	if err != nil {
		finish(fmt.Errorf("Could not open the tunnel: %w", err))
		return
	}
	gw := remoteIP(conn)
	link, err = ppp.Start(sctx, tunnel.New(conn), ppp.Config{Logf: e.opt.Logf, EchoInterval: e.opt.Echo})
	if err != nil {
		finish(fmt.Errorf("PPP negotiation failed: %w", err))
		return
	}
	info := link.Info()
	pol := netcfg.DefaultPolicy
	pol.Allowed = prof.Allowed()
	plan, err := netcfg.Build(tc, info, gw, pol)
	if err != nil {
		finish(err)
		return
	}
	step("Configuring network")
	dev, warns, err := e.opt.Network.Up(plan)
	netUp = true // Down is safe even if Up rolled back
	if err != nil {
		finish(err)
		return
	}
	warns = append(plan.Warnings, warns...)
	for _, w := range warns {
		e.opt.Logf("warning: %s", w)
	}

	bctx, bcancel := context.WithCancel(ctx)
	defer bcancel()
	bridgeErr := make(chan error, 1)
	go func() { bridgeErr <- vpn.Bridge(bctx, dev, link) }()

	var dns []string
	for _, r := range plan.DNSRules {
		srv := make([]string, len(r.Servers))
		for i, s := range r.Servers {
			srv[i] = s.String()
		}
		unit := "domains"
		if len(r.Domains) == 1 {
			unit = "domain"
		}
		dns = append(dns, fmt.Sprintf("%s · %d %s", strings.Join(srv, ", "), len(r.Domains), unit))
	}
	now := time.Now()
	e.mu.Lock()
	e.link = link
	e.st.State, e.st.Message = ipc.StateConnected, ""
	e.st.LocalIP = info.LocalIP.String()
	e.st.Since = now
	if s, err := strconv.Atoi(tc.AuthTimeout.Val); err == nil && s > 0 {
		e.st.ExpiresAt = now.Add(time.Duration(s) * time.Second)
	}
	e.st.Routes = len(plan.Routes)
	e.st.DNSRules = dns
	e.st.Warnings = warns
	e.mu.Unlock()
	e.opt.Logf("connected: IP %s, %d routes, %d DNS rules", info.LocalIP, len(plan.Routes), len(plan.DNSRules))

	select {
	case <-ctx.Done():
		finish(nil)
	case <-link.Done():
		finish(fmt.Errorf("Tunnel closed: %w", link.Err()))
	case err := <-bridgeErr:
		finish(fmt.Errorf("Packet bridge stopped: %w", err))
	}
}

// Disconnect ends any pending or active session and waits for cleanup.
func (e *Engine) Disconnect() {
	e.mu.Lock()
	switch e.st.State {
	case ipc.StateNeed2FA:
		if e.chalT != nil {
			e.chalT.Stop()
		}
		e.opt.Logf("cancelled while waiting for the verification code")
		e.st = ipc.Status{State: ipc.StateIdle}
		e.client, e.chal = nil, nil
		e.mu.Unlock()
		return
	case ipc.StateError:
		e.st = ipc.Status{State: ipc.StateIdle}
		e.mu.Unlock()
		return
	}
	cancel, done := e.cancel, e.sessDone
	if cancel == nil {
		// connecting but still in the login HTTP exchange: mark it so
		// afterAuth discards the result.
		if e.st.State == ipc.StateConnecting {
			e.st = ipc.Status{State: ipc.StateIdle}
			e.client = nil
		}
		e.mu.Unlock()
		return
	}
	e.userStop = true
	e.st.State, e.st.Message = ipc.StateDisconnecting, "Disconnecting"
	e.mu.Unlock()

	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		e.opt.Logf("disconnect timed out")
	}
}

func remoteIP(c net.Conn) netip.Addr {
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// SaveProfile creates (empty ID) or updates a profile and returns its ID.
func (e *Engine) SaveProfile(ed ipc.ProfileEdit) (string, error) {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	cfg, err := e.editableConfig()
	if err != nil {
		return "", err
	}
	p := config.Profile{
		ID:          ed.ID,
		Name:        strings.TrimSpace(ed.Name),
		Server:      strings.TrimSpace(ed.Server),
		Realm:       strings.TrimSpace(ed.Realm),
		TrustedCert: strings.ToLower(strings.ReplaceAll(strings.TrimSpace(ed.TrustedCert), ":", "")),
	}
	if p.Name == "" {
		return "", errors.New("Profile name is required")
	}
	idx := -1
	if p.ID == "" {
		p.ID = newProfileID(cfg)
	} else {
		for i := range cfg.Profiles {
			if cfg.Profiles[i].ID == p.ID {
				idx = i
			}
		}
		if idx < 0 {
			return "", errors.New("Profile not found")
		}
		if e.inUse(p.ID) {
			return "", errors.New("This profile cannot be changed while it is in use")
		}
		p.AllowedNetworks = cfg.Profiles[idx].AllowedNetworks // admin-only field
	}
	if err := p.Validate(); err != nil {
		return "", fmt.Errorf("Invalid profile: %w", err)
	}
	if idx >= 0 {
		cfg.Profiles[idx] = p
	} else {
		cfg.Profiles = append(cfg.Profiles, p)
	}
	if err := e.opt.Save(cfg); err != nil {
		return "", fmt.Errorf("Could not save the profile: %w", err)
	}
	e.opt.Logf("profile saved: %s (%s, server %s, pinned %v)", p.ID, p.Name, p.Server, p.TrustedCert != "")
	return p.ID, nil
}

// DeleteProfile removes a profile that is not in use.
func (e *Engine) DeleteProfile(id string) error {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	cfg, err := e.editableConfig()
	if err != nil {
		return err
	}
	if e.inUse(id) {
		return errors.New("This profile cannot be deleted while it is in use")
	}
	n := len(cfg.Profiles)
	cfg.Profiles = slices.DeleteFunc(cfg.Profiles, func(p config.Profile) bool { return p.ID == id })
	if len(cfg.Profiles) == n {
		return errors.New("Profile not found")
	}
	if err := e.opt.Save(cfg); err != nil {
		return fmt.Errorf("Could not delete the profile: %w", err)
	}
	e.opt.Logf("profile deleted: %s", id)
	return nil
}

func (e *Engine) editableConfig() (*config.Config, error) {
	if e.opt.Save == nil {
		return nil, errors.New("Profiles cannot be changed in this installation")
	}
	cfg, err := e.opt.Config()
	if err != nil {
		return nil, errors.New("Cannot read the profile file")
	}
	if cfg.LockProfiles {
		return nil, errors.New("Profiles are locked by an administrator")
	}
	return cfg, nil
}

func (e *Engine) inUse(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.busy() && e.st.Profile == id
}

func newProfileID(cfg *config.Config) string {
	for {
		var b [4]byte
		rand.Read(b[:])
		id := "p" + hex.EncodeToString(b[:])
		if _, exists := cfg.Find(id); !exists {
			return id
		}
	}
}
