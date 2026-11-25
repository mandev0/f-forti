//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"f-forti/internal/config"
	"f-forti/internal/ipc"
)

const (
	appDir = "FVPN"
	// SHA-256 of wintun.dll (amd64) from wintun-0.14.1.zip, whose own hash
	// 07c25618…ef51 matches www.wintun.net; signed by WireGuard LLC.
	wintunSHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
	// Data dir: owner Administrators, only SYSTEM and Administrators, no
	// inheritance from ProgramData (where users may create files).
	dataDirSDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

func dataDir() (string, error) {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(pd, appDir), nil
}

func configPath(dir string) string { return filepath.Join(dir, "config.json") }
func logPath(dir string) string    { return filepath.Join(dir, "fvpn.log") }

// checkDataDir refuses to run on a data dir not owned by SYSTEM/Administrators
// (e.g. pre-created by an unprivileged user to plant a config).
func checkDataDir(dir string) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read %s (is FVPN installed?): %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	sys, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	adm, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if !owner.Equals(sys) && !owner.Equals(adm) {
		return fmt.Errorf("%s is owned by an unexpected account (%s); refusing to use it", dir, owner)
	}
	return nil
}

// prepareDataDir creates the data dir (or validates an existing one) and
// enforces the restrictive ACL on it and everything below.
func prepareDataDir(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		if err := checkDataDir(dir); err != nil {
			return fmt.Errorf("%w — inspect and delete the folder, then run install again", err)
		}
		if fi, _ := os.Lstat(dir); fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a link (symlink/junction); refused", dir)
		}
	} else if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func resolveUser(name string) (string, error) {
	if name == "" {
		u, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return "", err
		}
		return u.User.Sid.String(), nil
	}
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return "", fmt.Errorf("user not found %q: %w", name, err)
	}
	return sid.String(), nil
}

func sidName(s string) string {
	sid, err := windows.StringToSid(s)
	if err != nil {
		return s
	}
	acc, dom, _, err := sid.LookupAccount("")
	if err != nil {
		return s
	}
	return dom + `\` + acc
}

func stopService(s *mgr.Service) {
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return
	}
	s.Control(svc.Stop)
	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
	}
}

// cmdMSIConfigure is run by the MSI (deferred, as SYSTEM) after Windows
// Installer has copied the files and registered the service, before it starts
// it: verifies wintun.dll, prepares the locked-down data dir, adds the allowed
// user and sets the recovery actions. A non-zero exit rolls the install back.
func cmdMSIConfigure(args []string) error {
	fs := flag.NewFlagSet("msi-configure", flag.ExitOnError)
	allow := fs.String("allow", "", `user allowed to use the service (default: the signed-in user), e.g. DOMAIN\name`)
	fs.Parse(args)
	if err := requireElevated(); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if sum, err := fileSHA256(filepath.Join(filepath.Dir(self), "wintun.dll")); err != nil {
		return err
	} else if sum != wintunSHA256 {
		return fmt.Errorf("wintun.dll is not the expected build (sha256 %s)", sum)
	}

	data, err := dataDir()
	if err != nil {
		return err
	}
	if err := prepareDataDir(data); err != nil {
		return err
	}
	cfg, err := config.Load(configPath(data))
	if err != nil {
		return err
	}
	sid, err := installUser(*allow)
	switch {
	case err != nil && *allow != "":
		return err
	case err != nil:
		// e.g. deployed before anyone signed in: not fatal, add later with
		// "fvpn-svc allow-user DOMAIN\name".
		fmt.Fprintln(os.Stderr, "warning: no allowed user added:", err)
	case !slices.Contains(cfg.AllowedUsers, sid):
		cfg.AllowedUsers = append(cfg.AllowedUsers, sid)
		fmt.Printf("allowed user: %s (%s)\n", sidName(sid), sid)
	}
	if err := config.Save(configPath(data), cfg); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ipc.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 3600)
}

// installUser picks the account that gets access to the service. The MSI
// runs this as SYSTEM, so "the current user" is useless here; take the user
// signed in at the console (with over-the-shoulder UAC that is the standard
// user, not the admin who typed the credentials), else any active session.
func installUser(name string) (string, error) {
	if name != "" {
		return resolveUser(name)
	}
	sessions := []uint32{windows.WTSGetActiveConsoleSessionId()}
	var info *windows.WTS_SESSION_INFO
	var n uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &info, &n) == nil {
		for _, si := range unsafe.Slice(info, n) {
			if si.State == windows.WTSActive {
				sessions = append(sessions, si.SessionID)
			}
		}
		windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	}
	for _, id := range sessions {
		var tok windows.Token
		if windows.WTSQueryUserToken(id, &tok) != nil {
			continue
		}
		u, err := tok.GetTokenUser()
		tok.Close()
		if err == nil {
			return u.User.Sid.String(), nil
		}
	}
	return "", errors.New("no signed-in user found")
}

func loadForEdit() (string, *config.Config, error) {
	if err := requireElevated(); err != nil {
		return "", nil, err
	}
	d, err := dataDir()
	if err != nil {
		return "", nil, err
	}
	if err := checkDataDir(d); err != nil {
		return "", nil, err
	}
	p := configPath(d)
	c, err := config.Load(p)
	return p, c, err
}

func cmdProfileAdd(args []string) error {
	fs := flag.NewFlagSet("profile-add", flag.ExitOnError)
	var p config.Profile
	var nets string
	fs.StringVar(&p.ID, "id", "", "profile id (lowercase)")
	fs.StringVar(&p.Name, "name", "", "display name")
	fs.StringVar(&p.Server, "server", "", "host:port")
	fs.StringVar(&p.Realm, "realm", "", "realm (if any)")
	fs.StringVar(&p.TrustedCert, "trusted-cert", "", "server certificate SHA-256")
	fs.StringVar(&nets, "allowed-networks", "", "optional: networks the gateway may push (CIDR,CIDR)")
	fs.Parse(args)
	p.AllowedNetworks = splitCSV(nets)
	if p.Name == "" {
		p.Name = p.ID
	}
	path, c, err := loadForEdit()
	if err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	c.Profiles = slices.DeleteFunc(c.Profiles, func(x config.Profile) bool { return x.ID == p.ID })
	c.Profiles = append(c.Profiles, p)
	if err := config.Save(path, c); err != nil {
		return err
	}
	fmt.Println("profile saved:", p.ID)
	return nil
}

func cmdProfileRemove(args []string) error {
	fs := flag.NewFlagSet("profile-remove", flag.ExitOnError)
	id := fs.String("id", "", "profile id")
	fs.Parse(args)
	path, c, err := loadForEdit()
	if err != nil {
		return err
	}
	n := len(c.Profiles)
	c.Profiles = slices.DeleteFunc(c.Profiles, func(x config.Profile) bool { return x.ID == *id })
	if len(c.Profiles) == n {
		return fmt.Errorf("no such profile: %s", *id)
	}
	return config.Save(path, c)
}

func cmdUser(args []string, allow bool) error {
	if len(args) != 1 {
		return errors.New(`give a user name, e.g. DOMAIN\name`)
	}
	sid, err := resolveUser(args[0])
	if err != nil {
		return err
	}
	path, c, err := loadForEdit()
	if err != nil {
		return err
	}
	if allow {
		if !slices.Contains(c.AllowedUsers, sid) {
			c.AllowedUsers = append(c.AllowedUsers, sid)
		}
	} else {
		c.AllowedUsers = slices.DeleteFunc(c.AllowedUsers, func(s string) bool { return s == sid })
	}
	if err := config.Save(path, c); err != nil {
		return err
	}
	// The pipe ACL is built at start: restart to apply.
	if m, err := mgr.Connect(); err == nil {
		defer m.Disconnect()
		if s, err := m.OpenService(ipc.ServiceName); err == nil {
			stopService(s)
			s.Start()
			s.Close()
			fmt.Println("service restarted")
		}
	}
	return nil
}

func cmdShow() error {
	_, c, err := loadForEdit()
	if err != nil {
		return err
	}
	type user struct{ SID, Name string }
	var users []user
	for _, s := range c.AllowedUsers {
		users = append(users, user{s, sidName(s)})
	}
	out := map[string]any{"allowedUsers": users, "profiles": c.Profiles}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}

func cmdLock(args []string) error {
	if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
		return errors.New("usage: fvpn-svc lock-profiles on|off")
	}
	path, c, err := loadForEdit()
	if err != nil {
		return err
	}
	c.LockProfiles = args[0] == "on"
	if err := config.Save(path, c); err != nil {
		return err
	}
	fmt.Println("profile lock:", args[0])
	return nil
}
