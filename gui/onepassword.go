//go:build windows

package main

// 1Password integration through the official CLI (op.exe) with the desktop
// app integration (Windows Hello unlock). Secrets never reach the web view:
// they go from op's stdout straight to the service pipe. op.exe is located
// explicitly and must carry a valid Authenticode signature by AgileBits.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"

	"f-forti/internal/ipc"
	"f-forti/internal/opcli"
)

// OPConfig is the per-profile 1Password reference (no secrets).
type OPConfig = opcli.Config

// OPCheck is what the UI may learn about the items (never the values).
type OPCheck struct {
	Username    string `json:"username"`
	HasPassword bool   `json:"hasPassword"`
	HasOTP      bool   `json:"hasOtp"`      // in the item the code is read from
	SeparateOTP bool   `json:"separateOtp"` // the code comes from another item
	ManualOTP   bool   `json:"manualOtp"`   // the user enters the code
}

var errOPOff = errors.New("1Password: the integration is turned off in Settings")

// OPTool describes the CLI installation.
type OPTool struct {
	Found bool   `json:"found"`
	Path  string `json:"path,omitempty"`
	Error string `json:"error,omitempty"`
}

var errOPMissing = errors.New("1Password CLI (op.exe) not found. Install it with \"winget install AgileBits.1Password.CLI\", then in the 1Password app enable Settings › Developer › Integrate with 1Password CLI")

// findOP returns the verified path of op.exe.
func findOP() (string, error) {
	var cands []string
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		cands = append(cands, filepath.Join(la, `Microsoft\WinGet\Links\op.exe`))
		if m, _ := filepath.Glob(filepath.Join(la, `Microsoft\WinGet\Packages\AgileBits.1Password.CLI_*\op.exe`)); len(m) > 0 {
			cands = append(cands, m...)
		}
	}
	if pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil {
		cands = append(cands, filepath.Join(pf, `1Password CLI\op.exe`))
	}
	if p, err := exec.LookPath("op.exe"); err == nil {
		cands = append(cands, p)
	}
	var lastErr error = errOPMissing
	for _, c := range cands {
		real, err := filepath.EvalSymlinks(c) // winget links are symlinks
		if err != nil {
			continue
		}
		if !filepath.IsAbs(real) {
			continue
		}
		if err := verifySigner(real); err != nil {
			lastErr = fmt.Errorf("%s is not a valid 1Password CLI: %w", real, err)
			continue
		}
		return real, nil
	}
	return "", lastErr
}

var (
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = crypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = crypt32.NewProc("CryptMsgClose")
)

const (
	cmsgSignerCertInfoParam = 7
	certFindSubjectCert     = 0xB0000 // CERT_COMPARE_SUBJECT_CERT << CERT_COMPARE_SHIFT
)

// verifySigner checks that path has a valid, trusted Authenticode signature
// and that the certificate that actually signed it belongs to AgileBits
// (opcli.SignerOK). Only checking names inside the signature would be
// bypassable: extra certificates can be embedded next to the real signer.
func verifySigner(path string) error {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fi := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: path16}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE, // offline-safe; chain + signature still verified
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fi),
	}
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verr != nil {
		return fmt.Errorf("signature not valid: %w", verr)
	}

	var store, msg windows.Handle
	var enc uint32
	if err := windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(path16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		&enc, nil, nil, &store, &msg, nil); err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	var n uint32
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&n))); r == 0 {
		return fmt.Errorf("signer info: %w", e)
	}
	buf := make([]byte, n)
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return fmt.Errorf("signer info: %w", e)
	}
	cert, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		certFindSubjectCert, unsafe.Pointer(&buf[0]), nil)
	if err != nil {
		return fmt.Errorf("signer certificate: %w", err)
	}
	defer windows.CertFreeCertificateContext(cert)
	sg := opcli.Signer{
		CN: certAttr(cert, "2.5.4.3", false), O: certAttr(cert, "2.5.4.10", false), C: certAttr(cert, "2.5.4.6", false),
		IssuerCN: certAttr(cert, "2.5.4.3", true), IssuerO: certAttr(cert, "2.5.4.10", true),
	}
	if !opcli.SignerOK(sg) {
		return fmt.Errorf("signed by CN=%q O=%q C=%q (issuer %q), not by AgileBits", sg.CN, sg.O, sg.C, sg.IssuerCN)
	}
	return nil
}

const (
	certNameAttrType   = 3 // CERT_NAME_ATTR_TYPE
	certNameIssuerFlag = 1 // CERT_NAME_ISSUER_FLAG
)

// certAttr returns one RDN attribute (by OID) of the subject or issuer.
func certAttr(cert *windows.CertContext, oid string, issuer bool) string {
	oid8, err := windows.BytePtrFromString(oid)
	if err != nil {
		return ""
	}
	var flags uint32
	if issuer {
		flags = certNameIssuerFlag
	}
	n := windows.CertGetNameString(cert, certNameAttrType, flags, unsafe.Pointer(oid8), nil, 0)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	windows.CertGetNameString(cert, certNameAttrType, flags, unsafe.Pointer(oid8), &buf[0], n)
	return windows.UTF16ToString(buf)
}

// runOP runs op with args and returns stdout. No shell, no console window;
// secrets only travel through the stdout pipe.
func runOP(ctx context.Context, args ...string) ([]byte, error) {
	path, err := findOP()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("timed out waiting for 1Password (was the unlock prompt answered?)")
		}
		return nil, errors.New(opcli.ErrorText(stderr.String(), err.Error()))
	}
	return out.Bytes(), nil
}

// opCredentials reads username and password, and whether a TOTP exists in
// the item the code will be read from.
func opCredentials(ctx context.Context, c OPConfig) (opcli.Credentials, error) {
	out, err := runOP(ctx, c.CredRef().Args("--format", "json", "--reveal")...)
	if err != nil {
		return opcli.Credentials{}, err
	}
	cr, err := opcli.ParseItem(out)
	clear(out)
	if c.ManualOTP {
		cr.HasOTP = false // never read, even if the item has one
	}
	if err != nil || !c.SeparateOTP() {
		return cr, err
	}
	cr.HasOTP, err = opHasOTP(ctx, c.OTPRef())
	return cr, err
}

// opHasOTP looks at an item's field types without revealing any value.
func opHasOTP(ctx context.Context, r opcli.Ref) (bool, error) {
	out, err := runOP(ctx, r.Args("--format", "json")...)
	if err != nil {
		return false, fmt.Errorf("one-time password item: %w", err)
	}
	it, err := opcli.ParseItem(out)
	clear(out)
	return it.HasOTP, err
}

// opTOTP returns the current one-time code, skipping the last moments of a
// 30-second window so the code is still valid when the gateway checks it.
func opTOTP(ctx context.Context, c OPConfig) (string, error) {
	if w := opcli.WaitBeforeOTP(time.Now().Unix()); w > 0 {
		select {
		case <-time.After(time.Duration(w)*time.Second + 300*time.Millisecond):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	out, err := runOP(ctx, c.OTPRef().Args("--otp")...)
	if err != nil {
		return "", err
	}
	code, err := opcli.ParseOTP(out)
	clear(out)
	return code, err
}

// lastOTP remembers the last code sent: a TOTP code can be used only once,
// and reconnecting within the same 30 s window would get the same code.
var lastOTP struct {
	sync.Mutex
	code string
	at   time.Time
}

// freshTOTP returns a code that has not been submitted yet, waiting for the
// next window if 1Password still shows the previous one.
func (a *App) freshTOTP(ctx context.Context, c OPConfig) (string, error) {
	code, err := opTOTP(ctx, c)
	if err != nil {
		return "", err
	}
	lastOTP.Lock()
	reused := code == lastOTP.code && time.Since(lastOTP.at) < 2*time.Minute
	lastOTP.Unlock()
	if reused {
		a.opPhase("next-code")
		wait := time.Duration(30-time.Now().Unix()%30)*time.Second + 500*time.Millisecond
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return "", ctx.Err()
		}
		if code, err = opTOTP(ctx, c); err != nil {
			return "", err
		}
	}
	lastOTP.Lock()
	lastOTP.code, lastOTP.at = code, time.Now()
	lastOTP.Unlock()
	return code, nil
}

// opPhase tells the UI which step of the 1Password sign-in is running.
func (a *App) opPhase(p string) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "op-phase", p)
	}
}

// ---- bound methods ----

// OnePasswordTool reports whether a verified op.exe is available.
func (a *App) OnePasswordTool() OPTool {
	p, err := findOP()
	if err != nil {
		return OPTool{Error: err.Error()}
	}
	return OPTool{Found: true, Path: p}
}

// Get1Password returns the 1Password settings of a profile.
func (a *App) Get1Password(profile string) OPConfig { return a.settings.OnePassword(profile) }

// Set1Password stores the 1Password settings of a profile.
func (a *App) Set1Password(profile string, c OPConfig) error {
	if !a.settings.OnePasswordOn() {
		return errOPOff
	}
	c = c.Trimmed()
	if err := c.Validate(); err != nil {
		return err
	}
	a.settings.SetOnePassword(profile, c)
	return nil
}

// Get1PasswordOn reports whether the 1Password integration is turned on.
func (a *App) Get1PasswordOn() bool { return a.settings.OnePasswordOn() }

// Set1PasswordOn turns the 1Password integration on or off for this user.
// Profile references are kept, so turning it back on restores them.
func (a *App) Set1PasswordOn(on bool) { a.settings.SetOnePasswordOn(on) }

// Test1Password looks the item up and reports what it contains (no values
// except the username). This triggers the 1Password unlock prompt.
func (a *App) Test1Password(c OPConfig) (OPCheck, error) {
	if !a.settings.OnePasswordOn() {
		return OPCheck{}, errOPOff
	}
	c = c.Trimmed()
	c.Enabled = true
	if err := c.Validate(); err != nil {
		return OPCheck{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cr, err := opCredentials(ctx, c)
	if err != nil {
		return OPCheck{}, fmt.Errorf("1Password: %w", err)
	}
	return OPCheck{Username: cr.Username, HasPassword: cr.Password != "", HasOTP: cr.HasOTP, SeparateOTP: c.SeparateOTP(), ManualOTP: c.ManualOTP}, nil
}

// ConnectWith1Password signs in with credentials from 1Password and answers
// the verification request with the item's one-time password. With ManualOTP
// it stops at the verification request and the UI asks for the code. Errors that
// come from 1Password start with "1Password:" so the UI can fall back to
// manual entry; other errors come from the service.
func (a *App) ConnectWith1Password(profile string) (*ipc.Status, error) {
	if !a.settings.OnePasswordOn() {
		return nil, errOPOff
	}
	c := a.settings.OnePassword(profile)
	if !c.Enabled {
		return nil, errors.New("1Password: not enabled for this profile")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	a.opPhase("credentials")
	cr, err := opCredentials(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("1Password: %w", err)
	}
	user, pass, hasOTP := cr.Username, cr.Password, cr.HasOTP
	cr = opcli.Credentials{}
	if user == "" || pass == "" {
		return nil, errors.New("1Password: the item has no username or password")
	}
	a.settings.Remember(profile, user)
	a.opPhase("signin")
	resp, err := a.call(ipc.Request{Op: ipc.OpConnect, Profile: profile, Username: user, Password: pass}, 2*time.Minute)
	pass = ""
	if err != nil {
		return statusOf(resp), friendlyErr(err)
	}
	st := statusOf(resp)
	if st == nil || st.State != ipc.StateNeed2FA || c.ManualOTP {
		return st, nil
	}
	if !hasOTP {
		return st, errors.New("1Password: no one-time password found; enter the code manually")
	}
	a.opPhase("code")
	code, err := a.freshTOTP(ctx, c)
	if err != nil {
		return st, fmt.Errorf("1Password: %w", err)
	}
	a.opPhase("verify")
	resp, err = a.call(ipc.Request{Op: ipc.OpSubmit2FA, Code: code}, 2*time.Minute)
	return statusOf(resp), friendlyErr(err)
}
