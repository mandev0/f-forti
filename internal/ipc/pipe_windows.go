//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// PipePath is the service control pipe.
const PipePath = `\\.\pipe\fvpn-control`

var (
	kernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procGetNamedPipeClientProcess = kernel32.NewProc("GetNamedPipeClientProcessId")
	procGetNamedPipeServerProcess = kernel32.NewProc("GetNamedPipeServerProcessId")
)

// Listen creates the control pipe. DACL: SYSTEM and Administrators full
// access, each allowed SID read/write; nobody else, no inheritance. Remote
// clients are rejected by the namedpipe package (FILE_PIPE_REJECT_REMOTE_CLIENTS)
// and the first instance is created exclusively (fails if squatted).
//
// asService selects the owner: SYSTEM for the real service, Administrators
// when running in the foreground from an elevated console.
func Listen(allowedSIDs []string, asService bool) (net.Listener, error) {
	owner := "BA"
	if asService {
		owner = "SY"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "O:%sG:%sD:P(A;;GA;;;SY)(A;;GA;;;BA)", owner, owner)
	for _, s := range allowedSIDs {
		if _, err := windows.StringToSid(s); err != nil {
			return nil, fmt.Errorf("invalid SID %q: %w", s, err)
		}
		// GRGW: the client dials with GENERIC_READ|GENERIC_WRITE. Because
		// GENERIC_WRITE includes FILE_CREATE_PIPE_INSTANCE, clients verify
		// the server process identity after connecting (see Dial).
		fmt.Fprintf(&b, "(A;;GRGW;;;%s)", s)
	}
	sd, err := windows.SecurityDescriptorFromString(b.String())
	if err != nil {
		return nil, err
	}
	return (&namedpipe.ListenConfig{
		SecurityDescriptor: sd,
		InputBufferSize:    MaxMessage,
		OutputBufferSize:   MaxMessage,
	}).Listen(PipePath)
}

type handler interface{ Handle() windows.Handle }

// ClientIdentity returns the SID of the process on the other end of a server
// side pipe connection and whether that process token is elevated.
func ClientIdentity(c net.Conn) (sid string, elevated bool, err error) {
	h, ok := c.(handler)
	if !ok {
		return "", false, errors.New("no pipe handle")
	}
	var pid uint32
	if r, _, e := procGetNamedPipeClientProcess.Call(uintptr(h.Handle()), uintptr(unsafe.Pointer(&pid))); r == 0 {
		return "", false, e
	}
	return processIdentity(pid)
}

func processIdentity(pid uint32) (string, bool, error) {
	ph, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false, err
	}
	defer windows.CloseHandle(ph)
	var tok windows.Token
	if err := windows.OpenProcessToken(ph, windows.TOKEN_QUERY, &tok); err != nil {
		return "", false, err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", false, err
	}
	return u.User.Sid.String(), tok.IsElevated(), nil
}

// Allowed reports whether a client identity may use the service.
func Allowed(sid string, elevated bool, allowed []string) bool {
	return elevated || sid == "S-1-5-18" || slices.Contains(allowed, sid)
}

// DialOptions controls server verification.
type DialOptions struct {
	// AllowElevatedServer accepts a server running as an elevated admin
	// (foreground "fvpn-svc run" during development) instead of SYSTEM.
	AllowElevatedServer bool
}

// Dial connects to the service and verifies that the process serving the
// pipe runs as LocalSystem (or elevated admin in dev mode) before any
// secret is sent over it.
func Dial(timeout time.Duration, opt DialOptions) (*Client, error) {
	c, err := namedpipe.DialTimeout(PipePath, timeout)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to the service (is it running?): %w", err)
	}
	h, ok := c.(handler)
	if !ok {
		c.Close()
		return nil, errors.New("no pipe handle")
	}
	var pid uint32
	if r, _, e := procGetNamedPipeServerProcess.Call(uintptr(h.Handle()), uintptr(unsafe.Pointer(&pid))); r == 0 {
		c.Close()
		return nil, fmt.Errorf("cannot find the pipe server process: %w", e)
	}
	// Authoritative check: the pipe server must be the process SCM runs our
	// service in. Unprivileged users may query service status, but cannot
	// open a SYSTEM process token, so SCM is the reliable source.
	if svcPID, err := ServicePID(); err == nil && svcPID == pid {
		return NewClient(c), nil
	}
	if opt.AllowElevatedServer {
		if _, elevated, err := processIdentity(pid); err == nil && elevated {
			return NewClient(c), nil
		}
	}
	c.Close()
	return nil, fmt.Errorf("pipe server (pid %d) is not the %s service: refused", pid, ServiceName)
}

// ServiceName is the Windows service name.
const ServiceName = "fvpn"

// ServicePID returns the process ID of the running service.
func ServicePID() (uint32, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	s, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need); err != nil {
		return 0, err
	}
	if st.CurrentState != windows.SERVICE_RUNNING || st.ProcessId == 0 {
		return 0, errors.New("service is not running")
	}
	return st.ProcessId, nil
}
