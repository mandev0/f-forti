//go:build windows

// fvpn-closegui closes running FVPN app instances so Windows Installer can
// replace fvpn-gui.exe without a "files in use" prompt or a reboot. It is
// embedded in the MSI (Binary table) and never installed, so the logic of the
// package being installed runs even when an older version is upgraded.
//
//	fvpn-closegui "C:\Program Files\FVPN\fvpn-gui.exe"
//
//  1. Ask the instance in this session to quit (fvpn-gui.exe --quit).
//  2. Wait for every fvpn-gui.exe started from that path to exit.
//  3. Terminate what is still running: the app holds no state, the VPN
//     belongs to the service (which the installer stops anyway).
//
// Instances of other users that this process may not open are left alone;
// Windows Installer then replaces the file on the next restart.
// The exit code is always 0: closing the app must never fail the install.
package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	quitTimeout = 10 * time.Second // graceful: tray icon and notifications cleaned up
	killTimeout = 5 * time.Second
)

func main() {
	if len(os.Args) != 2 {
		return
	}
	gui := filepath.Clean(os.Args[1])
	if !filepath.IsAbs(gui) || !strings.EqualFold(filepath.Base(gui), "fvpn-gui.exe") {
		return
	}
	if _, err := os.Stat(gui); err != nil {
		return // nothing installed yet
	}
	procs := running(gui)
	if len(procs) == 0 {
		return
	}
	defer func() {
		for _, h := range procs {
			windows.CloseHandle(h)
		}
	}()

	askQuit(gui)
	left := wait(procs, quitTimeout)
	for _, h := range left {
		windows.TerminateProcess(h, 1)
	}
	wait(left, killTimeout)
}

// running returns handles to the processes whose image is exactly gui.
func running(gui string) []windows.Handle {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	self := uint32(os.Getpid())
	var out []windows.Handle
	pe := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ProcessID == self || !strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), "fvpn-gui.exe") {
			continue
		}
		h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe.ProcessID)
		if err != nil {
			continue // another user's process: not ours to touch
		}
		if p := imagePath(h); p != "" && strings.EqualFold(filepath.Clean(p), gui) {
			out = append(out, h)
		} else {
			windows.CloseHandle(h)
		}
	}
	return out
}

func imagePath(h windows.Handle) string {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// askQuit runs "fvpn-gui.exe --quit": a second instance that forwards the
// request to the running one in this session and exits.
func askQuit(gui string) {
	ctx, cancel := context.WithTimeout(context.Background(), quitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gui, "--quit")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	_ = cmd.Run()
}

// wait returns the processes still running after d.
func wait(procs []windows.Handle, d time.Duration) []windows.Handle {
	deadline := time.Now().Add(d)
	var left []windows.Handle
	for _, h := range procs {
		ms := uint32(0)
		if r := time.Until(deadline); r > 0 {
			ms = uint32(r / time.Millisecond)
		}
		if ev, _ := windows.WaitForSingleObject(h, ms); ev != windows.WAIT_OBJECT_0 {
			left = append(left, h)
		}
	}
	return left
}
