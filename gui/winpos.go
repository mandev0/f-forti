//go:build windows

package main

import (
	"errors"
	"math"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"f-forti/internal/winplace"
)

// Window geometry is handled with Win32 directly, in physical pixels:
// Wails v2 mixes coordinate systems (WindowGetPosition is absolute,
// WindowSetPosition is relative to the work area, sizes are in DIPs), which
// makes the window drift when switching views.

const windowClass = "FVPNWindow"

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	procFindWindowExW   = user32.NewProc("FindWindowExW")
	procGetWindowRect   = user32.NewProc("GetWindowRect")
	procSetWindowPos    = user32.NewProc("SetWindowPos")
	procGetDpiForWindow = user32.NewProc("GetDpiForWindow")
	procMonitorFromWin  = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfoW = user32.NewProc("GetMonitorInfoW")
	errWindowNotFound   = errors.New("window not found")
	geometryMu          sync.Mutex
	placement           winplace.State
)

type rect = winplace.Rect

// instanceRunning reports whether some process (of this user's desktop) has
// the FVPN window open.
func instanceRunning() bool {
	cls, err := windows.UTF16PtrFromString(windowClass)
	if err != nil {
		return false
	}
	h, _, _ := procFindWindowExW.Call(0, 0, uintptr(unsafe.Pointer(cls)), 0)
	return h != 0
}

type monitorInfo struct {
	Size    uint32
	Monitor rect
	Work    rect
	Flags   uint32
}

const (
	swpNoZOrder        = 0x0004
	swpNoActivate      = 0x0010
	swpAsyncWindowPos  = 0x4000
	monitorDefaultNear = 0x00000002
)

// ownWindow finds our top-level window by class name and process ID.
func ownWindow() (windows.HWND, error) {
	cls, _ := windows.UTF16PtrFromString(windowClass)
	pid := uint32(os.Getpid())
	var h uintptr
	for {
		h, _, _ = procFindWindowExW.Call(0, h, uintptr(unsafe.Pointer(cls)), 0)
		if h == 0 {
			return 0, errWindowNotFound
		}
		var wpid uint32
		windows.GetWindowThreadProcessId(windows.HWND(h), &wpid)
		if wpid == pid {
			return windows.HWND(h), nil
		}
	}
}

func windowRect(h windows.HWND) (rect, error) {
	var r rect
	if ok, _, e := procGetWindowRect.Call(uintptr(h), uintptr(unsafe.Pointer(&r))); ok == 0 {
		return r, e
	}
	return r, nil
}

func workArea(h windows.HWND) (rect, bool) {
	mon, _, _ := procMonitorFromWin.Call(uintptr(h), monitorDefaultNear)
	mi := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	if ok, _, _ := procGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi))); ok == 0 {
		return rect{}, false
	}
	return mi.Work, true
}

// resizeKeepingPlace changes the window width (in DIPs) without making it
// wander: expanding grows evenly around the current centre; shrinking back
// returns to the exact main-view position unless the user moved the wide
// window, in which case the narrow window is centred on where it now is.
// The result always stays inside the monitor's work area.
func resizeKeepingPlace(widthDIP int, expanding bool) error {
	geometryMu.Lock()
	defer geometryMu.Unlock()

	h, err := ownWindow()
	if err != nil {
		return err
	}
	cur, err := windowRect(h)
	if err != nil {
		return err
	}
	scale := 1.0
	if dpi, _, _ := procGetDpiForWindow.Call(uintptr(h)); dpi > 0 {
		scale = float64(dpi) / 96
	}
	newW := int32(math.Round(float64(widthDIP) * scale))
	if newW == cur.W() {
		return nil
	}
	work, _ := workArea(h)
	next := placement.Next(cur, newW, expanding, work)
	// Coordinates may be negative (monitors left of/above the primary):
	// pass them through as signed values.
	if ok, _, e := procSetWindowPos.Call(uintptr(h), 0,
		uintptr(int(next.Left)), uintptr(int(next.Top)), uintptr(int(next.W())), uintptr(int(next.H())),
		swpNoZOrder|swpNoActivate|swpAsyncWindowPos); ok == 0 {
		return e
	}
	return nil
}
