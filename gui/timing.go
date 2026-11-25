//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// Startup timing: every mark is the time since the OS created the process,
// so time spent before our code runs (AV scanning, loader) shows up as a
// large first mark. Written to %LOCALAPPDATA%\FVPN\startup.log.

var (
	timingMu    sync.Mutex
	timingMarks []string
	timingDone  bool
	procCreated = processCreationTime()
)

func init() { mark("go runtime ready") }

func processCreationTime() time.Time {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		return time.Now()
	}
	return time.Unix(0, creation.Nanoseconds())
}

func mark(name string) {
	timingMu.Lock()
	defer timingMu.Unlock()
	if timingDone {
		return
	}
	timingMarks = append(timingMarks, fmt.Sprintf("%6d ms  %s", time.Since(procCreated).Milliseconds(), name))
}

// flushTiming appends the collected marks to the log once.
func flushTiming() {
	timingMu.Lock()
	if timingDone {
		timingMu.Unlock()
		return
	}
	timingDone = true
	lines := append([]string(nil), timingMarks...)
	timingMu.Unlock()

	dir, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return
	}
	dir = filepath.Join(dir, "FVPN")
	_ = os.MkdirAll(dir, 0o700)
	f, err := os.OpenFile(filepath.Join(dir, "startup.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	exe, _ := os.Executable()
	fmt.Fprintf(f, "== %s  %s %s\n%s\n\n", procCreated.Format("2006-01-02 15:04:05"), filepath.Base(exe), version, strings.Join(lines, "\n"))
}

// Mark records a frontend milestone; "ready" ends the measurement.
func (a *App) Mark(name string) {
	if len(name) > 40 {
		name = name[:40]
	}
	mark("js: " + name)
	if name == "ready" {
		go flushTiming()
	}
}
