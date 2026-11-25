//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Per-user autostart via HKCU\...\Run: no admin rights, removable by the
// user from Task Manager → Startup apps as well.
const (
	runKey  = `Software\Microsoft\Windows\CurrentVersion\Run`
	runName = "FVPN"
)

func autostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(runName)
	return err == nil && v != ""
}

func setAutostartReg(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		err := k.DeleteValue(runName)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue(runName, `"`+exe+`" --tray`)
}

// installedCopy reports whether we run from Program Files (so the autostart
// entry will not point at a temporary download location).
func installedCopy() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(pf, exe)
	return err == nil && !strings.HasPrefix(rel, "..")
}
