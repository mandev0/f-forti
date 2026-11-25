//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// isWindows11 reports build >= 22000 (Mica backdrop support).
func isWindows11() bool {
	return windows.RtlGetVersion().BuildNumber >= 22000
}

// Accent holds the user's Windows accent colour in the two variants WinUI
// uses for accent fills: SystemAccentColorDark1 in light theme and
// SystemAccentColorLight2 in dark theme.
type Accent struct {
	Light string `json:"light"` // for light theme
	Dark  string `json:"dark"`  // for dark theme
}

// systemAccent reads HKCU\...\Explorer\Accent\AccentPalette (8 RGBA
// entries: Light3, Light2, Light1, Base, Dark1, Dark2, Dark3, -). Falls back
// to the default Windows blue.
func systemAccent() Accent {
	def := Accent{Light: "#005fb8", Dark: "#60cdff"}
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\Accent`, registry.QUERY_VALUE)
	if err != nil {
		return def
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue("AccentPalette")
	if err != nil || len(b) < 32 {
		return def
	}
	hex := func(i int) string { return fmt.Sprintf("#%02x%02x%02x", b[i*4], b[i*4+1], b[i*4+2]) }
	return Accent{Light: hex(4), Dark: hex(1)}
}

// systemDark reports whether Windows apps use the dark theme.
func systemDark() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	return err == nil && v == 0
}

const (
	mainWidth     = 380
	settingsWidth = 900
	windowHeight  = 660
)
