//go:build windows

package main

import (
	"embed"
	goruntime "runtime"
	"sync"

	"fyne.io/systray"

	"f-forti/internal/ipc"
)

//go:embed tray/*.ico
var trayFS embed.FS

func trayIcon(name string) []byte {
	b, _ := trayFS.ReadFile("tray/" + name + ".ico")
	return b
}

type trayUI struct {
	mu    sync.Mutex
	ready bool
	icon  string

	status, connect, disconnect, show, autostart, quit *systray.MenuItem
}

// startTray runs the notification-area icon on its own locked OS thread:
// the tray window and its message loop must live on the same thread, and
// the main thread belongs to Wails.
func (a *App) startTray() {
	go func() {
		goruntime.LockOSThread()
		systray.Run(a.trayReady, nil)
	}()
}

func (a *App) trayReady() {
	t := &a.tray
	systray.SetIcon(trayIcon("idle"))
	systray.SetTooltip("FVPN")
	systray.SetOnTapped(a.focus) // left click: open the window

	t.mu.Lock()
	t.icon = "idle"
	t.status = systray.AddMenuItem("Disconnected", "")
	t.status.Disable()
	systray.AddSeparator()
	t.connect = systray.AddMenuItem("Connect…", "Connect with password and verification code")
	t.disconnect = systray.AddMenuItem("Disconnect", "Disconnect the VPN now")
	t.disconnect.Disable()
	systray.AddSeparator()
	t.show = systray.AddMenuItem("Show window", "")
	t.autostart = systray.AddMenuItemCheckbox("Start at login", "", autostartEnabled())
	systray.AddSeparator()
	t.quit = systray.AddMenuItem("Quit", "")
	t.ready = true
	t.mu.Unlock()

	if ev := a.lastEvent.Load(); ev != nil {
		a.updateTray(*ev)
	}

	for {
		select {
		case <-t.connect.ClickedCh:
			a.showLogin()
		case <-t.disconnect.ClickedCh:
			go a.Disconnect()
		case <-t.show.ClickedCh:
			a.focus()
		case <-t.autostart.ClickedCh:
			a.SetAutostart(!t.autostart.Checked())
		case <-t.quit.ClickedCh:
			a.requestQuit()
		}
	}
}

// updateTray mirrors the service state into icon, tooltip and menu.
func (a *App) updateTray(ev StatusEvent) {
	t := &a.tray
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ready {
		return
	}
	state := ipc.State("")
	if ev.Status != nil {
		state = ev.Status.State
	}
	icon, text, tip := "idle", "Disconnected", "FVPN — disconnected"
	canConnect, canDisconnect := true, false
	connectLabel := "Connect…"
	switch {
	case ev.ServiceError != "":
		icon, text, tip = "err", "Service unavailable", "FVPN — service not running"
		canConnect = false
	case state == ipc.StateConnected:
		icon, text = "ok", "Connected · "+ev.Status.LocalIP
		tip = "FVPN — connected (" + ev.Status.LocalIP + ")"
		canConnect, canDisconnect = false, true
	case state == ipc.StateNeed2FA:
		icon, text, tip = "busy", "Waiting for verification code", "FVPN — waiting for verification code"
		connectLabel = "Enter code…"
		canDisconnect = true
	case state == ipc.StateConnecting:
		icon, text, tip = "busy", "Connecting...", "FVPN — connecting"
		canConnect, canDisconnect = false, true
	case state == ipc.StateDisconnecting:
		icon, text, tip = "busy", "Disconnecting...", "FVPN — disconnecting"
		canConnect = false
	case state == ipc.StateError:
		icon, text, tip = "err", "Connection lost", "FVPN — disconnected (error)"
	}
	if icon != t.icon {
		systray.SetIcon(trayIcon(icon))
		t.icon = icon
	}
	systray.SetTooltip(tip)
	t.status.SetTitle(text)
	t.connect.SetTitle(connectLabel)
	setEnabled(t.connect, canConnect)
	setEnabled(t.disconnect, canDisconnect)
}

func (a *App) syncTrayAutostart(on bool) {
	t := &a.tray
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ready {
		return
	}
	if on {
		t.autostart.Check()
	} else {
		t.autostart.Uncheck()
	}
}

func setEnabled(m *systray.MenuItem, on bool) {
	if on {
		m.Enable()
	} else {
		m.Disable()
	}
}
