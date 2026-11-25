//go:build windows

package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"f-forti/internal/ipc"
)

// App is bound to the frontend (window.go.main.App).
type App struct {
	ctx      context.Context
	dev      bool
	mica     bool
	settings *Settings

	pollMu sync.Mutex
	poll   *ipc.Client

	allowClose atomic.Bool
	lastState  atomic.Value // ipc.State; read by the UI thread in beforeClose
	lastEvent  atomic.Pointer[StatusEvent]
	notifyOK   atomic.Bool
	hidOnce    sync.Once

	tray trayUI
}

// StatusEvent is pushed to the frontend every second.
type StatusEvent struct {
	Status       *ipc.Status `json:"status"`
	ServiceError string      `json:"serviceError,omitempty"`
}

// InitInfo is what the frontend needs at start.
type InitInfo struct {
	Profiles      []ipc.ProfileInfo   `json:"profiles"`
	LastProfile   string              `json:"lastProfile"`
	Users         map[string]string   `json:"users"`
	Locked        bool                `json:"locked"`
	Error         string              `json:"error,omitempty"`
	Version       string              `json:"version"`
	Mica          bool                `json:"mica"`
	OnePassword   map[string]OPConfig `json:"onePassword"`
	OnePasswordOn bool                `json:"onePasswordOn"`
	Accent        Accent              `json:"accent"`
}

func NewApp(dev, mica bool) *App { return &App{dev: dev, mica: mica, settings: LoadSettings()} }

func (a *App) startup(ctx context.Context) {
	mark("OnStartup")
	a.ctx = ctx
	// Nothing here may block: Wails shows the window only after startup
	// returns and the page has loaded. Notification setup (registry/COM) runs
	// in the background.
	go func() {
		if runtime.InitializeNotifications(ctx) == nil {
			a.notifyOK.Store(runtime.IsNotificationAvailable(ctx))
		}
		mark("notifications ready")
	}()
	// First run of the installed copy: start with Windows (user can turn
	// it off from the tray, the window footer or Task Manager).
	if !a.settings.AutostartInit && installedCopy() {
		if setAutostartReg(true) == nil {
			a.settings.MarkAutostartInit()
		}
	}
	a.startTray()
	go a.pollLoop()
	mark("OnStartup done")
}

// domReady fires on WebView2 NavigationCompleted, which is when Wails shows
// the window for the first time.
func (a *App) domReady(ctx context.Context) {
	mark("page loaded, window shown")
}

func (a *App) shutdown(ctx context.Context) {
	if a.notifyOK.Load() {
		runtime.CleanupNotifications(ctx)
	}
	systray.Quit()
	a.pollMu.Lock()
	if a.poll != nil {
		a.poll.Close()
	}
	a.pollMu.Unlock()
}

// beforeClose hides the window to the tray instead of exiting; exiting is
// done from the tray menu (Quit).
func (a *App) beforeClose(ctx context.Context) (prevent bool) {
	if a.allowClose.Load() {
		return false
	}
	runtime.WindowHide(ctx)
	a.hidOnce.Do(func() {
		if a.notifyOK.Load() {
			runtime.SendNotification(ctx, runtime.NotificationOptions{
				ID:    "fvpn-hidden",
				Title: "FVPN is still running",
				Body:  "Use the notification area icon to connect or disconnect.",
			})
		}
	})
	return true
}

// requestQuit (tray "Quit") asks for confirmation while a session is active.
func (a *App) requestQuit() {
	st, _ := a.lastState.Load().(ipc.State)
	switch st {
	case ipc.StateConnected, ipc.StateConnecting, ipc.StateNeed2FA:
		a.focus()
		runtime.EventsEmit(a.ctx, "close-requested")
		return
	}
	a.Quit(false)
}

// Quit exits the GUI, optionally disconnecting first.
func (a *App) Quit(disconnect bool) {
	if disconnect {
		a.call(ipc.Request{Op: ipc.OpDisconnect}, 30*time.Second)
	}
	a.allowClose.Store(true)
	runtime.Quit(a.ctx)
}

// showLogin opens the window on the password (or pending code) field.
func (a *App) showLogin() {
	a.focus()
	runtime.EventsEmit(a.ctx, "focus-login")
}

// SetView resizes the window for the main view or the wider settings view,
// keeping it in place (see resizeKeepingPlace).
func (a *App) SetView(view string) {
	w := mainWidth
	if view == "settings" {
		w = settingsWidth
	}
	if err := resizeKeepingPlace(w, view == "settings"); err != nil {
		runtime.WindowSetSize(a.ctx, w, windowHeight) // fallback: grows to the right
	}
}

// GetAutostart reports whether FVPN starts at logon.
func (a *App) GetAutostart() bool { return autostartEnabled() }

// SetAutostart turns start-at-logon on or off.
func (a *App) SetAutostart(on bool) error {
	if err := setAutostartReg(on); err != nil {
		return err
	}
	a.settings.MarkAutostartInit()
	a.syncTrayAutostart(on)
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "autostart", on)
	}
	return nil
}

// focus brings the window forward (second instance launched).
func (a *App) focus() {
	if a.ctx == nil {
		return
	}
	runtime.WindowShow(a.ctx)
	runtime.WindowUnminimise(a.ctx)
	runtime.WindowSetAlwaysOnTop(a.ctx, true)  // bring to front over other apps,
	runtime.WindowSetAlwaysOnTop(a.ctx, false) // then behave normally
}

func (a *App) dial() (*ipc.Client, error) {
	return ipc.Dial(3*time.Second, ipc.DialOptions{AllowElevatedServer: a.dev})
}

// call runs one request on its own connection, so long operations (login)
// never block the status poller.
func (a *App) call(r ipc.Request, timeout time.Duration) (*ipc.Response, error) {
	cl, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	resp, err := cl.Do(r, timeout)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// Init returns profiles and remembered usernames.
func (a *App) Init() InitInfo {
	info := InitInfo{LastProfile: a.settings.LastProfile, Users: a.settings.Users, Version: version, Mica: a.mica, Accent: systemAccent(), OnePassword: a.settings.OnePasswordAll(), OnePasswordOn: a.settings.OnePasswordOn()}
	resp, err := a.call(ipc.Request{Op: ipc.OpProfiles}, 5*time.Second)
	if err != nil {
		info.Error = friendly(err)
		return info
	}
	info.Profiles, info.Locked = resp.Profiles, resp.Locked
	return info
}

// Connect sends credentials to the service. The password is not stored.
func (a *App) Connect(profile, user, pass string) (*ipc.Status, error) {
	user = strings.TrimSpace(user)
	if profile == "" || user == "" || pass == "" {
		return nil, errors.New("Profile, username and password are required")
	}
	a.settings.Remember(profile, user)
	resp, err := a.call(ipc.Request{Op: ipc.OpConnect, Profile: profile, Username: user, Password: pass}, 2*time.Minute)
	pass = ""
	return statusOf(resp), friendlyErr(err)
}

// Submit2FA sends the one-time code.
func (a *App) Submit2FA(code string) (*ipc.Status, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, errors.New("Enter the code")
	}
	resp, err := a.call(ipc.Request{Op: ipc.OpSubmit2FA, Code: code}, 2*time.Minute)
	return statusOf(resp), friendlyErr(err)
}

// Disconnect ends the session (or cancels a pending 2FA / clears an error).
func (a *App) Disconnect() (*ipc.Status, error) {
	resp, err := a.call(ipc.Request{Op: ipc.OpDisconnect}, 30*time.Second)
	return statusOf(resp), friendlyErr(err)
}

// Logs returns the service log tail.
func (a *App) Logs() ([]string, error) {
	resp, err := a.call(ipc.Request{Op: ipc.OpLogs}, 5*time.Second)
	if err != nil {
		return nil, friendlyErr(err)
	}
	return resp.Logs, nil
}

func statusOf(r *ipc.Response) *ipc.Status {
	if r == nil {
		return nil
	}
	return r.Status
}

func (a *App) pollLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		ev := a.pollOnce()
		a.lastEvent.Store(&ev)
		a.onStatus(ev)
		a.updateTray(ev)
		runtime.EventsEmit(a.ctx, "status", ev)
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *App) pollOnce() StatusEvent {
	a.pollMu.Lock()
	defer a.pollMu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if a.poll == nil {
			cl, err := a.dial()
			if err != nil {
				return StatusEvent{ServiceError: friendly(err)}
			}
			a.poll = cl
		}
		resp, err := a.poll.Do(ipc.Request{Op: ipc.OpStatus}, 5*time.Second)
		if err == nil && resp.Status != nil {
			return StatusEvent{Status: resp.Status}
		}
		a.poll.Close()
		a.poll = nil
	}
	return StatusEvent{ServiceError: "No response from the service"}
}

// onStatus reacts to state transitions (title, notifications).
func (a *App) onStatus(ev StatusEvent) {
	state := ipc.State("")
	if ev.Status != nil {
		state = ev.Status.State
	}
	prev, _ := a.lastState.Load().(ipc.State)
	a.lastState.Store(state)
	if state == prev {
		return
	}

	if prev == ipc.StateConnected && state == ipc.StateError {
		// Unexpected drop: reconnecting needs a new 2FA code, so get the
		// user's attention.
		a.focus()
		if a.notifyOK.Load() {
			runtime.SendNotification(a.ctx, runtime.NotificationOptions{
				ID:    "fvpn-drop",
				Title: "VPN connection lost",
				Body:  capFirst(ev.Status.LastError),
			})
		}
	}
}

func friendlyErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(friendly(err))
}

func friendly(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "cannot connect to the service"):
		return "The FVPN service is not running or this user is not allowed to use it"
	case strings.Contains(s, "service: refused"):
		return "Security: the control pipe is not owned by the FVPN service; refused"
	}
	return capFirst(s)
}
