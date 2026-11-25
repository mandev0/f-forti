//go:build windows

// fvpn-gui is the unprivileged desktop client of the FVPN service.
package main

import (
	"embed"
	"flag"
	"slices"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

const version = "0.9.4"

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	dev := flag.Bool("dev", false, `connect to a foreground "fvpn-svc run" server`)
	trayOnly := flag.Bool("tray", false, "start in the notification area without opening the window")
	quit := flag.Bool("quit", false, "close the running instance (used by the installer)")
	noAutostart := flag.Bool("remove-autostart", false, "delete this user's start-at-login entry (used by the uninstaller)")
	flag.Parse()
	if *noAutostart {
		setAutostartReg(false)
		return
	}
	if *quit && !instanceRunning() {
		return // nothing to close; do not open a window
	}
	mark("main")

	// NetBird-style window: fixed 380x660 main view (900 wide for settings),
	// opaque background matching the page's base gray in the system theme.
	// Earlier variants live in gui/frontend/_alt/ (fluent used Mica).
	const useMica = false
	mica := useMica && isWindows11()
	bg := &options.RGBA{R: 243, G: 243, B: 243, A: 255}
	if systemDark() {
		bg = &options.RGBA{R: 24, G: 26, B: 29, A: 255}
	}
	backdrop := windows.None
	if mica {
		bg = &options.RGBA{A: 0}
		backdrop = windows.Mica
	}

	app := NewApp(*dev, mica)
	mark("wails.Run")
	err := wails.Run(&options.App{
		Title:            "FVPN",
		Width:            mainWidth,
		Height:           windowHeight,
		DisableResize:    true,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: bg,
		OnStartup:        app.startup,
		OnDomReady:       app.domReady,
		OnShutdown:       app.shutdown,
		OnBeforeClose:    app.beforeClose,
		StartHidden:      *trayOnly,
		Bind:             []interface{}{app},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "f0f1e4a3-fvpn-gui",
			// A second launch forwards its arguments here and exits.
			OnSecondInstanceLaunch: func(d options.SecondInstanceData) {
				if slices.Contains(d.Args, "--quit") || slices.Contains(d.Args, "-quit") {
					app.Quit(false) // the VPN itself is the service's business
					return
				}
				app.focus()
			},
		},
		EnableDefaultContextMenu: false,
		Windows: &windows.Options{
			Theme:                windows.SystemDefault,
			WindowClassName:      windowClass, // lets winpos.go find our HWND
			DisableWindowIcon:    false,
			WebviewIsTransparent: mica,
			WindowIsTranslucent:  mica,
			BackdropType:         backdrop,
		},
	})
	if err != nil {
		println("error:", err.Error())
	}
}
