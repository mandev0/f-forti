# Third-party notices

FVPN is licensed under the MIT License (see [LICENSE](LICENSE)). The binaries
include or ship with the following third-party components. Their full license
texts are in the respective module sources (`go mod download`) or next to the
files listed below.

## Shipped files

| Component | Files | License |
|---|---|---|
| Wintun (WireGuard LLC) | `third_party/wintun/amd64/wintun.dll` | Prebuilt Binaries License, see [third_party/wintun/LICENSE.txt](third_party/wintun/LICENSE.txt). Redistributed unmodified, used only via the `wintun.h` API. |
| Inter (Rasmus Andersson) | `gui/frontend/dist/fonts/inter-variable.ttf` | SIL Open Font License 1.1, see [Inter-OFL.txt](gui/frontend/dist/fonts/Inter-OFL.txt) |
| JetBrains Mono | `gui/frontend/dist/fonts/jetbrains-mono-variable.ttf` | SIL Open Font License 1.1, see [JetBrainsMono-OFL.txt](gui/frontend/dist/fonts/JetBrainsMono-OFL.txt) |
| Wails runtime | `gui/frontend/wailsjs/runtime/*` | MIT |

## Go modules compiled into the Windows binaries

| Module | License |
|---|---|
| fyne.io/systray | Apache-2.0 |
| github.com/godbus/dbus/v5 | BSD-2-Clause |
| github.com/google/btree | Apache-2.0 |
| github.com/leaanthony/go-ansi-parser | MIT |
| github.com/leaanthony/slicer | MIT |
| github.com/leaanthony/u | MIT |
| github.com/pkg/errors | BSD-2-Clause |
| github.com/rivo/uniseg | MIT |
| github.com/wailsapp/go-webview2 | MIT |
| github.com/wailsapp/wails/v2 | MIT |
| golang.org/x/net, x/sys, x/term, x/time | BSD-3-Clause |
| golang.zx2c4.com/wintun | MIT |
| golang.zx2c4.com/wireguard | MIT |
| golang.zx2c4.com/wireguard/windows | MIT |
| gvisor.dev/gvisor | Apache-2.0 (only in `fvpn-cli`) |

Regenerate the module list with:

```sh
GOOS=windows go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' ./cmd/... ./gui | sort -u
```

## Trademarks

Fortinet, FortiGate, FortiClient and FortiOS are trademarks of Fortinet, Inc.
WireGuard and Wintun are trademarks of Jason A. Donenfeld. 1Password is a
trademark of AgileBits Inc. FVPN is an independent project and is not
affiliated with, endorsed by, or sponsored by any of them.
