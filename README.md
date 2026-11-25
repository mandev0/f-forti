# FVPN

An unofficial FortiGate SSL-VPN client for Windows, written in Go.

FVPN talks the FortiGate SSL-VPN protocol (HTTPS login, 2FA, PPP over TLS) and
brings the tunnel up on a Wintun adapter. Daily use needs no administrator
rights: a small LocalSystem service owns the adapter, routes and DNS, and the
unprivileged GUI (Wails) or `fvpn-ctl` talks to it over a locked-down named
pipe (`\\.\pipe\fvpn-control`).

> **Status:** early (0.9.x). Tested against a single gateway so far. FortiOS
> 7.6.3+ removes SSL-VPN tunnel mode; IPsec/IKEv2 is not supported.

## Features

- Username/password login with a second factor (TOTP code or FortiToken push)
- Split tunnel and split DNS from the gateway configuration (routes compacted,
  default/huge routes refused, optional per-profile allow-list)
- Tunnel DNS on the adapter plus NRPT rules per split-DNS domain group
- Certificate pinning (SHA-256) for gateways with non-public certificates
- Optional 1Password CLI (`op`) integration, turned on per user in Settings:
  credentials from one item, the TOTP code from the same or a separate item
- Profiles managed from the GUI or by an administrator (`lock-profiles`)
- MSI installer; no UPX, no self-elevation, symbols kept (AV/EDR friendly)

## Components

| Binary | Purpose |
|---|---|
| `fvpn-svc.exe` | Windows service: tunnel, adapter, routes, DNS, IPC server |
| `fvpn-gui.exe` | Tray app / window (Wails, WebView2) |
| `fvpn-ctl.exe` | CLI client: `status`, `profiles`, `logs`, `connect`, `disconnect` |
| `fvpn-closegui.exe` | Embedded in the MSI, not installed: closes running app instances before files are replaced. |
| `fvpn-probe` | Logs in, prints the gateway's tunnel configuration, logs out. No tunnel, no admin. |
| `fvpn-cli` | Brings the tunnel up inside a userspace TCP/IP stack (gVisor) to test DNS/TCP/ping or serve a loopback SOCKS5 proxy. Changes nothing on the host. |

## Install

Run `FVPN-<version>.msi` once as administrator. It installs to
`C:\Program Files\FVPN`, registers the `fvpn` service and allows the installing
user to use the pipe. Afterwards, as an administrator:

```bat
fvpn-svc profile-add -id main -name "Main" -server vpn.example.com:10443 -trusted-cert <SHA256>
fvpn-svc allow-user DOMAIN\someone
fvpn-svc lock-profiles on
fvpn-svc show
```

Use `fvpn-probe -server vpn.example.com:10443` first to see the certificate
fingerprint and what the gateway pushes.

## Build

Cross-compiled from Linux:

- Go (see `go.mod`), Wails CLI v2
- `wixl` / `msibuild` from msitools for the MSI (`build.sh` expects them under
  `~/.local/opt/msitools`)

```sh
./build.sh   # vet + tests, Windows binaries in bin/windows, MSI in bin/
```

`go test ./...` runs the protocol, PPP, routing and engine tests on any OS.

## Security notes

- Passwords are never stored; reconnecting requires full re-authentication.
- The service only accepts pipe clients listed in its configuration.
- Unsigned binaries may trigger SmartScreen/EDR warnings; sign them or add an
  allow-list rule (see `bin/windows/SHA256SUMS`).

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT, see [LICENSE](LICENSE). Third-party components: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

FVPN is not affiliated with or endorsed by Fortinet, Inc.
