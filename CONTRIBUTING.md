# Contributing to FVPN

Thanks for helping. Bug reports, gateway compatibility reports and pull
requests are all welcome.

## Reporting

- **Bugs:** use the [bug report](../../issues/new?template=bug-report.yml)
  form.
- **Does FVPN work with your gateway?** Use the
  [gateway compatibility](../../issues/new?template=gateway-compatibility.yml)
  form, whether it works or not. These reports are how FVPN learns about
  gateways other than the one it was written against.
- **Security problems:** do not open an issue. See [SECURITY.md](SECURITY.md).

Before you paste logs, remove gateway addresses, usernames, internal
domains and certificate details.

## Building

FVPN is cross-compiled from Linux (or WSL). You need:

- Go, at the version in `go.mod`
- the Wails CLI v2, at the version in `go.mod`:
  `go install github.com/wailsapp/wails/v2/cmd/wails@<version>`
- `wixl`, `msibuild` and `msiinfo` for the MSI: `sudo apt install wixl msitools`.
  Without root, unpack the Ubuntu packages into `~/.local/opt/msitools/root`
  (`apt-get download` + `dpkg -x`); `build.sh` looks there too.

Then:

```sh
./build.sh   # vet + tests, Windows binaries in bin/windows, MSI in bin/
go test ./...  # protocol, PPP, routing and engine tests; runs on any OS
```

CI ([.github/workflows/build.yml](.github/workflows/build.yml)) runs
`build.sh` on every push and pull request.

## Testing against a gateway

Two developer tools, `fvpn-probe` and `fvpn-cli`, are not shipped to users.
They run on Linux too and change nothing on the host:

```sh
bin/fvpn-probe -server vpn.example.com:10443          # login + tunnel config
bin/fvpn-cli -server vpn.example.com:10443 -socks 127.0.0.1:1080
```

`fvpn-probe` signs in, prints the tunnel configuration and hints (SAML,
host check, full tunnel) and signs out; `-redact` masks addresses for
sharing. `fvpn-cli` brings the tunnel up inside a userspace TCP/IP stack (gVisor), runs
DNS/TCP/ping checks and can serve a loopback SOCKS5 proxy.

## Pull requests

- Keep changes focused; one topic per pull request.
- `./build.sh` must pass (it runs `go vet` for Linux and Windows and all
  tests).
- Add tests for protocol, parsing and routing changes. Pure logic lives in
  packages that build on any OS (for example `internal/opcli`,
  `internal/netcfg`) so it can be tested without Windows.
- Add a line to [CHANGELOG.md](CHANGELOG.md) under **Unreleased** for
  user-visible changes.
- The UI is plain HTML/CSS/JS in `gui/frontend/dist` (no build step) and is
  English only.

## Releases

Bump `version` in `gui/main.go` and `productVersion` in `gui/wails.json`,
move the **Unreleased** changelog entries under the new version, then push a
tag `vX.Y.Z`. CI checks that the tag matches and creates a draft release
with the MSI and `SHA256SUMS`.
