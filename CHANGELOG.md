# Changelog

All notable changes to FVPN are listed here. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
include breaking changes.

## 0.9.5 (2026-11-25)

### Added

- 1Password: a third choice for the one-time password, **Enter it myself**.
  1Password fills in only the username and password, and the app asks for
  the code from your own authenticator app or token. Previously this case
  ended in an error message.

### Changed

- The 1Password "One-time password from another item" checkbox is now a
  three-way choice: from the same item, from another item, or entered
  manually. Existing profiles keep their behaviour.
- README rewritten for end users: supported features, quick start,
  troubleshooting.

### Removed

- Unused alternative frontends (`gui/frontend/_alt`).

## 0.9.4

First public version.

- FortiGate SSL-VPN login with username, password and a second factor (code
  or FortiToken Mobile push), tunnel on a Wintun adapter.
- Split tunnel and split DNS (NRPT) from the gateway configuration,
  certificate pinning.
- LocalSystem service with a locked-down named pipe. The tray app and
  `fvpn-ctl` run without administrator rights.
- Optional 1Password CLI integration.
- MSI installer; `fvpn-probe` and `fvpn-cli` developer tools.
