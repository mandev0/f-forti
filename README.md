# FVPN

An unofficial FortiGate SSL-VPN client for Windows, written in Go.

FVPN signs in to a FortiGate SSL-VPN gateway (username, password and a second
factor), then brings the tunnel up on a Wintun adapter. Daily use needs no
administrator rights. A small Windows service owns the adapter, routes and
DNS, and the tray app talks to it over a locked-down named pipe.

> **Status: early (0.9.x).** FVPN has been tested against only one gateway so
> far. Check [what is supported](#what-is-supported) before you install it.
> If it works (or fails) with your gateway, please
> [report it](../../issues/new?template=gateway-compatibility.yml).

FVPN is not affiliated with or endorsed by Fortinet, Inc.

## What is supported

| Feature | Status |
|---|---|
| Username and password login, realms | Supported |
| Second factor: verification code (FortiToken, authenticator app) or FortiToken Mobile push | Supported |
| Split tunnel (the gateway sends a list of routes) | Supported |
| Split DNS (per-domain DNS servers, via NRPT rules) | Supported |
| Gateways with self-signed or private certificates (SHA-256 pinning) | Supported |
| Optional 1Password integration (credentials and TOTP code) | Supported |
| **Full tunnel** (all traffic through the VPN) | **Not supported yet.** The connection is refused. |
| **SAML / SSO login** (Entra ID, Okta, ...) | **Not supported yet** |
| Client certificate authentication | Not supported yet |
| Host check / FortiClient EMS compliance | Not supported |
| IPv6 inside the tunnel | Not supported (IPv4 only) |
| IPsec / IKEv2 | Not supported. Note: FortiOS 7.6.3 and later removed SSL-VPN tunnel mode. |
| Windows 10/11 x64 | Supported |
| Windows on ARM | Not supported yet |

## Quick start

1. **Download** `FVPN-<version>.msi` from the
   [latest release](../../releases/latest). Check it against `SHA256SUMS`
   if you like.
2. **Install it.** The installer asks for administrator rights once. It
   installs to `C:\Program Files\FVPN`, registers the `fvpn` service and
   allows the user who ran it to use the VPN.
3. **Add a profile.** Open FVPN from the Start menu or the tray, go to
   **Settings › Profiles › Add profile** and enter:
   - a name,
   - the gateway address, for example `vpn.example.com:10443` (the same
     address you would use in FortiClient),
   - the realm, only if your administrator gave you one.

   Click **Check** to look at the server certificate. If Windows does not
   trust it (common for company gateways), compare the fingerprint with the
   one your administrator gave you, then tick **Trust this certificate**.
4. **Connect.** Flip the switch on the main screen, enter your username and
   password, then the verification code (or approve the push on your phone).

### Optional: 1Password

If you use 1Password, FVPN can fill in the username and password for you
and, optionally, the TOTP code.

1. Install the 1Password CLI: `winget install AgileBits.1Password.CLI`.
2. In the 1Password app, turn on **Settings › Developer › Integrate with
   1Password CLI**.
3. In FVPN, turn on 1Password in **Settings**, then in the profile turn on
   **Sign in with 1Password** and enter the item name.
4. Choose where the **one-time password** comes from:
   - **From the same item:** the login item has a one-time password field.
   - **From another 1Password item:** keeps the two factors apart. This is
     safer, especially with the code item in another vault.
   - **Enter it myself:** you type the code from your own authenticator app
     or token. 1Password only fills in the username and password.

Click **Test** to check the item. Secret values are never shown, and they
never pass through the app's web view.

## Troubleshooting

**Windows SmartScreen or my antivirus blocks the installer.**
The binaries are not code-signed yet. Make sure you downloaded the MSI from
this repository's releases and that its hash matches `SHA256SUMS`. On a
managed PC, ask IT to add an allow-list rule (by hash, or by the path
`C:\Program Files\FVPN\*`).

**"The gateway sent no split-tunnel routes".**
Your gateway uses full tunnel, which FVPN does not support yet.

**FortiClient opens a browser to sign in.**
Your gateway uses SAML/SSO, which FVPN does not support yet.

**The certificate is "Not trusted by Windows".**
Many company gateways use a private certificate. Compare the fingerprint
with the one from your administrator before you tick **Trust this
certificate**. A trusted certificate is pinned: if the gateway later
presents a different one, FVPN refuses to connect until you check it again.

**Another Windows user on the same PC cannot connect.**
Only the user who installed FVPN may use it. An administrator can allow
more users: `fvpn-svc allow-user DOMAIN\name`.

**Where are the logs?**
In the app, under **Settings › Logs**. From a terminal, run
`fvpn-ctl logs`. The service log files are in `%ProgramData%\FVPN`.

When you [open an issue](../../issues/new/choose), remove gateway
addresses, usernames and certificate details from logs first.

## For administrators

The MSI can be deployed silently. `ALLOWUSER` sets the user who may use the
VPN (the default is the signed-in user):

```bat
msiexec /i FVPN-<version>.msi /qn ALLOWUSER=DOMAIN\name
```

Profiles and users can be managed from an elevated prompt. Once
`lock-profiles on` is set, users cannot add or edit profiles in the app:

```bat
fvpn-svc profile-add -id main -name "Main" -server vpn.example.com:10443 -trusted-cert <SHA256>
fvpn-svc allow-user DOMAIN\someone
fvpn-svc lock-profiles on
fvpn-svc show
```

`profile-add` also takes `-realm` and `-allowed-networks CIDR,...`, which
limits the routes accepted from the gateway. Configuration and logs live in
`%ProgramData%\FVPN` and are kept across upgrades and uninstalls.

## Components

| Binary | Purpose |
|---|---|
| `fvpn-svc.exe` | Windows service: tunnel, adapter, routes, DNS, IPC server |
| `fvpn-gui.exe` | Tray app and window (Wails, WebView2) |
| `fvpn-ctl.exe` | CLI client: `status`, `profiles`, `logs`, `connect`, `disconnect` |
| `fvpn-closegui.exe` | Embedded in the MSI, not installed: closes running app instances before files are replaced |

Developer tools for testing against a gateway (`fvpn-probe`, `fvpn-cli`) are
described in [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

- Passwords are never stored. Every connection signs in again from scratch.
- The service only accepts pipe clients listed in its configuration.
- Binaries are built in GitHub Actions from this repository. They are not
  packed (no UPX), and symbols are kept, which helps antivirus heuristics.

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Building

See [CONTRIBUTING.md](CONTRIBUTING.md). In short, on Linux with Go, the Wails
CLI and msitools installed:

```sh
./build.sh   # vet + tests, Windows binaries in bin/windows, MSI in bin/
```

## License

MIT, see [LICENSE](LICENSE). Third-party components:
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
