# TODO

## Roadmap: gateway compatibility

These keep FVPN from working with many gateways. Each needs its own design
before implementation.

- [ ] **Full tunnel.** Today a configuration without split routes, or with a
      default route, is refused (`internal/netcfg`). Needs: a default route
      over the tunnel (split 0.0.0.0/1 + 128.0.0.0/1), the gateway host route
      kept on the physical interface, DNS forced to the tunnel, and a clean
      restore on disconnect, crash or service stop.
- [ ] **Block IPv6 while connected** (prerequisite for full tunnel). The
      tunnel carries IPv4 only, so IPv6 traffic would bypass it. Options:
      firewall (WFP) rules or unbinding IPv6 for the session.
- [ ] **SAML / SSO login** (Entra ID, Okta, ...). The login page hint is
      already detected (`internal/forti/client.go`). Needs: opening the
      gateway's SAML URL in a browser or an embedded WebView2, catching the
      redirect back with the session cookie, then the usual tunnel setup.
- [ ] **Client certificate authentication.** Use a certificate from the
      Windows certificate store (CNG) for the TLS handshake.
- [ ] **Clear errors at connect time.** Only full tunnel gets a clear message
      today. SAML and host-check hints are detected by `fvpn-probe` only
      (`LoginPage` hints, `LastRedir`); the service should report "this
      gateway uses SAML/host check, which is not supported" instead of a
      generic login failure.
- [ ] **Host check.** Not planned to be implemented; document it as
      unsupported (done in the README) and give a clear error (see above).
- [ ] (Later) FortiOS 7.6.3+ removes SSL-VPN tunnel mode, so IPsec/IKEv2
      would be needed.

## Code signing / EDR allow-listing

Plan: builds already run in GitHub Actions. Now that the repository is
public, apply to the SignPath Foundation for free open-source code signing.

Unsigned Go binaries (especially `fvpn-svc.exe`, which installs a service,
loads a driver and tunnels network traffic) can trip Defender/EDR heuristics,
and SmartScreen warns about unsigned executables.

- [ ] Get a code signing certificate (ideally EV, or OV kept in an HSM).
- [ ] If there is one: sign `fvpn-svc.exe`, `fvpn-gui.exe` and
      `fvpn-ctl.exe` with
      `signtool sign /fd sha256 /tr <RFC3161 timestamp URL> /td sha256`,
      adding a signing step after `build.sh` (on Windows, or with
      `osslsigncode`).
- [ ] If not: define an EDR allow-list rule. In order of preference:
      1. Publisher/certificate rule (if signed).
      2. SHA-256 rule: update with the hashes in `bin/windows/SHA256SUMS` for
         every release.
      3. Path rule (`C:\Program Files\FVPN\*`), the weakest; acceptable only
         because writing to that directory is limited to
         Administrators/SYSTEM.
- [x] `wintun.dll` is already signed by WireGuard LLC; nothing to do (its
      SHA-256 is verified at install time).
- [ ] If a signed release still gets flagged by Defender, submit it as a
      false positive: https://www.microsoft.com/wdsi/filesubmission

## 1Password

- [ ] `op.exe` signature check (`SignerOK` in `internal/opcli`): current
      releases are signed with Microsoft Trusted Signing (CN=O=Agilebits,
      C=CA, issued by "Microsoft ID Verified CS ..."); older ones by
      "AgileBits Inc.". If 1Password changes how it signs, FVPN rejects op.
      The error message shows the actual signer; update the rule to match.

## Deferred

- [ ] DTLS or the `tun` tunnel method (performance).
