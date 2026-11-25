#!/usr/bin/env bash
# Builds the Windows binaries into bin/windows, the installer bin/FVPN-<version>.msi
# and the Linux test tools into bin/.
# MSI tooling: wixl/msibuild/msiinfo from the system (apt install wixl
# msitools, as in CI) or, without root, unpacked from the Ubuntu packages
# into ~/.local/opt/msitools/root (apt-get download + dpkg -x).
# Symbols are kept on purpose (no -s -w): stripped Go binaries score worse
# with AV heuristics, and there is no packer (UPX) either.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.local/opt/go/bin:$HOME/go/bin:$HOME/.local/opt/node/bin:$PATH"

MSITOOLS="$HOME/.local/opt/msitools/root"
missing=()
for t in go wails; do command -v "$t" >/dev/null || missing+=("$t"); done
if [ ! -x "$MSITOOLS/usr/bin/wixl" ]; then
  for t in wixl msibuild msiinfo; do command -v "$t" >/dev/null || missing+=("$t"); done
fi
if [ ${#missing[@]} -gt 0 ]; then
  echo "missing tools: ${missing[*]} (see CONTRIBUTING.md › Building)" >&2
  exit 1
fi

OUT=bin/windows
mkdir -p "$OUT"

VERSION=$(sed -n 's/^const version = "\(.*\)"/\1/p' gui/main.go)
grep -q "\"productVersion\": \"$VERSION\"" gui/wails.json \
  || { echo "version mismatch: gui/main.go $VERSION vs gui/wails.json productVersion" >&2; exit 1; }

echo "== test"
go vet ./...
GOOS=windows go vet ./...
go test -count=1 ./... | grep -v 'no test files'

echo "== windows/amd64"
for c in fvpn-svc fvpn-ctl fvpn-probe fvpn-cli fvpn-closegui; do
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$OUT/$c.exe" "./cmd/$c"
done
(cd gui && wails build -platform windows/amd64 -skipbindings -trimpath -o fvpn-gui.exe >/dev/null)
cp gui/build/bin/fvpn-gui.exe "$OUT/"
cp third_party/wintun/amd64/wintun.dll "$OUT/"
cp third_party/wintun/LICENSE.txt "$OUT/wintun-LICENSE.txt"

echo "== linux (test tools)"
for c in fvpn-probe fvpn-cli; do
  CGO_ENABLED=0 go build -trimpath -o "bin/$c" "./cmd/$c"
done

echo "== msi"
if [ -x "$MSITOOLS/usr/bin/wixl" ]; then
  msitool() { local t=$1; shift; LD_LIBRARY_PATH="$MSITOOLS/usr/lib/x86_64-linux-gnu" "$MSITOOLS/usr/bin/$t" "$@"; }
else
  msitool() { "$@"; }
fi
MSI="bin/FVPN-$VERSION.msi"
rm -f "$MSI"   # never let a stale MSI pass the check below
msitool wixl \
  -a x64 -D Version="$VERSION" -D BinDir="$OUT" -o "$MSI" installer/fvpn.wxs \
  2>&1 | grep -v 'builder.vala:.*unimplemented' || true
[ -s "$MSI" ] || { echo "wixl failed" >&2; exit 1; }
# wixl only writes advertised shortcuts; point the Start menu entry at the exe.
msitool msibuild "$MSI" \
  -q "UPDATE \`Shortcut\` SET \`Target\` = '[#gui]' WHERE \`Shortcut\` = 'GuiStartMenu'"
# wixl cannot write exe-from-Binary actions; make CloseGui run fvpn-closegui
# from the Binary table (type 2 + 64 = continue on error, synchronous).
msitool msibuild "$MSI" \
  -q "UPDATE \`CustomAction\` SET \`Type\` = 66, \`Source\` = 'CloseGuiBin' WHERE \`Action\` = 'CloseGui'"
msitool msiinfo export "$MSI" CustomAction \
  | grep -qP '^CloseGui\t66\tCloseGuiBin\t' || { echo "CloseGui custom action patch failed" >&2; exit 1; }

(cd "$OUT" && sha256sum *.exe wintun.dll | tee SHA256SUMS)
sha256sum "$MSI"
