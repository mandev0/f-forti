"""Generates the FVPN icons with no dependencies.

  python3 -I tools/mkicon.py

writes, all from the same drawing (blue rounded tile, white shield, keyhole):
  gui/build/appicon.png             application icon
  gui/build/windows/icon.ico        exe / taskbar icon (written here so it can
                                    never go stale against appicon.png)
  gui/frontend/dist/logo.svg        in-app logo (main view, About)
  gui/tray/{idle,ok,busy,err}.ico   tray icons: same tile, grey when not
                                    connected, status dot bottom-right
"""
import os
import struct
import zlib

BLUE = (28, 100, 242)  # #1c64f2, same as --accent in app.css
GREY = (110, 118, 129)
WHITE = (255, 255, 255)
GREEN = (26, 160, 70)
AMBER = (230, 160, 0)
RED = (215, 40, 50)


def in_rounded_rect(x, y, r=0.2):
    cx = min(max(x, r), 1 - r)
    cy = min(max(y, r), 1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def in_shield(x, y):
    if y < 0.13 or y > 0.86:
        return False
    half = 0.30
    if y <= 0.52:
        return abs(x - 0.5) <= half
    t = (y - 0.52) / (0.86 - 0.52)
    return abs(x - 0.5) <= half * (1 - t ** 1.6)


def in_keyhole(x, y):
    if (x - 0.5) ** 2 + (y - 0.42) ** 2 <= 0.075 ** 2:
        return True
    return abs(x - 0.5) <= 0.035 and 0.42 <= y <= 0.64


def sample_app(x, y):
    if not in_rounded_rect(x, y):
        return None
    if in_shield(x, y) and not in_keyhole(x, y):
        return WHITE
    return BLUE


def make_tray_sampler(tile, dot):
    # Tray: the app icon itself (tile colour reflects the state) with an
    # optional status dot bottom-right inside a white ring.
    def s(x, y):
        if dot is not None:
            d = (x - 0.79) ** 2 + (y - 0.79) ** 2
            if d <= 0.18 ** 2:
                return dot
            if d <= 0.23 ** 2:
                return WHITE
        if not in_rounded_rect(x, y):
            return None
        if in_shield(x, y) and not in_keyhole(x, y):
            return WHITE
        return tile
    return s


def shield_svg_path(steps=24):
    # Same outline as in_shield(), in a 100x100 box.
    pts = [(20, 13), (80, 13), (80, 52)]
    for i in range(1, steps + 1):
        t = i / steps
        pts.append((50 + 30 * (1 - t ** 1.6), 52 + 34 * t))
    for i in range(steps - 1, -1, -1):
        t = i / steps
        pts.append((50 - 30 * (1 - t ** 1.6), 52 + 34 * t))
    pts.append((20, 13))
    return "M" + " L".join("%.2f %.2f" % p for p in pts) + "Z"


def write_svg(path):
    blue = "#%02x%02x%02x" % BLUE
    keyhole = "M46.5 42 h7 v22 h-7Z"
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
        '<rect width="100" height="100" rx="20" fill="%s"/>'
        '<path fill="#fff" fill-rule="evenodd" d="%s"/>'
        '<circle cx="50" cy="42" r="7.5" fill="%s"/>'
        '<path fill="%s" d="%s"/>'
        "</svg>\n" % (blue, shield_svg_path(), blue, blue, keyhole)
    )
    with open(path, "w") as f:
        f.write(svg)


def render(n, sampler, ss=4):
    px = []
    for py in range(n):
        row = []
        for pxx in range(n):
            r = g = b = a = 0
            for sy in range(ss):
                for sx in range(ss):
                    c = sampler((pxx + (sx + 0.5) / ss) / n, (py + (sy + 0.5) / ss) / n)
                    if c is not None:
                        r += c[0]; g += c[1]; b += c[2]; a += 1
            if a:
                row.append((round(r / a), round(g / a), round(b / a), round(255 * a / (ss * ss))))
            else:
                row.append((0, 0, 0, 0))
        px.append(row)
    return px


def write_png(path, px):
    with open(path, "wb") as f:
        f.write(png_bytes(px))


def png_bytes(px):
    n = len(px)
    raw = bytearray()
    for row in px:
        raw.append(0)
        for p in row:
            raw.extend(p)

    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0))
    data += chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")
    return data


def dib(px):
    n = len(px)
    hdr = struct.pack("<IiiHHIIiiII", 40, n, n * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    xor = bytearray()
    for row in reversed(px):  # bottom-up
        for r, g, b, a in row:
            xor.extend((b, g, r, a))
    stride = ((n + 31) // 32) * 4
    andmask = bytes(stride * n)  # alpha channel decides transparency
    return hdr + bytes(xor) + andmask


def write_ico(path, images):
    entries, blobs = [], []
    off = 6 + 16 * len(images)
    for px in images:
        n = len(px)
        b = png_bytes(px) if n >= 256 else dib(px)  # 256 px entry as PNG (Vista+)
        entries.append(struct.pack("<BBBBHHII", n % 256, n % 256, 0, 0, 1, 32, len(b), off))
        blobs.append(b)
        off += len(b)
    with open(path, "wb") as f:
        f.write(struct.pack("<HHH", 0, 1, len(images)))
        for e in entries:
            f.write(e)
        for b in blobs:
            f.write(b)


def main():
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    write_png(os.path.join(root, "gui/build/appicon.png"), render(512, sample_app, ss=3))
    write_ico(os.path.join(root, "gui/build/windows/icon.ico"),
              [render(n, sample_app) for n in (16, 20, 24, 32, 40, 48, 64, 256)])
    write_svg(os.path.join(root, "gui/frontend/dist/logo.svg"))
    tray = os.path.join(root, "gui/tray")
    os.makedirs(tray, exist_ok=True)
    variants = {
        "idle": make_tray_sampler(GREY, None),
        "ok": make_tray_sampler(BLUE, GREEN),
        "busy": make_tray_sampler(BLUE, AMBER),
        "err": make_tray_sampler(GREY, RED),
    }
    for name, s in variants.items():
        write_ico(os.path.join(tray, name + ".ico"), [render(n, s) for n in (16, 20, 24, 32, 40, 48)])
        write_png(os.path.join(tray, name + "-preview.png"), render(64, s))


if __name__ == "__main__":
    main()
