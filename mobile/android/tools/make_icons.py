#!/usr/bin/env python3
"""Generate the app's launcher icons + header mark from the
owners' Concept 2 ring artwork (a white mark on black).

The artwork's geometry is used untouched; only the colours
are mapped onto the locked palette: the black background
becomes navy (#0A2540) and the mark stays white, exactly as
drawn. The mark's alpha comes from the artwork's luminance
(black -> transparent), so edges anti-alias cleanly.

Inputs : the source .webp (white on black, square).
Outputs: res/mipmap-*/ic_launcher.png (+ _round, same art)
         app assets/ring-mark.png (transparent-bg mark for
         the in-app header, drawn over the navy tile).

Usage: make_icons.py <source.webp> <app-main-dir>
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw

NAVY = (10, 37, 64, 255)
WHITE = (255, 255, 255, 255)

SIZES = {  # density -> launcher px
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192,
}


def mark_alpha(src: Image.Image) -> Image.Image:
    """White-on-black artwork -> alpha mask (luminance)."""
    return src.convert("L")


def main() -> None:
    src_path, app_main = Path(sys.argv[1]), Path(sys.argv[2])
    src = Image.open(src_path).convert("RGB")
    alpha = mark_alpha(src)

    # Launcher icons: navy field, white mark over the whole
    # canvas (the artwork's own margins set the ring size).
    for density, px in SIZES.items():
        icon = Image.new("RGBA", (px, px), NAVY)
        a = alpha.resize((px, px), Image.LANCZOS)
        icon.paste(Image.new("RGBA", (px, px), WHITE), (0, 0), a)
        out = app_main / "res" / density
        out.mkdir(parents=True, exist_ok=True)
        icon.save(out / "ic_launcher.png")
        icon.save(out / "ic_launcher_round.png")
        print("wrote", out / "ic_launcher.png", px)

    # Header mark: transparent background, white mark; the
    # header lays it over its own navy tile.
    size = 512
    header = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    a = alpha.resize((size, size), Image.LANCZOS)
    header.paste(Image.new("RGBA", (size, size), WHITE), (0, 0), a)
    assets = app_main / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    header.save(assets / "ring-mark.png")
    print("wrote", assets / "ring-mark.png", size)


if __name__ == "__main__":
    main()
