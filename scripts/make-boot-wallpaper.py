#!/usr/bin/env python3
"""Draws the boot-menu wallpaper: the ALDO TECH mark with the site URL below it.

The mark is assets/boot/aldotech-logo-mark.svg, the colours are those of
aldo.tech (navy background, light mark, amber URL). The mark and the URL sit in
the upper half, above Limine's menu entries (centred around y = 290 whatever
the screen size, because the image and the menu are both centred). Run it only when the artwork changes and commit the PNG: the ISO
build reads assets/boot/wallpaper.png and needs neither Pillow nor the font.

    scripts/make-boot-wallpaper.py FONT.ttf [OUT.png]

FONT is Unbounded 600 (SIL OFL), the typeface of the website.
"""
import sys

from PIL import Image, ImageDraw, ImageFont

W, H = 800, 600
NAVY, TEXT, AMBER = (44, 44, 68), (241, 242, 247), (255, 174, 43)
# The mark's two polygons and viewBox, from aldotech-logo-mark.svg.
MARK_A = [(512, 148), (645, 383), (380, 575), (578, 575), (196, 705)]
MARK_B = [(658, 407), (828, 706), (535, 494)]
BOX = (190, 140, 645, 575)
URL = "https://aldo.tech"
SS = 4  # supersampling for smooth polygon edges


def main() -> None:
    font_path = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "assets/boot/wallpaper.png"
    img = Image.new("RGB", (W * SS, H * SS), NAVY)
    d = ImageDraw.Draw(img)

    mark_w = 130
    s = mark_w * SS / BOX[2]
    top_y = 70
    left, top = (W - mark_w) / 2 * SS, top_y * SS
    for poly in (MARK_A, MARK_B):
        d.polygon([(left + (x - BOX[0]) * s, top + (y - BOX[1]) * s) for x, y in poly], fill=TEXT)
    img = img.resize((W, H), Image.LANCZOS)

    d = ImageDraw.Draw(img)
    font = ImageFont.truetype(font_path, 22)
    y = top_y + mark_w * BOX[3] / BOX[2] + 26
    d.text(((W - d.textlength(URL, font=font)) / 2, y), URL, font=font, fill=AMBER)
    img.save(out, optimize=True)


if __name__ == "__main__":
    main()
