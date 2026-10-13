"""Кадры панели в webp для лендинга.

Берет готовые скриншоты из docs/img (их снимает docs/make-shots.py) и кладет в
landing/site/shots/<язык>/ двумя размерами: полным для героя и лайтбокса и
уменьшенным для галереи. Там же og.png, картинка для превью ссылки: webp
понимают не все мессенджеры.
"""
import os

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "docs", "img")
DST = os.path.join(ROOT, "landing", "site", "shots")
SHOTS = ("home", "environment", "history", "servers", "access")
SMALL = 960
OG = (1200, 630)


def scaled(im, width):
    return im.resize((width, round(im.height * width / im.width)), Image.LANCZOS)


for lang, sub in (("ru", "ru"), ("en", "")):
    out = os.path.join(DST, lang)
    os.makedirs(out, exist_ok=True)
    for name in SHOTS:
        im = Image.open(os.path.join(SRC, sub, name + ".png")).convert("RGB")
        im.save(os.path.join(out, name + ".webp"), "WEBP", quality=82, method=6)
        small = scaled(im, SMALL)
        small.save(os.path.join(out, f"{name}-{SMALL}.webp"), "WEBP", quality=84, method=6)
        kb = os.path.getsize(os.path.join(out, name + ".webp")) // 1024
        kb_small = os.path.getsize(os.path.join(out, f"{name}-{SMALL}.webp")) // 1024
        print(f"{lang}/{name}: {im.width}x{im.height} {kb} KB, {SMALL} {kb_small} KB")

    home = Image.open(os.path.join(SRC, sub, "home.png")).convert("RGB")
    og = scaled(home, OG[0]).crop((0, 0) + OG)
    og.save(os.path.join(out, "og.png"), optimize=True)
    print(f"{lang}/og.png: {os.path.getsize(os.path.join(out, 'og.png')) // 1024} KB")
