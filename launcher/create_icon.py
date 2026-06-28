"""Generate assets/icon.ico for the Windows launcher executable."""

from __future__ import annotations

from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:
    raise SystemExit("Install Pillow first: pip install pillow")

ASSETS = Path(__file__).resolve().parent.parent / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)
OUT = ASSETS / "icon.ico"

SIZE = 256
img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Shield shape (SOC blue theme)
shield = [
    (128, 20), (220, 60), (220, 140), (128, 236), (36, 140), (36, 60),
]
draw.polygon(shield, fill=(13, 17, 23, 255), outline=(88, 166, 255, 255), width=6)

# Inner accent
inner = [(128, 50), (190, 80), (190, 130), (128, 200), (66, 130), (66, 80)]
draw.polygon(inner, fill=(31, 41, 55, 255))

# Checkmark (defensive / verified)
draw.line((90, 130, 115, 160), fill=(63, 185, 80, 255), width=12)
draw.line((115, 160, 175, 95), fill=(63, 185, 80, 255), width=12)

# Save multi-resolution ICO
sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
icons = [img.resize(s, Image.Resampling.LANCZOS) for s in sizes]
icons[0].save(OUT, format="ICO", sizes=[(i.width, i.height) for i in icons])
print(f"Created {OUT}")
