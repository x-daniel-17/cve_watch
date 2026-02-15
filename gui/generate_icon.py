#!/usr/bin/env python3
"""Generate the CVE Watch app icon (.icns) using Pillow.

Draws a shield with an eye/scan motif on a gradient background.
Run: python generate_icon.py
Produces: AppIcon.icns
"""

import math
import os
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def draw_shield(draw: ImageDraw.ImageDraw, cx: float, cy: float, size: float, fill: str, outline: str | None = None, width: int = 0):
    """Draw a shield shape centered at (cx, cy)."""
    # Shield: rounded top, pointed bottom
    w = size * 0.45
    h = size * 0.52
    top = cy - h * 0.45
    bottom = cy + h * 0.55
    mid = cy + h * 0.05

    # Build shield path as polygon points
    points = []
    steps = 30

    # Left side curve (top-left to mid-left)
    for i in range(steps + 1):
        t = i / steps
        x = cx - w + (w * 0.05) * math.sin(t * math.pi * 0.5)
        y = top + (mid - top) * t
        points.append((x, y))

    # Bottom point
    for i in range(steps + 1):
        t = i / steps
        angle = math.pi * 0.5 + math.pi * t
        x = cx + w * math.cos(angle) * (1 - t * 0.15)
        y = mid + (bottom - mid) * t
        points.append((x, y))

    # Right side curve (mid-right to top-right)
    for i in range(steps + 1):
        t = i / steps
        x = cx + w - (w * 0.05) * math.sin((1 - t) * math.pi * 0.5)
        y = mid + (top - mid) * t
        points.append((x, y))

    draw.polygon(points, fill=fill, outline=outline, width=width)


def draw_icon(size: int) -> Image.Image:
    """Draw the CVE Watch icon at the given pixel size."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cx, cy = size / 2, size / 2
    margin = size * 0.08
    inner = size - margin * 2

    # Background: rounded rectangle with dark blue gradient feel
    # We'll draw concentric rounded rects for a gradient effect
    bg_colors = [
        (25, 35, 60),    # dark blue-gray
        (30, 42, 72),
        (35, 50, 85),
        (38, 55, 95),
        (42, 62, 108),
    ]
    r = size * 0.22  # corner radius

    for i, color in enumerate(bg_colors):
        inset = margin + (inner * 0.02) * i
        box = [inset, inset, size - inset, size - inset]
        draw.rounded_rectangle(box, radius=r - i, fill=color)

    # Main shield - steel blue
    shield_size = inner * 0.88

    # Shield shadow
    draw_shield(draw, cx + size * 0.01, cy + size * 0.02, shield_size, fill=(15, 20, 35))

    # Shield body - gradient-like with two overlapping shields
    draw_shield(draw, cx, cy, shield_size, fill=(55, 90, 140))
    draw_shield(draw, cx, cy - size * 0.005, shield_size * 0.97, fill=(70, 115, 170))

    # Inner shield highlight
    draw_shield(draw, cx, cy, shield_size * 0.82, fill=(85, 135, 195))

    # Draw a stylized eye/scan icon in the center of the shield
    eye_cx = cx
    eye_cy = cy + size * 0.02

    # Magnifying glass circle
    glass_r = size * 0.12
    glass_lw = max(2, int(size * 0.025))

    # Glass circle
    draw.ellipse(
        [eye_cx - glass_r, eye_cy - glass_r, eye_cx + glass_r, eye_cy + glass_r],
        outline=(220, 235, 255),
        width=glass_lw,
    )

    # Inner dot (representing scan/search focus)
    dot_r = glass_r * 0.35
    draw.ellipse(
        [eye_cx - dot_r, eye_cy - dot_r, eye_cx + dot_r, eye_cy + dot_r],
        fill=(220, 235, 255),
    )

    # Glass handle
    handle_start_x = eye_cx + glass_r * 0.7
    handle_start_y = eye_cy + glass_r * 0.7
    handle_end_x = eye_cx + glass_r * 1.6
    handle_end_y = eye_cy + glass_r * 1.6
    draw.line(
        [(handle_start_x, handle_start_y), (handle_end_x, handle_end_y)],
        fill=(220, 235, 255),
        width=glass_lw + max(1, int(size * 0.008)),
    )

    # Small warning triangle at top-right of shield
    tri_cx = cx + size * 0.11
    tri_cy = cy - size * 0.12
    tri_size = size * 0.065
    tri_points = [
        (tri_cx, tri_cy - tri_size),
        (tri_cx - tri_size * 0.85, tri_cy + tri_size * 0.6),
        (tri_cx + tri_size * 0.85, tri_cy + tri_size * 0.6),
    ]
    draw.polygon(tri_points, fill=(255, 180, 60))

    # Exclamation mark inside triangle
    exc_lw = max(1, int(size * 0.012))
    exc_top = tri_cy - tri_size * 0.45
    exc_bot = tri_cy + tri_size * 0.15
    draw.line([(tri_cx, exc_top), (tri_cx, exc_bot)], fill=(40, 30, 10), width=exc_lw)
    dot_sz = max(1, int(size * 0.01))
    draw.ellipse(
        [tri_cx - dot_sz, tri_cy + tri_size * 0.3 - dot_sz,
         tri_cx + dot_sz, tri_cy + tri_size * 0.3 + dot_sz],
        fill=(40, 30, 10),
    )

    return img


def main():
    script_dir = Path(__file__).resolve().parent

    # macOS icon sizes needed for .iconset
    # format: (filename, pixel_size)
    icon_sizes = [
        ("icon_16x16.png", 16),
        ("icon_16x16@2x.png", 32),
        ("icon_32x32.png", 32),
        ("icon_32x32@2x.png", 64),
        ("icon_128x128.png", 128),
        ("icon_128x128@2x.png", 256),
        ("icon_256x256.png", 256),
        ("icon_256x256@2x.png", 512),
        ("icon_512x512.png", 512),
        ("icon_512x512@2x.png", 1024),
    ]

    # Create iconset directory
    iconset_dir = script_dir / "AppIcon.iconset"
    iconset_dir.mkdir(exist_ok=True)

    # Generate the icon at 1024px and resize for each needed size
    print("Generating icon variants...")
    master = draw_icon(1024)

    for filename, px in icon_sizes:
        if px == 1024:
            img = master.copy()
        else:
            img = master.resize((px, px), Image.LANCZOS)
        img.save(iconset_dir / filename, "PNG")
        print(f"  {filename} ({px}x{px})")

    # Convert to .icns using iconutil
    icns_path = script_dir / "AppIcon.icns"
    print(f"\nCreating {icns_path.name}...")
    subprocess.run(
        ["iconutil", "-c", "icns", str(iconset_dir), "-o", str(icns_path)],
        check=True,
    )
    print(f"✓ {icns_path}")

    # Clean up iconset
    import shutil
    shutil.rmtree(iconset_dir)


if __name__ == "__main__":
    main()
