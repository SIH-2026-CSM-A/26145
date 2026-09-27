# /// script
# requires-python = ">=3.11"
# dependencies = ["pillow"]
# ///
"""Render a terminal-style PNG of the tamper-evidence check, for slides.

Every command shown is run for real, in a temp dir, and its real output is drawn. The steps:
analyze the demo capture into a DB, verify-log passes, one byte of one alert's stored JSON is
changed with Python's sqlite3 module, and verify-log reports BROKEN at that index.

Usage: uv run --script scripts/render_verify_log.py OUT.png
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parents[1]
INDEX = 3  # the alert whose stored JSON gets one byte changed
EDIT = f"""python3 - <<'EOF'
import re, sqlite3
db = sqlite3.connect("demo.db")
(raw,) = db.execute("SELECT json_data FROM alerts WHERE seq = {INDEX}").fetchone()
i = re.search(r'"dst_port": *', raw).end()                # first digit of the port
new = raw[:i] + str((int(raw[i]) + 1) % 10) + raw[i + 1:]   # one byte changed
db.execute("UPDATE alerts SET json_data = ? WHERE seq = {INDEX}", (new,)); db.commit()
print(f"alert #{INDEX}: dst_port {{raw[i]}}... -> {{new[i]}}...")
EOF"""
STEPS = [
    ("sih26145 analyze demo/demo.pcap --db demo.db", 0),
    ("sih26145 verify-log --db demo.db", 0),
    (EDIT, 0),
    ("sih26145 verify-log --db demo.db", 1),
]


def run_steps(work: Path) -> list[tuple[str, str]]:
    env = dict(os.environ, PATH=f"{REPO / '.venv' / 'bin'}:{os.environ['PATH']}",
               SIH26145_INTERNAL_CIDRS="147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12")
    (work / "demo").mkdir()
    (work / "demo" / "demo.pcap").symlink_to(REPO / "demo" / "demo.pcap")
    out = []
    for cmd, want in STEPS:
        p = subprocess.run(["bash", "-c", cmd], cwd=work, env=env, capture_output=True, text=True)
        if p.returncode != want:
            sys.exit(f"step failed ({p.returncode}): {cmd}\n{p.stdout}{p.stderr}")
        out.append((cmd, p.stdout.rstrip("\n")))
    n = int(re.search(r"verified: (\d+) records", out[1][1]).group(1))
    assert n > INDEX, out[1][1]
    assert out[3][1].startswith(f"BROKEN at index {INDEX} of {n}:"), out[3][1]
    return out


W, H, PAD = 1920, 1080, 64
# the dashboard's tokens (dashboard/src/index.css) and its bundled fonts (@fontsource-variable)
INK, PANEL, LINE = "#040814", "#0e1832", "#26395f"
FG, DIM, GREEN, RED, PROMPT = "#e6edf7", "#9aa8c0", "#34d399", "#f43f5e", "#5ee6ff"
FONTS = REPO / "dashboard" / "node_modules" / "@fontsource-variable"
MONO = FONTS / "jetbrains-mono" / "files" / "jetbrains-mono-latin-wght-normal.woff2"
NOLIG = ["-calt", "-liga"]  # JetBrains Mono would draw "--" and "->" as ligatures
SANS = FONTS / "space-grotesk" / "files" / "space-grotesk-latin-wght-normal.woff2"


def face(path: Path, size: int, weight: int) -> ImageFont.FreeTypeFont:
    f = ImageFont.truetype(str(path), size)
    f.set_variation_by_axes([weight])
    return f


def render(transcript: list[tuple[str, str]], path: str, size: int = 26) -> None:
    font, bold = face(MONO, size, 400), face(MONO, size, 700)
    img = Image.new("RGB", (W, H), INK)
    d = ImageDraw.Draw(img)
    for gx in range(0, W, 48):  # the page's faint grid
        d.line([(gx, 0), (gx, H)], fill="#0a1226")
    for gy in range(0, H, 48):
        d.line([(0, gy), (W, gy)], fill="#0a1226")
    box = [32, 32, W - 32, H - 32]
    d.rounded_rectangle(box, radius=22, fill=PANEL, outline=LINE, width=1)
    d.line([(32, 104), (W - 32, 104)], fill=LINE)
    d.text((64, 68), "SAAKSHI", font=face(SANS, 30, 700), fill=FG, anchor="lm")
    d.text((230, 68), "tamper-evident alert log · SHA-256 hash chain · every command below ran for real",
           font=face(SANS, 24, 400), fill=DIM, anchor="lm")
    y, line_h = 104 + PAD // 2 + 8, int(size * 1.5)
    cols = int((W - 2 * PAD - 64) // font.getlength("m"))

    def line(text, fill, f=font, x=PAD + 32):
        nonlocal y
        for k in range(0, max(len(text), 1), cols):
            d.text((x, y), text[k:k + cols], font=f, fill=fill, features=NOLIG)
            y += line_h

    for cmd, output in transcript:
        first, *rest = cmd.split("\n")
        d.text((PAD + 32, y), "$ ", font=bold, fill=PROMPT, features=NOLIG)
        line(first, FG, bold, PAD + 32 + int(font.getlength("$ ")))
        for r in rest:
            line("> " + r, DIM)
        for o in output.split("\n"):
            line(o, GREEN if o.startswith("verified") else RED if o.startswith("BROKEN") else DIM,
                 bold if o.startswith(("verified", "BROKEN")) else font)
        y += line_h // 2
    if y > H - 48:
        return render(transcript, path, size - 1)  # shrink until the whole transcript fits
    img.save(path, optimize=True)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        t = run_steps(Path(tmp))
    render(t, sys.argv[1])
    print("\n".join(o for _, o in t))
    print("wrote", sys.argv[1])
