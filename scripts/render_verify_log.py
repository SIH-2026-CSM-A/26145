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


W, H, PAD = 1920, 1080, 48
BG, FG, DIM, GREEN, RED, PROMPT = "#0b1220", "#e2e8f0", "#64748b", "#4ade80", "#f87171", "#38bdf8"


def render(transcript: list[tuple[str, str]], path: str, size: int = 26) -> None:
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size)
    bold = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", size)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 56], fill="#1e293b")
    for k, c in enumerate(("#f87171", "#fbbf24", "#4ade80")):
        d.ellipse([24 + k * 34, 18, 44 + k * 34, 38], fill=c)
    d.text((W // 2, 28), "sih26145: tamper-evident alert log (SHA-256 hash chain)", font=font, fill=DIM, anchor="mm")
    y, line_h, cols = 56 + PAD, int(size * 1.45), int((W - 2 * PAD) // font.getlength("m"))

    def line(text, fill, f=font, x=PAD):
        nonlocal y
        for k in range(0, max(len(text), 1), cols):
            d.text((x, y), text[k:k + cols], font=f, fill=fill)
            y += line_h

    for cmd, output in transcript:
        first, *rest = cmd.split("\n")
        d.text((PAD, y), "$ ", font=bold, fill=PROMPT)
        line(first, FG, bold, PAD + int(font.getlength("$ ")))
        for r in rest:
            line("> " + r, FG)
        for o in output.split("\n"):
            line(o, GREEN if o.startswith("verified") else RED if o.startswith("BROKEN") else DIM)
        y += line_h // 2
    if y > H - PAD // 2:
        return render(transcript, path, size - 1)  # shrink until the whole transcript fits
    img.save(path, optimize=True)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        t = run_steps(Path(tmp))
    render(t, sys.argv[1])
    print("\n".join(o for _, o in t))
    print("wrote", sys.argv[1])
