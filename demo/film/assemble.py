"""Assembles the film from the rendered scenes, the live recording and the narration.

Each segment of plan.py lasts exactly as long as its narration. Live segments are cut from
out/live.mp4 around the events film-record.mjs logged; every cut in the recording carries a
visible "time skip" badge (nothing is sped up). Narration: one WAV per line at its cue, then
loudnorm to -16 LUFS. Subtitles: one cue per line (max 2 lines), burned in at 36 px and written
as a separate .srt.

Runs in the TTS venv (numpy, soundfile, Pillow, fontTools):
    .venv-tts/bin/python assemble.py OUT.mp4
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import numpy as np
import soundfile as sf
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont
from PIL import Image, ImageDraw, ImageFont

from plan import plan

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
FPS, RATE = 30, 24000
HOST = "192.168.1.66"
FONTS = HERE.parents[1] / "dashboard" / "node_modules" / "@fontsource-variable"


def ff(*args):
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *map(str, args)], check=True)


def static_font(weight: int, path: Path) -> Path:
    """Space Grotesk at one weight, as a TTF that libass and Pillow can load."""
    if not path.exists():
        f = TTFont(FONTS / "space-grotesk" / "files" / "space-grotesk-latin-wght-normal.woff2")
        f = instantiateVariableFont(f, {"wght": weight})
        f.flavor = None
        for rec in f["name"].names:  # a family name of its own, so libass picks exactly this file
            if rec.nameID in (1, 4, 16):
                rec.string = "SAAKSHI Sub"
            elif rec.nameID in (2, 17):
                rec.string = "Regular"
            elif rec.nameID == 6:
                rec.string = "SAAKSHI-Sub"
        f.save(path)
    return path


def badge(text: str, path: Path, font: Path) -> Path:
    f = ImageFont.truetype(str(font), 30)
    w = int(f.getlength(text)) + 110
    img = Image.new("RGBA", (w, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, w - 1, 63], radius=32, fill=(4, 8, 20, 230), outline=(251, 191, 36, 255), width=2)
    for k in (0, 1):  # a drawn "fast forward" sign, no emoji font needed
        x = 24 + k * 17
        d.polygon([(x, 20), (x + 17, 32), (x, 44)], fill=(251, 191, 36, 255))
    d.text((72, 32), text, font=f, fill=(230, 237, 247, 255), anchor="lm")
    img.save(path)
    return path


def live_windows(p: dict, ev: dict) -> dict:
    """Source windows in out/live.mp4 for each live segment: [(start, dur), ...]."""
    E, M = ev["events"], ev["marks"]
    lands = [e for e in E if e["kind"] == "land"]
    tile = {"THREAT_RECON_PORTSCAN": "tile-e", "THREAT_C2_BEACON": "tile-b", "THREAT_DNS_DGA": "tile-c", "THREAT_DNS_TUNNEL": "tile-c",
            "THREAT_ENCRYPTED_ANOMALY": "tile-d", "THREAT_EXFILTRATION": "tile-f", "THREAT_DDOS_VOLUME": "tile-a"}

    def landing(a):  # the spark of alert a lands on its tile at the first pulse after it arrived
        return next(e["t"] for e in lands if e["tile"] == tile[a["cls"]] and e["t"] > a["t"])

    alerts = [e for e in E if e["kind"] == "alert"]
    host = [a for a in alerts if a["src"] == HOST]
    first = lambda cls, pool=alerts: next(a for a in pool if a["cls"] == cls)  # noqa: E731
    w = {"quiet": [(M["page"] + 3.0, p["quiet"]["dur"])]}
    w["scan"] = [(landing(first("THREAT_RECON_PORTSCAN", host)) - 3.2, p["scan"]["dur"])]
    chain = [first(c, host) for c in ("THREAT_ENCRYPTED_ANOMALY", "THREAT_C2_BEACON", "THREAT_DNS_DGA", "THREAT_DNS_TUNNEL", "THREAT_EXFILTRATION")]
    n = round(p["chain"]["dur"] * FPS)
    sizes = [n // 5 + (1 if i < n % 5 else 0) for i in range(5)]
    w["chain"] = [(landing(a) - 0.66 * k / FPS, k / FPS) for a, k in zip(chain, sizes)]
    w["flood"] = [(landing(first("THREAT_DDOS_VOLUME")) - 3.4, p["flood"]["dur"])]
    for k in ("map", "case", "card", "fp"):
        w[k] = [(M[k], p[k]["dur"])]
    return w


def srt_time(t: float) -> str:
    ms = round(t * 1000)
    return f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d},{ms % 1000:03d}"


def main(dest: Path):
    p = {s["id"]: s for s in plan()}
    ev = json.loads((OUT / "live-events.json").read_text())
    win = live_windows(p, ev)
    font = static_font(600, OUT / "SAAKSHI-Sub.ttf")
    tmp = OUT / "pieces"
    tmp.mkdir(exist_ok=True)

    # 1. video pieces, frame exact; a badge on every piece that starts after a cut in the recording
    pieces, t, starts, prev_end, report = [], 0, {}, None, []
    for s in plan():
        starts[s["id"]] = t
        if s["kind"] == "scene":
            parts = [(OUT / "scenes" / f"{s['id']}.mp4", 0.0, s["dur"])]
        else:
            parts = [(OUT / "live.mp4", a, d) for a, d in win[s["id"]]]
        for src, a, d in parts:
            n = round(d * FPS)
            out = tmp / f"{len(pieces):02d}-{s['id']}.mp4"
            vf = f"fps={FPS}"
            args = ["-ss", f"{a:.3f}", "-i", src]
            if src.name == "live.mp4" and prev_end is not None and a - prev_end > 0.5:
                gap = a - prev_end
                b = badge(f"time skip · {gap:.0f} s cut", tmp / f"badge-{len(pieces)}.png", font)
                args += ["-i", b]
                vf = f"[0:v]fps={FPS}[v];[v][1:v]overlay=x=W-w-48:y=40:enable='lt(t,2.2)'"
                report.append(f"{s['id']}: {gap:.1f} s of the recording skipped")
            ff(*args, "-frames:v", n, "-filter_complex" if "overlay" in vf else "-vf", vf, "-an",
               "-c:v", "libx264", "-crf", "14", "-preset", "medium", "-pix_fmt", "yuv420p", out)
            if src.name == "live.mp4":
                if prev_end is not None and a < prev_end - 0.05:
                    raise SystemExit(f"{s['id']} overlaps the previous live piece by {prev_end - a:.2f} s")
                prev_end = a + n / FPS
            pieces.append(out)
            t += n / FPS
    total = t
    (tmp / "list.txt").write_text("".join(f"file '{x}'\n" for x in pieces))
    ff("-f", "concat", "-safe", "0", "-i", tmp / "list.txt", "-c", "copy", tmp / "video.mp4")

    # 2. narration at the cues, then -16 LUFS
    audio = np.zeros(int((total + 0.5) * RATE), dtype=np.float32)
    srt, cues = [], []
    for s in plan():
        for c in s["cues"]:
            w, sr = sf.read(OUT / "wav" / c["wav"], dtype="float32")
            assert sr == RATE
            at = starts[s["id"]] + c["at"]
            i = int(at * RATE)
            audio[i:i + len(w)] += w[: len(audio) - i]
            cues.append((at, at + len(w) / RATE, c["text"]))
    sf.write(tmp / "narration.wav", audio, RATE)
    ff("-i", tmp / "narration.wav", "-af", "loudnorm=I=-16:TP=-1.5:LRA=11", "-ar", 48000, tmp / "narration-16lufs.wav")

    # 3. subtitles: one cue per line, balanced over at most two lines
    for k, (a, b, text) in enumerate(cues, 1):
        lines = textwrap.wrap(text, width=max(40, len(text) // 2 + 6)) if len(text) > 62 else [text]
        assert len(lines) <= 2, text
        srt.append(f"{k}\n{srt_time(a)} --> {srt_time(b)}\n" + "\n".join(lines) + "\n")
    srt_path = dest.with_suffix(".srt")
    srt_path.write_text("\n".join(srt))
    (tmp / "subs.srt").write_text("\n".join(srt))

    # burned in from an ASS file at the film's own 1920x1080 (an SRT would be laid out on libass's
    # default 384x288 canvas, which scales the font and margins up ~3.75x)
    ass = ["[Script Info]", "ScriptType: v4.00+", "PlayResX: 1920", "PlayResY: 1080", "WrapStyle: 1", "",
           "[V4+ Styles]",
           "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, "
           "Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding",
           "Style: Sub,SAAKSHI Sub,36,&H00F7EDE6,&H00F7EDE6,&H38140804,&H38140804,0,0,0,0,100,100,0,0,3,12,0,2,160,160,48,1",
           "", "[Events]", "Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text"]
    at = lambda x: f"{int(x // 3600)}:{int(x // 60 % 60):02d}:{x % 60:05.2f}"  # noqa: E731
    for a, b, text in cues:
        lines = textwrap.wrap(text, width=max(40, len(text) // 2 + 6)) if len(text) > 62 else [text]
        ass.append(f"Dialogue: 0,{at(a)},{at(b)},Sub,,0,0,0,," + "\\N".join(lines))
    (tmp / "subs.ass").write_text("\n".join(ass) + "\n")
    ff("-i", tmp / "video.mp4", "-i", tmp / "narration-16lufs.wav",
       "-vf", f"ass={tmp / 'subs.ass'}:fontsdir={OUT}",
       "-r", FPS, "-c:v", "libx264", "-crf", "18", "-preset", "slow", "-pix_fmt", "yuv420p",
       "-c:a", "aac", "-b:a", "192k", "-ar", 48000, "-ac", 2, "-shortest", "-movflags", "+faststart", dest)
    print(f"film: {dest} ({total:.1f} s)")
    print(f"subtitles: {srt_path} ({len(cues)} cues)")
    print("\n".join(report))


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
