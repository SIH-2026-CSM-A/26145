"""Checks a finished film: a contact sheet of frames, and audio/subtitle sync.

For each subtitle cue it finds the first speech onset in the film's own audio track near the cue
start, and reports the offset. A cue whose onset is more than 120 ms off fails.
    .venv-tts/bin/python check.py FILM.mp4 SHEET.png
"""

import re
import subprocess
import sys
from pathlib import Path

import numpy as np
import soundfile as sf

film, sheet = Path(sys.argv[1]), Path(sys.argv[2])
dur = float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", film],
                           capture_output=True, text=True).stdout)
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", film, "-vf", f"fps={24 / dur},scale=640:-1,tile=4x6",
                "-frames:v", "1", sheet], check=True)
wav = sheet.with_suffix(".wav")
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", film, "-ac", "1", "-ar", "16000", wav], check=True)
a, sr = sf.read(wav)
env = np.sqrt(np.convolve(a ** 2, np.ones(160) / 160, mode="same"))  # 10 ms RMS
on = env > max(0.01, env.max() * 0.03)
worst, bad = 0.0, []
for m in re.finditer(r"(\d+):(\d+):(\d+),(\d+) --> ", film.with_suffix(".srt").read_text()):
    h, mi, s, ms = map(int, m.groups())
    t = h * 3600 + mi * 60 + s + ms / 1000
    lo, hi = int((t - 0.3) * sr), int((t + 0.3) * sr)
    idx = np.nonzero(on[lo:hi])[0]
    off = (idx[0] / sr - 0.3) if len(idx) else float("nan")
    worst = max(worst, abs(off)) if off == off else worst
    if not off == off or abs(off) > 0.12:
        bad.append(f"cue at {t:.2f} s: onset offset {off * 1000:.0f} ms")
print(f"duration {dur:.2f} s; worst onset offset {worst * 1000:.0f} ms over {len(re.findall(' --> ', film.with_suffix('.srt').read_text()))} cues")
print("\n".join(bad) or "all cues within 120 ms")
