"""Narration for the film: Kokoro-82M (Apache-2.0), offline once the weights are cached.

Runs in its own venv, not the product's (see demo/film/README.md):
    .venv-tts/bin/python tts.py phonemes            # print what Kokoro will say, per line
    .venv-tts/bin/python tts.py samples OUT_DIR      # 3 voices x the hook's first two lines
    .venv-tts/bin/python tts.py render VOICE OUT_DIR # one WAV per line + lines.json (beat, text, seconds)

Lines come from script.md: every "> " line under a "## N." beat heading is one subtitle unit.
"""

import json
import re
import sys
from pathlib import Path

import numpy as np
import soundfile as sf
from kokoro import KPipeline

HERE = Path(__file__).resolve().parent
RATE = 24000
SPEED = 0.9  # ~165 words a minute; Kokoro's 1.0 is ~185
# Pronunciation fixes, as misaki markup "[word](/phonemes/)". Spelled acronyms use letter names.
LEXICON = {
    "SAAKSHI": "[SAAKSHI](/sˈɑkʃi/)",
    "NTRO's": "[NTRO's](/ˌɛntˌiˌɑɹˈOz/)",
    "JA4": "[JA4](/ʤˌAˈA fˈɔɹ/)",
    "DGA": "[DGA](/dˌiʤˌiˈA/)",
    "C2": "[C2](/sˌiˈtu/)",
    "SHA-256": "[SHA-256](/ʃˈɑ tˈu fˈɪfti sˈɪks/)",
    "SYN": "[SYN](/sˈɪn/)",
    "Bharatiya": "[Bharatiya](/bˈɑɹətˌijə/)",
    "Sakshya": "[Sakshya](/sˈɑkʃjə/)",
    "Adhiniyam": "[Adhiniyam](/ʌdˈɪnijəm/)",
}


def lines(script: Path = HERE / "script.md"):
    beat = None
    for raw in script.read_text().splitlines():
        m = re.match(r"## (\d+)\.", raw)
        if m:
            beat = int(m.group(1))
        elif raw.startswith("> ") and beat:
            yield beat, raw[2:].strip()


def spoken(text: str) -> str:
    for word, markup in LEXICON.items():
        text = re.sub(rf"(?<![\w\[]){re.escape(word)}(?![\w\]])", markup, text)
    return text


def pipeline(voice: str) -> KPipeline:
    return KPipeline(lang_code="b" if voice.startswith("b") else "a", repo_id="hexgrad/Kokoro-82M")


def say(pipe: KPipeline, voice: str, text: str) -> tuple[np.ndarray, str]:
    audio, phon = [], []
    for r in pipe(spoken(text), voice=voice, speed=SPEED):
        audio.append(r.audio.numpy())
        phon.append(r.phonemes)
    a = np.concatenate(audio)
    # Kokoro pads each line with ~0.35 s lead and ~0.55 s tail of silence; keep 50/120 ms so
    # the film's own line gap sets the pace
    nz = np.nonzero(np.abs(a) > 0.01)[0]
    a = a[max(nz[0] - int(0.05 * RATE), 0): nz[-1] + int(0.12 * RATE)]
    return a, " ".join(phon)


def main():
    cmd = sys.argv[1]
    if cmd == "phonemes":
        pipe = pipeline("af_heart")
        for beat, text in lines():
            print(beat, text, "\n   ", say(pipe, "af_heart", text)[1])
    elif cmd == "samples":
        out = Path(sys.argv[2])
        first_two = [t for _, t in list(lines())[:2]]
        for voice in ("af_heart", "am_michael", "bf_emma"):
            pipe = pipeline(voice)
            gap = np.zeros(int(RATE * 0.35), dtype=np.float32)
            parts = [x for t in first_two for x in (say(pipe, voice, t)[0], gap)]
            wav = np.concatenate(parts)
            sf.write(out / f"voice-sample-{voice}.wav", wav, RATE)
            print(voice, f"{len(wav) / RATE:.1f} s")
    elif cmd == "render":
        voice, out = sys.argv[2], Path(sys.argv[3])
        out.mkdir(parents=True, exist_ok=True)
        pipe, rows = pipeline(voice), []
        for i, (beat, text) in enumerate(lines()):
            wav, phon = say(pipe, voice, text)
            name = f"line-{i:02d}.wav"
            sf.write(out / name, wav, RATE)
            rows.append({"beat": beat, "text": text, "wav": name, "seconds": round(len(wav) / RATE, 3), "phonemes": phon})
        (out / "lines.json").write_text(json.dumps(rows, indent=1))
        for b in sorted({r["beat"] for r in rows}):
            print(f"beat {b}: {sum(r['seconds'] for r in rows if r['beat'] == b):.1f} s")
        print(f"total speech {sum(r['seconds'] for r in rows):.1f} s")


if __name__ == "__main__":
    main()
