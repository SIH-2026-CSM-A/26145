"""The film's timeline, from the rendered narration (out/wav/lines.json).

Every segment lasts exactly as long as its narration plus a short lead and tail, so no sentence
is ever cut and the picture never waits on the voice. `python3 plan.py` prints the plan as JSON
(the recorder and the scene renderer read it); assemble.py imports it.
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
GAP, LEAD, TAIL = 0.3, 0.5, 0.6  # seconds: between lines, before the first, after the last

# (segment id, source, line indices from script.md in order). Scenes are HTML pages rendered frame
# by frame; live segments are cut from the one real replay recording.
SEGMENTS = [
    ("hook", "scene", range(0, 5)),
    ("arch", "scene", range(5, 13)),
    ("quiet", "live", range(13, 16)),
    ("scan", "live", range(16, 18)),
    ("chain", "live", range(18, 21)),
    ("flood", "live", range(21, 22)),
    ("map", "live", range(22, 25)),
    ("case", "live", range(25, 30)),
    ("tamper", "scene", range(30, 34)),
    ("card", "live", range(34, 37)),
    ("fp", "live", range(37, 39)),
    ("numbers", "scene", range(39, 43)),
    ("end", "scene", range(43, 44)),
]


def plan(lines_json: Path = HERE / "out" / "wav" / "lines.json") -> list[dict]:
    rows = json.loads(lines_json.read_text())
    assert len(rows) == 44, f"script has {len(rows)} lines; SEGMENTS expects 44"
    out, t = [], 0.0
    for sid, kind, idx in SEGMENTS:
        cues, c = [], LEAD
        for i in idx:
            cues.append({"line": i, "at": round(c, 3), "dur": rows[i]["seconds"], "text": rows[i]["text"], "wav": rows[i]["wav"]})
            c += rows[i]["seconds"] + GAP
        dur = round(c - GAP + TAIL, 3)
        out.append({"id": sid, "kind": kind, "start": round(t, 3), "dur": dur, "cues": cues})
        t += dur
    return out


if __name__ == "__main__":
    p = plan()
    print(json.dumps(p, indent=1))
    import sys
    print(f"total {p[-1]['start'] + p[-1]['dur']:.1f} s", file=sys.stderr)
    for s in p:
        print(f"  {s['id']:8s} {s['kind']:5s} {s['start']:6.1f} +{s['dur']:5.1f}", file=sys.stderr)
