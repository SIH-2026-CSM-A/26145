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
    ("problem", "scene", range(0, 11)),
    ("threats", "scene", range(11, 18)),
    ("arch", "scene", range(18, 27)),
    ("quiet", "live", range(27, 30)),
    ("scan", "live", range(30, 32)),
    ("chain", "live", range(32, 35)),
    ("flood", "live", range(35, 39)),
    ("map", "live", range(39, 42)),
    ("case", "live", range(42, 47)),
    ("tamper", "scene", range(47, 52)),
    ("safe", "scene", range(52, 57)),
    ("numbers", "scene", range(57, 61)),
    ("why", "scene", range(61, 64)),
    ("end", "scene", range(64, 65)),
]


def plan(lines_json: Path = HERE / "out" / "wav" / "lines.json") -> list[dict]:
    rows = json.loads(lines_json.read_text())
    n = SEGMENTS[-1][2].stop
    assert len(rows) == n, f"script has {len(rows)} lines; SEGMENTS expects {n}"
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
