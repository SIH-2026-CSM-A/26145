# The narrated film

Everything here is tooling. None of it is part of the product or its dependencies.

| Step | Command (from `demo/film/`) | Output (in `out/`, git-ignored) |
|---|---|---|
| 1. Voice setup, once | `uv venv --python 3.12 .venv-tts`, then `uv pip install --python .venv-tts/bin/python torch --index-url https://download.pytorch.org/whl/cpu`, then `... kokoro soundfile pillow fonttools brotli` and the `en-core-web-sm` 3.8.0 wheel. The model weights download once from Hugging Face | `.venv-tts/` |
| 2. Narration | `.venv-tts/bin/python tts.py render af_heart out/wav` (Kokoro-82M, Apache-2.0, 0.9 speed; `tts.py phonemes` prints the pronunciation) | one WAV per script line, `lines.json` |
| 3. Timeline | `python3 plan.py > out/plan.json` | segment start/length from the audio |
| 4. Tamper transcript | `uv run --script ../../scripts/render_verify_log.py out/tamper.json` (runs the real commands) | `tamper.json` |
| 5. Scenes | `node render-scenes.mjs` (hook, architecture, tamper, numbers, end card; frame by frame) | `scenes/*.mp4` |
| 6. Live part | `node film-record.mjs` (one real `serve demo/demo.pcap --speed 5` replay, Chrome screencast) | `live.mp4`, `live-events.json` |
| 7. Film | `.venv-tts/bin/python assemble.py OUT.mp4` | `OUT.mp4` (H.264/AAC 1080p30, −16 LUFS, burned-in subtitles) + `OUT.srt` |

`script.md` is the narration. Each segment of the film lasts as long as its narration. Every cut
in the live recording carries a "time skip" badge, and nothing is sped up.

Install `en-core-web-sm` into `.venv-tts` yourself (step 1). Otherwise misaki's first run asks
spaCy to download it, and spaCy's `uv` call installs it into the project's `.venv`.
