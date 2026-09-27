# SAAKSHI film: narration script

Target 3:00–3:30 at ~140 words per minute. Every line says only what is true and what is on screen
at that moment. Numbers come from the running demo or from docs/BENCHMARK.md, docs/MODELS.md and
docs/RULES.md. One WAV per sentence (subtitle timing); each beat's video lasts as long as its audio.

Pronunciation (Kokoro phoneme overrides): SAAKSHI = "SAAK-shee", NTRO = "N-T-R-O",
JA4 = "J-A-four", DGA = "D-G-A", C2 = "C-two", SHA-256 = "shah two-fifty-six",
F.R.I.E.N.D.S = "Friends".

---

## 1. Hook (0:00–0:25) · title scene (HTML, anime.js)
**Screen:** dark field; a link line draws left to right through a diode gate; the return direction
appears dashed with a lock. Then the six threat classes appear as chips in their colours.

> Critical networks watch their links through a one-way data diode.
> The monitor can see everything on the link, but it can never send a single byte back.
> SAAKSHI is our answer to NTRO's problem statement: find threats in that one-way traffic.
> Six of them: floods, command-and-control beacons, random domains and DNS tunnels,
> malware hidden inside encrypted sessions, scanning, and data leaving the network.

(76 words · ~31 s)

## 2. Architecture (0:25–0:55) · animated diagram (HTML, anime.js)
**Screen:** the chain lights up box by box: tap and diode → capture → flows → feature store →
rules and model → alerts → campaigns → hash-chained log → dashboard. The contract line appears
under the feature store.

> Packets arrive through a passive tap and the diode.
> We rebuild them into flows, and a feature store keeps rolling counts per host, per server and per pair.
> Rules and a trained model score every flow.
> Alerts that share a rare host, server, name or fingerprint are grouped into campaigns,
> and every alert is written to a log chained with SHA-256.
> One rule holds it together: each feature declares what the link must show for it.
> If a flow's reply was never captured, a feature that needs the reply is not guessed.
> The detector switches to a declared substitute.

(89 words · ~38 s)

## 3. Live replay (0:55–2:00) · the real pipeline, `serve demo/demo.pcap --speed 5`
**Screen:** the dashboard, live. "⏩ time skip +Ns" cards mark every cut; there is no speed ramp.

*3a, quiet link:* hero with steady dots, KPI strip.
> This is the real pipeline, replaying a committed capture at five times real time:
> real university traffic, plus generated attack packets.
> Each dot is about five flows. Nothing crosses back.

*3b, scan:* the spark flies to tile (e), which pulses.
> Host one-nine-two dot one-six-eight dot one dot six-six scans ports on one internal server.
> That alert opens a campaign.

*3c, the chain:* sparks land on (d), (b), (c) and (f), one after another; the ribbon card for the
host gains a colour each time.
> Then the same host shows a rare TLS client, regular check-ins to an outside server,
> lookups of random-looking names, data hidden in DNS, and a large upload.
> Each one shares a rare pivot with the campaign, so all six join it.

*3d, flood:* the red spark lands on tile (a); a fourth campaign card appears.
> A SYN flood on another server shares no rare pivot with them. It gets its own campaign.

*3e, map and timeline:* scroll to the map; click 192.168.1.66; the swim lanes animate.
> The map shows each campaign. The host's timeline lists what was seen, in order:
> discovery, then command and control, then exfiltration.
> It is history. It does not predict the next step.

(143 words · ~61 s)

## 4. Case file (2:00–2:30) · click the exfiltration line
**Screen:** the case file slides in; the evidence bar fills past its threshold tick; the
request/reply diagram; "Verify chain" pressed, ticks run across the blocks.

> The upload sent two hundred and eighty bytes out for every byte that came back.
> The rule's threshold is fifty.
> This link carried both directions, so that ratio could be computed.
> Without the reply, the contract would switch to an egress spike and a rare destination.
> Verify recomputes the hash chain on the server. All ten records check out.

(64 words · ~27 s)

## 5. Tamper test (2:30–2:45) · the verify-log terminal
**Screen:** `verify-log` prints "verified: 10 records"; the one-byte edit runs; `verify-log`
prints "BROKEN at index 3 of 10" in red.

> Now change one byte of alert three in the database.
> The check fails, and names the record: broken at index three.
> It catches edits made without rebuilding the whole chain.
> Signed checkpoints, which stop that too, are the next step we are building.

(23 words · ~10 s)

## 6. Honesty (2:45–3:10) · model card, then the three university C2 alerts on the map
**Screen:** model card, "Held-out result" highlighted; then the two university campaigns on the map.

> The model card says what the model cannot do.
> On scenarios it never saw, it catches only twenty-eight percent of malicious flows at its alert budget,
> so model-only alerts are capped at medium.
> And these three C2 alerts on real university hosts are false positives.
> We show them as they are.

(50 words · ~21 s)

## 7. Numbers (3:10–3:25) · a numbers card in the dashboard style
**Screen:** four figures, each with its source: ~860 flows/s · ~223 Mbps · one laptop core
(docs/BENCHMARK.md); p99 250 ms flush → alert at half load; flows close after 15 s idle; under the latency figure, small:
"flow lane today · fast lane (≈1 s) next".

> On one laptop core, SAAKSHI scores about eight hundred and sixty flows a second, about two hundred and twenty megabits per second.
> At half load, ninety-nine percent of alerts are out within a quarter of a second of a flow closing.
> A flow closes after fifteen seconds of silence.
> Alerting on floods and scans within a second, before a flow closes, is being built now; the fifteen seconds is today's measured behaviour.

(46 words · ~20 s)

## 8. End card (3:25–3:32)
**Screen:** SAAKSHI · SIH26145 · Team F.R.I.E.N.D.S · github.com/SIH-2026-CSM-A/26145, and under it
"Live demo: 8.234.101.133.sslip.io" (screen only, not narrated)

> SAAKSHI. SIH twenty-six one forty-five, team Friends.

(8 words · ~4 s)

---

**Total:** ~499 words, ~3:32 at 140 wpm (Kokoro's pace is usually a little faster; the final
length is set by the audio). Owner rule: if the total runs over 3:40, cut the middle sentence of 3e
first, then "Each dot is about five flows" in 3a. Beats 5, 6 and 7 are never cut.
Voice: Kokoro af_heart at 0.9 speed (owner's pick).
