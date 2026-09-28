# SAAKSHI film v2: narration script

Target 4:30–5:30. Every line says only what is true and what is on screen at that moment. Numbers
come from the running demo or docs/BENCHMARK.md. One WAV per "> " line (one subtitle unit); each
segment's video lasts as long as its audio. v1: script-v1.md.

Rules for v2: nothing about work that is not built; no model card, no "28%", no "false positive";
the university hosts' C2 campaigns may be visible on the map, but the narration does not point at
them.

Pronunciation (Kokoro phoneme overrides in tts.py): SAAKSHI, NTRO, SYN, Bharatiya Sakshya
Adhiniyam, F.R.I.E.N.D.S = "Friends".

Changes from the owner's draft, each to keep a line true:
- beat 3: "a log that cannot be changed without it showing" → "a hash-chained log, so an edited
  record breaks the chain" (a full rebuild of the chain is caught only against an exported head);
- beat 4: "within about a second" → "within two seconds" (fast lane p50 1.5 s, p99 2.0 s on the
  generated SYN flood, docs/BENCHMARK.md);
- beat 7: "headers and timing only" → "headers, timing and cleartext handshake details only" (the
  DNS and TLS rules read query names and ClientHello fields);
- beat 8: "about two hundred and twenty megabits" → "two hundred and twenty-three" (the screen
  shows ~223 Mbps);
- beat 9: "a record that proves it was not changed" → "a record where an edited alert breaks the
  chain".

---

## 1. The problem · new scene (problem.html)
**Screen:** three critical networks, the diode, a one-way arrow, the monitor on the far side; then
what most tools assume, struck through; then the question and the name.

> Some networks must never leak: defence systems, power grids, telecom cores.
> Links like these are often guarded by a data diode, a device that lets traffic flow in one direction only.
> Hardware, not software, stops anything from going back.
> That keeps the network safe. But it also means the security monitor sits on the far side.
> It only sees a copy of the traffic. It can never ask a question, never send a probe, never block anything.
> Most security tools were built for two-way links.
> They expect to see every reply, they often read the content, and they assume they can check things online.
> On a one-way link, replies can be missing, most traffic is encrypted, and there is no internet.
> NTRO's problem statement asks: can AI find cyber threats in this one-way traffic alone?
> SAAKSHI, the Hindi word for witness, is our answer.
> It watches, it never talks back, and every alert comes with its evidence.

## 2. Six threats in plain words · new scene (threats.html)
**Screen:** six cards in the class colours, each with a small animation, appearing as named.

> The problem statement names six threats.
> Floods: a server buried under fake traffic.
> Command and control: an infected machine quietly checking in with its attacker, like clockwork.
> Random-looking domain names, and data smuggled out inside DNS lookups.
> Malware hiding inside encrypted connections.
> Scanning: an attacker knocking on every door to find one that is open.
> And exfiltration: data being stolen out of the network.

## 3. How SAAKSHI works · the v1 architecture scene, with the fast lane (arch.html)
> Packets arrive through a passive tap and the diode.
> We rebuild them into conversations, called flows, and keep rolling counts for every host and server.
> Floods and scans are also counted packet by packet, every second, so they are caught while they are still happening.
> Rules and a trained AI model score every flow.
> Alerts that point to the same unusual host, server or name are grouped into one campaign,
> so an analyst reads one story instead of ten scattered alarms.
> And every alert is written to a hash-chained log, so an edited record breaks the chain.
> One rule holds it all together: if the link did not show us something, we never pretend we saw it.
> Each alert says what it could see and what it could not.

## 4. Live replay · the real pipeline, `serve demo/demo.pcap --speed 5`
**Screen:** the dashboard, live. Every cut in the recording carries a "time skip" card.

*quiet*
> This is the real pipeline, replaying a recorded capture at five times real time:
> real university traffic, plus attack traffic we generated.
> Each dot is about five flows. Nothing crosses back.

*scan*
> Host one-nine-two dot one-six-eight dot one dot six-six scans ports on an internal server.
> That alert opens a campaign.

*chain*
> Then the same host shows a rare encrypted client, regular check-ins to an outside server,
> lookups of random-looking names, data hidden in DNS, and a large upload.
> Each one shares something rare with the campaign, so they all join it.

*flood:* tile (a) shows the outlined provisional alert, then (after a time-skip card) the
confirming alert, solid.
> A SYN flood hits another server.
> The fast lane flags it within two seconds, outlined,
> and it turns solid when the full check confirms it.
> It gets its own campaign.

*map:* scroll to the map; click 192.168.1.66; the stage timeline.
> The map shows each campaign.
> The host's timeline lists what happened, in order: discovery, then command and control, then data theft.
> It is a record of what was seen, not a guess about what comes next.

## 5. Case file · click the upload line, then Verify
> Open the upload alert.
> This host sent two hundred and eighty bytes out for every byte that came back. The rule's line is fifty.
> The alert also shows what this link could see. Here both directions were captured.
> If the replies had been missing, SAAKSHI would switch to a different, declared signal, and say so on the alert.
> Verify checks the whole log again, on the spot. Every record checks out.

## 6. Tamper test · the verify-log terminal (tamper.html, real transcript)
> In an inquiry, the first question is: has anyone changed the record?
> Change one byte of alert three in the database, and the check fails,
> and names the exact record: broken at index three.
> Each export carries a data sheet to support a certificate
> under Section sixty-three of the Bharatiya Sakshya Adhiniyam.

## 7. Safe by design · new card (safe.html)
> SAAKSHI is built for places where trust matters.
> The AI model can never raise a high alert on its own. A rule must see the evidence too.
> It reads headers, timing and cleartext handshake details only, and never decrypts anything.
> It runs fully offline.
> Model and rule updates arrive as signed bundles, and anything tampered with is refused before it is loaded.

## 8. Numbers · the numbers card, updated (numbers.html)
**Screen:** ~860 flows/s · ~223 Mbps · flood/scan alert < 2 s (fast lane, 1× replay, p99) · same 91
alerts on a GCP Linux VM; a source line under each (docs/BENCHMARK.md).

> On one laptop core, SAAKSHI handles about eight hundred and sixty flows a second,
> about two hundred and twenty-three megabits per second.
> Floods and scans are flagged in under two seconds.
> The same pipeline gives the same detections on a cloud Linux server.

## 9. Why it matters · new card (why.html)
> For the analyst: one campaign to read, with its evidence, instead of a pile of alarms.
> For NTRO: detection that works with the diode, not against it.
> For an inquiry: a record where an edited alert breaks the chain.

## 10. End card (end.html)
**Screen:** SAAKSHI · The silent witness · SIH26145 · Team F.R.I.E.N.D.S · the repository, and the
live demo address (screen only).

> SAAKSHI. The silent witness. SIH twenty-six one forty-five, team Friends.
