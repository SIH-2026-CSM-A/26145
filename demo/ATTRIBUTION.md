# demo/demo.pcap: sources and attribution

`demo.pcap` is 11 minutes of capture time (8.0 MB, classic pcap, Ethernet). It is built by
`scripts/build_demo_capture.py`, which is deterministic: rebuilding gives the same file.

| | |
|---|---|
| sha256 | `ba44d087e800be6df0befdde5a7fb241073c9bfa01174b87949f6ea6d1a756f0` |
| Real background | 98,993 packets: every packet to or from the hand-checked normal hosts of CTU-13-Extended scenario 5, from the first 11 minutes of `capture20110815-2.truncated.pcap` (sha256 of that file: `bb116165…f29e`, full hash in `docs/MODELS.md` §2.1) |
| Generated attacks | 3,340 packets from `src/sih26145/utils/attack_scenarios.py`, re-addressed so host 192.168.1.66 runs recon → C2 → TLS beacon → DGA → DNS tunnel → exfiltration, then a SYN flood on 10.50.0.10 |

**What was changed in the real traffic.**
- Timestamps are shifted so the capture starts at 2026-09-21 14:14:00 UTC. Intervals are
  unchanged.
- Nothing else was changed. The packets are header-only, as published (TCP cut at 54 bytes, UDP
  at 42, ICMP at 66), and each record keeps its original wire length.
- No payload was ever present.

**Licence and citation.** The background traffic comes from the CTU-13 dataset (Stratosphere
Laboratory, Czech Technical University in Prague). The dataset README says:

> Disclaimer: You are free to use these files as long as you reference this project and the authors.

References:
- Sebastian Garcia, Martin Grill, Jan Stiborek and Alejandro Zunino, "An empirical comparison
  of botnet detection methods", *Computers & Security* 45 (2014), pp. 100–123.
- Sebastian Garcia, Malware Capture Facility Project, https://stratosphereips.org

The generated attack traffic uses documentation address ranges (203.0.113.0/24,
198.51.100.0/24) and private ranges for the enclave. Flood sources are random public addresses
chosen by a fixed seed. They are not real hosts.
