# AGENTS.md — SIH26145 Project Guidelines

1. This repository belongs exclusively to SIH26145.
2. All implementation must remain inside this repository unless explicitly approved.
3. Do not modify files outside the assigned implementation scope.
4. Do not modify shared contracts/interfaces merely for convenience.
5. Read AGENTS.md before every implementation phase.
6. Prefer WSL2 Ubuntu/Linux for development and testing.
7. Keep the repository under:
   ~/NewProjects/sih26145/
8. Do not work from:
   /mnt/c/
9. Use evidence-based verification.
10. Do not claim performance numbers until they have been measured.
11. The SIH26145 architecture must preserve the passive/read-only nature of the monitored traffic path.
12. No active packet injection, mitigation, probing, or return traffic.
13. No payload decryption or TLS interception.
14. PCAP replay/synthetic traffic may be used for reproducible demonstration and testing.
15. Future implementation phases must be performed incrementally with explicit verification between phases.
