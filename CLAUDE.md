# CLAUDE.md — gotchas only

Read AGENTS.md (standing rules), docs/ARCHITECTURE.md, docs/AUDIT.md, TODO.md first.

- Work on `main`. `master` is an older, empty branch. Tag `baseline-antigravity` = intake state.
- Tests: `uv run pytest -q`. Python is 3.13 in `.venv` (pyproject says >=3.11).
- "Unidirectional" = the enclave never transmits. The *capture* may hold both halves of a
  conversation or only one; `FlowRecord.observability_state` measures it per flow. Never
  assume either.
- Every feature a detector reads must be declared in `src/sih26145/feature_contract.toml`.
  `tests/contract/` AST-scans detectors and fails on undeclared or over-tier reads.
  Adding a feature = add the contract row in the same commit.
- `reverse_dependent` features raise `UnavailableFeatureError` on flows without
  `reverse_seen`. Catch it and branch; never default it to 0.
- Internal networks come from `SIH26145_INTERNAL_CIDRS` (default RFC1918 + fc00::/7).
  Outbound = internal→external. The demo generator uses 203.0.113.0/24 / 198.51.100.0/24
  (documentation ranges) as "external".
- `api/app.py` holds module-global `storage` and `broadcaster`; tests share them.
- `src/sih26145/detectors/rules/` has no `__init__.py` (namespace package) — imports work.
- Zeek is not installed on this machine; the dpkt path is the one that runs.
- ML models are trained on CTU-13-Extended (docs/MODELS.md). No accuracy figure anywhere; quote
  only the per-scenario numbers in MODELS.md. Retraining: `scripts/train_models.py` (deterministic).
- Changing `models/features.py` ML_FEATURES or the model row = redump + retrain; the suite refuses
  artefacts whose manifest features/version don't match.
- CTU-13 public `botnet-capture-*.pcap` files hold only infected hosts; benign flows come from the
  CTU-13-Extended `*.truncated.pcap` files (pcapng, headers only) in `26145-data/ctu13-extended/`.
- Throughput figures live in docs/BENCHMARK.md; re-measure (idle machine) before changing them.
- Commits: conventional commits, no AI-attribution trailers.
- Rule thresholds are tuned (ruleset 2.1.0, docs/RULES.md). Changing one = rerun
  `scripts/rule_eval.py` sweep/pick/run/report; `report` asserts its table matches detectors.py.
- `.gitignore` had a Python `lib/` rule that hid `dashboard/src/lib/`; it is now `/lib/`. Check
  `git check-ignore -v` when a new directory seems to vanish from a commit.
- `demo/demo.pcap` is committed (sha256 pinned in tests/integration/test_demo_capture.py,
  demo/ATTRIBUTION.md, DEPLOY.md). Rebuild = `scripts/build_demo_capture.py`, then update all three.
- Port 8000 is taken by something else on this machine: use `PORT=18001 scripts/demo.sh`,
  `SIH_PORT=18000 docker compose up`. Docker Desktop must be started (Windows app) first.
- The API is read-only by design (public demo, no auth): tests/api/test_readonly_surface.py.
- Models, thresholds, contract and default lists ship in the signed bundle
  `src/sih26145/models/bundle/saakshi-models.tar(.sig)`; the pipeline refuses to start if the code differs.
  After changing any of them: `saakshi bundle build --out <that tar>` then `saakshi bundle sign <tar> --key
  ~/.config/saakshi/bundle-ed25519.pem` (key never in the repo; pubkey pinned in `config/bundle_ed25519.pub`).
