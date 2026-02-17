/**
 * Runtime Enforcement Tests — authority token layer (Reference Implementation)
 *
 * Uses Node.js built-in test runner (node:test).
 * Run with: npx tsx --test tests/runtime_enforced.spec.ts
 *
 * Tests (T1–T7): Concept verification for the Execution Contract gate.
 *
 *   T1: Valid ALLOW + valid token → execution succeeds
 *   T2: Signature tampered → ExecutionDeniedError (SIGNATURE_INVALID)
 *   T3: proposal_hash changed → ExecutionDeniedError (PROPOSAL_HASH_MISMATCH)
 *   T4: expires_at in the past → ExecutionDeniedError (TOKEN_EXPIRED)
 *   T5: Same token replayed → second call fails (TOKEN_REPLAYED)
 *   T6: STRICT mode, rule miss → STOP, no token issued
 *   T7: PERMISSIVE mode, rule miss → HOLD token issued, kernel blocks (DECISION_NOT_ALLOW)
 *
 * Note: Environment fingerprint mismatch tests (runner identity binding,
 * cross-workflow replay, cross-commit replay) are in the production kernel:
 * echo-execution-kernel (private) — tests/runtime_enforced.spec.ts T8–T10.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runAuthorityPipeline } from '../src/authority_pipeline.js';
import { executeWithAuthority, type VerifiedToken } from '../src/execution_kernel.js';
import { GateMode } from '../src/config/mode.js';
import { initRegistry } from '../src/token_registry.js';
import { ExecutionDeniedError } from '../src/errors.js';

const POLICY_PATH = './policy.yaml';
const ALLOW_CMD = 'echo';
const DENY_CMD = 'rm';
const DENY_ARGS = ['-rf', '/'];

// Initialize registry once for all tests
initRegistry();

// ─── Helper: build a fresh ALLOW token via the real pipeline ────────────────
async function freshAllowToken(args: string[]): Promise<{
  token: VerifiedToken;
  proposal: import('../src/canonical_proposal.js').CanonicalProposal;
}> {
  const result = await runAuthorityPipeline(ALLOW_CMD, args, POLICY_PATH, GateMode.STRICT);
  assert.equal(result.decision, 'ALLOW', 'expected ALLOW from pipeline');
  assert.ok(result.token, 'token must be present for ALLOW');
  assert.ok(result.proposal, 'proposal must be present for ALLOW');
  return { token: result.token!, proposal: result.proposal! };
}

// ────────────────────────────────────────────────────────────────────────────
// T1: Valid ALLOW + valid token → execution succeeds
// ────────────────────────────────────────────────────────────────────────────
test('T1: valid ALLOW token → kernel passes all 7 steps, exits 0', async () => {
  const { token, proposal } = await freshAllowToken(['t1-run']);

  assert.equal(token.decision, 'ALLOW');
  assert.ok(token.token_id, 'token_id must be set');
  assert.ok(token.issuer_signature, 'signature must be set');
  assert.ok(token.policy_hash, 'policy_hash must be set');
  assert.ok(token.environment_fingerprint, 'env_fingerprint must be set');
  assert.equal(token.scope.action, 'execute');

  const result = await executeWithAuthority(ALLOW_CMD, ['t1-run'], proposal, token);
  assert.equal(result.exit_code, 0);
  assert.equal(result.executed, true);
});

// ────────────────────────────────────────────────────────────────────────────
// T2: Signature tampered → SIGNATURE_INVALID
// ────────────────────────────────────────────────────────────────────────────
test('T2: tampered issuer_signature → SIGNATURE_INVALID', async () => {
  const { token, proposal } = await freshAllowToken(['t2-sig-tamper']);

  const tamperedToken: VerifiedToken = {
    ...token,
    token_id: token.token_id + '-tamper', // new id — different token
    issuer_signature: 'a'.repeat(128) // 64 bytes hex, but wrong
  };

  await assert.rejects(
    () => executeWithAuthority(ALLOW_CMD, ['t2-sig-tamper'], proposal, tamperedToken),
    (err: unknown) => {
      assert.ok(err instanceof ExecutionDeniedError, 'must be ExecutionDeniedError');
      assert.equal(err.error_type, 'SIGNATURE_INVALID');
      return true;
    }
  );
});

// ────────────────────────────────────────────────────────────────────────────
// T3: proposal_hash changed → PROPOSAL_HASH_MISMATCH
// ────────────────────────────────────────────────────────────────────────────
test('T3: proposal_hash in token does not match proposal → PROPOSAL_HASH_MISMATCH', async () => {
  const { token, proposal } = await freshAllowToken(['t3-hash-check']);

  const differentProposal = { ...proposal, args: ['t3-different-arg'] };

  await assert.rejects(
    () => executeWithAuthority(ALLOW_CMD, ['t3-different-arg'], differentProposal, token),
    (err: unknown) => {
      assert.ok(err instanceof ExecutionDeniedError, 'must be ExecutionDeniedError');
      assert.equal(err.error_type, 'PROPOSAL_HASH_MISMATCH');
      return true;
    }
  );
});

// ────────────────────────────────────────────────────────────────────────────
// T4: expires_at in the past → TOKEN_EXPIRED
// ────────────────────────────────────────────────────────────────────────────
test('T4: expired token → TOKEN_EXPIRED', async () => {
  const { token, proposal } = await freshAllowToken(['t4-ttl-check']);

  const expiredToken: VerifiedToken = {
    ...token,
    token_id: token.token_id + '-expired',
    expires_at: new Date(Date.now() - 60_000).toISOString()
  };

  await assert.rejects(
    () => executeWithAuthority(ALLOW_CMD, ['t4-ttl-check'], proposal, expiredToken),
    (err: unknown) => {
      assert.ok(err instanceof ExecutionDeniedError, 'must be ExecutionDeniedError');
      assert.equal(err.error_type, 'TOKEN_EXPIRED');
      return true;
    }
  );
});

// ────────────────────────────────────────────────────────────────────────────
// T5: Same token used twice → TOKEN_REPLAYED (token_id replay prevention)
// ────────────────────────────────────────────────────────────────────────────
test('T5: same token used twice → TOKEN_REPLAYED', async () => {
  const { token, proposal } = await freshAllowToken(['t5-replay-test']);

  // First call succeeds — marks token_id used
  const firstResult = await executeWithAuthority(ALLOW_CMD, ['t5-replay-test'], proposal, token);
  assert.equal(firstResult.exit_code, 0);

  // Second call with same token → token_id already in registry
  await assert.rejects(
    () => executeWithAuthority(ALLOW_CMD, ['t5-replay-test'], proposal, token),
    (err: unknown) => {
      assert.ok(err instanceof ExecutionDeniedError, 'must be ExecutionDeniedError');
      assert.equal(err.error_type, 'TOKEN_REPLAYED');
      return true;
    }
  );
});

// ────────────────────────────────────────────────────────────────────────────
// T6: STRICT mode, rule miss → STOP, no token issued
// ────────────────────────────────────────────────────────────────────────────
test('T6: STRICT mode + rule miss → decision=STOP, no token', async () => {
  const result = await runAuthorityPipeline(DENY_CMD, DENY_ARGS, POLICY_PATH, GateMode.STRICT);

  assert.equal(result.decision, 'STOP');
  assert.equal(result.gate_mode, GateMode.STRICT);
  assert.equal(result.token, undefined, 'no token must be issued for STOP');
  assert.ok(result.reason, 'reason must be set');
});

// ────────────────────────────────────────────────────────────────────────────
// T7: PERMISSIVE mode, rule miss → HOLD token, kernel blocks
// ────────────────────────────────────────────────────────────────────────────
test('T7: PERMISSIVE mode + rule miss → HOLD token issued, kernel blocks (DECISION_NOT_ALLOW)', async () => {
  const result = await runAuthorityPipeline(DENY_CMD, DENY_ARGS, POLICY_PATH, GateMode.PERMISSIVE);

  assert.equal(result.decision, 'HOLD');
  assert.equal(result.gate_mode, GateMode.PERMISSIVE);
  assert.ok(result.token, 'HOLD token must be issued in PERMISSIVE mode');
  assert.equal(result.token!.decision, 'HOLD');

  // Kernel must block the HOLD token (step 2: decision !== 'ALLOW')
  await assert.rejects(
    () => executeWithAuthority(DENY_CMD, DENY_ARGS, result.proposal!, result.token!),
    (err: unknown) => {
      assert.ok(err instanceof ExecutionDeniedError, 'must be ExecutionDeniedError');
      assert.equal(err.error_type, 'DECISION_NOT_ALLOW');
      return true;
    }
  );
});
