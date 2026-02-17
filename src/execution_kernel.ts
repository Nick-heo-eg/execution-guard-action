/**
 * Execution Kernel — THE ONLY authorized spawn() call site.
 *
 * REFERENCE IMPLEMENTATION: Demonstrates the Execution Contract concept.
 * Production kernel: echo-execution-kernel (private) — runner-bound
 * authority tokens, composite replay key, 9-field env fingerprint.
 *
 * SECURITY CONTRACT:
 *   spawn() MUST NOT be called anywhere else in this codebase.
 *   A verified authority token is required to reach spawn.
 *   Any verification failure throws ExecutionDeniedError — spawn is never reached.
 *
 * Verification chain (7 steps, fail-closed):
 *   1. Token not expired (TTL)
 *   2. decision === 'ALLOW' (blocks HOLD and any other decision)
 *   3. token_id not replayed (in-memory only — reference implementation)
 *   4. proposal_hash matches re-computed canonical hash
 *   5. policy_hash matches current policy content hash
 *   6. environment_fingerprint matches current runtime (3-field reference)
 *   7. ED25519 signature valid
 *
 * Token marked used BEFORE spawn — prevents replay even on hang.
 * CI guard: scripts/check-spawn.sh enforces single call site.
 */

import { spawn } from 'child_process';
import { verify as cryptoVerify, createPublicKey } from 'crypto';
import { isTokenUsed, markTokenUsed } from './token_registry.js';
import { canonicalHash, hashPolicyFile, type CanonicalProposal } from './canonical_proposal.js';
import { buildEnvironmentFingerprint } from './environment_fingerprint.js';
import { canonicalStringify } from './canonical_stringify.js';
import { ExecutionDeniedError } from './errors.js';

export type TokenDecision = 'ALLOW' | 'HOLD';

/** Structured scope bound to the token — action + resource + constraints. */
export interface TokenScope {
  action: string;       // e.g. 'execute'
  resource: string;     // e.g. 'echo hello from execution-guard'
  constraints: {
    policy_version: string;  // = policy_hash at issuance time
    gate_mode: string;       // 'STRICT' | 'PERMISSIVE'
    guard_version: string;
  };
}

/**
 * A token issued by authority_pipeline and passed to the kernel for execution.
 * ALLOW tokens may reach spawn() after all 7 verification steps pass.
 * HOLD tokens are immediately blocked (step 2).
 */
export interface VerifiedToken {
  token_id: string;                  // UUIDv7
  proposal_hash: string;             // SHA256(canonical_proposal)
  policy_hash: string;               // SHA256(policy.yaml) — explicit field
  environment_fingerprint: string;   // SHA256(runner environment)
  policy_version: string;            // = policy_hash (backward compat alias)
  decision: TokenDecision;           // 'ALLOW' | 'HOLD'
  audit_ref: string;                 // UUIDv7 cross-reference
  expires_at: string;                // ISO8601
  issued_at: string;                 // ISO8601
  scope: TokenScope;                 // structured scope
  gate_mode: 'STRICT' | 'PERMISSIVE';
  guard_version: string;
  /** ED25519 signature over canonical token payload (excluding sig + public_key_hex) */
  issuer_signature: string;
  /** Ephemeral public key used to issue this token (per-run, not persisted) */
  public_key_hex: string;
}

export interface KernelResult {
  exit_code: number;
  token_id: string;
  audit_ref: string;
  executed: true;
}

/** JSON audit log entry format */
interface KernelAuditEntry {
  decision: string;
  proposal_hash: string;
  token_id: string;
  policy_hash: string;
  environment_fingerprint: string;
  reason: string;
  executed: boolean;
  error_type?: string;
}

function emitAuditLog(entry: KernelAuditEntry): void {
  process.stdout.write(JSON.stringify(entry) + '\n');
}

/**
 * Execute a command under authority of a verified token.
 *
 * All 7 verification steps must pass — fail-closed.
 * @throws ExecutionDeniedError if any step fails. spawn() is never reached on failure.
 */
export async function executeWithAuthority(
  command: string,
  args: string[],
  proposal: CanonicalProposal,
  token: VerifiedToken
): Promise<KernelResult> {

  const auditBase = {
    decision: token.decision,
    proposal_hash: token.proposal_hash,
    token_id: token.token_id,
    policy_hash: token.policy_hash,
    environment_fingerprint: token.environment_fingerprint
  };

  // Compute current environment fingerprint once — used in step 6 (binding)
  const currentEnvFingerprint = buildEnvironmentFingerprint(proposal.policy_path);

  // --- Step 1: TTL ---
  const now = new Date();
  const expiresAt = new Date(token.expires_at);
  if (now > expiresAt) {
    const err = new ExecutionDeniedError(
      'TOKEN_EXPIRED',
      `Token expired at ${token.expires_at}, now=${now.toISOString()}`
    );
    emitAuditLog({ ...auditBase, reason: err.message, executed: false, error_type: err.error_type });
    throw err;
  }

  // --- Step 2: Decision gate (ALLOW only) ---
  if (token.decision !== 'ALLOW') {
    const err = new ExecutionDeniedError(
      'DECISION_NOT_ALLOW',
      `Token decision is '${token.decision}', not ALLOW`
    );
    emitAuditLog({ ...auditBase, reason: err.message, executed: false, error_type: err.error_type });
    throw err;
  }

  // --- Step 3: Replay prevention (token_id — reference implementation) ---
  // Production kernel: composite key (proposal_hash|env_fp) per 60s window.
  if (isTokenUsed(token.token_id)) {
    const err = new ExecutionDeniedError(
      'TOKEN_REPLAYED',
      `Execution replay detected: token_id=${token.token_id} has already been used`
    );
    emitAuditLog({ ...auditBase, reason: err.message, executed: false, error_type: err.error_type });
    throw err;
  }

  // --- Step 4: Proposal hash binding ---
  const expectedProposalHash = canonicalHash(proposal);
  if (token.proposal_hash !== expectedProposalHash) {
    const err = new ExecutionDeniedError(
      'PROPOSAL_HASH_MISMATCH',
      `Proposal hash mismatch: token=${token.proposal_hash} computed=${expectedProposalHash}`
    );
    emitAuditLog({ ...auditBase, reason: err.message, executed: false, error_type: err.error_type });
    throw err;
  }

  // --- Step 5: Policy hash binding (explicit) ---
  const currentPolicyHash = hashPolicyFile(proposal.policy_path);
  if (token.policy_hash !== currentPolicyHash) {
    const err = new ExecutionDeniedError(
      'POLICY_HASH_MISMATCH',
      `Policy changed since token issuance: token=${token.policy_hash} current=${currentPolicyHash}`
    );
    emitAuditLog({ ...auditBase, reason: err.message, executed: false, error_type: err.error_type });
    throw err;
  }

  // --- Step 6: Environment fingerprint binding ---
  if (token.environment_fingerprint !== currentEnvFingerprint) {
    const err = new ExecutionDeniedError(
      'ENV_FINGERPRINT_MISMATCH',
      `Environment changed since token issuance: token=${token.environment_fingerprint} current=${currentEnvFingerprint}`
    );
    emitAuditLog({ ...auditBase, reason: err.message, executed: false, error_type: err.error_type });
    throw err;
  }

  // --- Step 7: ED25519 signature ---
  const { issuer_signature, public_key_hex, ...payloadWithoutSig } = token;
  const canonicalPayload = canonicalStringify(payloadWithoutSig);
  const publicKeyBuffer = Buffer.from(public_key_hex, 'hex');
  let signatureValid = false;
  try {
    const publicKeyObj = createPublicKey({ key: publicKeyBuffer, format: 'der', type: 'spki' });
    signatureValid = cryptoVerify(
      null,
      Buffer.from(canonicalPayload, 'utf8'),
      publicKeyObj,
      Buffer.from(issuer_signature, 'hex')
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    const err = new ExecutionDeniedError(
      'SIGNATURE_INVALID',
      'ED25519 signature verification failed — token may have been tampered'
    );
    emitAuditLog({ ...auditBase, reason: err.message, executed: false, error_type: err.error_type });
    throw err;
  }

  // --- All 7 steps passed ---
  // Mark token used BEFORE spawn (replay blocked even on hang)
  // Reference: token_id only. Production kernel: composite key (proposal_hash|env_fp).
  markTokenUsed(token.token_id, {
    audit_ref: token.audit_ref,
    policy_hash: token.policy_hash,
    command,
    scope: token.scope,
    gate_mode: token.gate_mode,
    guard_version: token.guard_version
  });

  emitAuditLog({
    ...auditBase,
    reason: `policy_match: ${token.scope.constraints.policy_version}`,
    executed: true
  });

  // THE ONLY spawn() call in this codebase.
  const exitCode = await new Promise<number>((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'inherit', shell: false });
    child.on('close', (code) => resolve(code ?? 0));
    child.on('error', (err) => reject(err));
  });

  return {
    exit_code: exitCode,
    token_id: token.token_id,
    audit_ref: token.audit_ref,
    executed: true
  };
}
