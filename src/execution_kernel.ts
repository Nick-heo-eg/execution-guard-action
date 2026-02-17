/**
 * Execution Kernel — THE ONLY authorized spawn() call site.
 *
 * SECURITY CONTRACT:
 *   spawn() MUST NOT be called anywhere else in this codebase.
 *   A verified authority token is required to reach this function.
 *   Token verification is rechecked here — defense in depth.
 *   No token = no spawn. Period.
 *
 * CI guard: scripts/check-spawn.sh enforces this at build time.
 */

import { spawn } from 'child_process';
import { verify as cryptoVerify, createPublicKey } from 'crypto';
import { isTokenUsed, markTokenUsed } from './token_registry.js';
import { canonicalHash, type CanonicalProposal } from './canonical_proposal.js';
import { buildEnvironmentFingerprint } from './environment_fingerprint.js';
import { canonicalStringify } from './canonical_stringify.js';

/** A token that has been issued and verified by the authority pipeline. */
export interface VerifiedToken {
  token_id: string;
  proposal_hash: string;
  environment_fingerprint: string;
  policy_version: string;
  decision: 'ALLOW';
  audit_ref: string;
  expires_at: string;
  issued_at: string;
  scope: string;
  guard_version: string;
  /** ED25519 signature over canonical token payload (excluding this field) */
  issuer_signature: string;
  /** Public key hex used to issue this token (ephemeral, per-run) */
  public_key_hex: string;
}

export interface KernelResult {
  exit_code: number;
  token_id: string;
  audit_ref: string;
}

/**
 * Execute a command under authority of a verified token.
 *
 * Verification chain (all must pass — fail-closed):
 *   1. Token not expired (TTL)
 *   2. Token decision is ALLOW
 *   3. Token not already used (replay prevention)
 *   4. proposal_hash matches re-computed canonical hash
 *   5. environment_fingerprint matches current environment
 *   6. ED25519 signature is valid
 *
 * Token is marked used BEFORE spawn — prevents replay even on hang.
 *
 * @throws Error if ANY verification step fails. spawn() is NEVER reached on failure.
 */
export async function executeWithAuthority(
  command: string,
  args: string[],
  proposal: CanonicalProposal,
  token: VerifiedToken
): Promise<KernelResult> {
  // --- Verification Step 1: TTL ---
  const now = new Date();
  const expiresAt = new Date(token.expires_at);
  if (now > expiresAt) {
    throw new Error(
      `[KERNEL] Token expired. expires_at=${token.expires_at}, now=${now.toISOString()}. SPAWN BLOCKED.`
    );
  }

  // --- Verification Step 2: Decision gate ---
  if (token.decision !== 'ALLOW') {
    throw new Error(
      `[KERNEL] Token decision is '${token.decision}', not ALLOW. SPAWN BLOCKED.`
    );
  }

  // --- Verification Step 3: Replay prevention (in-memory + persistent) ---
  if (isTokenUsed(token.token_id)) {
    throw new Error(
      `[KERNEL] Token replay detected. token_id=${token.token_id}. SPAWN BLOCKED.`
    );
  }

  // --- Verification Step 4: Proposal hash binding ---
  const expectedProposalHash = canonicalHash(proposal);
  if (token.proposal_hash !== expectedProposalHash) {
    throw new Error(
      `[KERNEL] Proposal hash mismatch. ` +
      `token=${token.proposal_hash}, computed=${expectedProposalHash}. SPAWN BLOCKED.`
    );
  }

  // --- Verification Step 5: Environment fingerprint binding ---
  const currentEnvFingerprint = buildEnvironmentFingerprint(proposal.policy_path);
  if (token.environment_fingerprint !== currentEnvFingerprint) {
    throw new Error(
      `[KERNEL] Environment fingerprint mismatch. ` +
      `token=${token.environment_fingerprint}, current=${currentEnvFingerprint}. ` +
      `Policy or runner environment changed between issuance and execution. SPAWN BLOCKED.`
    );
  }

  // --- Verification Step 6: ED25519 signature ---
  // Reconstruct the exact payload that was signed (everything except sig + public_key_hex)
  const { issuer_signature, public_key_hex, ...payloadWithoutSig } = token;
  const canonicalPayload = canonicalStringify(payloadWithoutSig);
  const publicKeyBuffer = Buffer.from(public_key_hex, 'hex');
  const publicKeyObj = createPublicKey({ key: publicKeyBuffer, format: 'der', type: 'spki' });
  // Node.js Ed25519 verify: algorithm is null (key type implies algorithm)
  const signatureValid = cryptoVerify(
    null,
    Buffer.from(canonicalPayload, 'utf8'),
    publicKeyObj,
    Buffer.from(issuer_signature, 'hex')
  );
  if (!signatureValid) {
    throw new Error(
      `[KERNEL] Signature verification failed. Token may have been tampered with. SPAWN BLOCKED.`
    );
  }

  // --- All verifications passed ---
  // Mark token used BEFORE spawn (prevents replay even if process hangs)
  markTokenUsed(token.token_id, {
    audit_ref: token.audit_ref,
    proposal_hash: token.proposal_hash,
    env_fingerprint: token.environment_fingerprint,
    command,
    args,
    scope: token.scope,
    guard_version: token.guard_version
  });

  console.log(`[KERNEL] Token verified. token_id=${token.token_id} audit_ref=${token.audit_ref}`);
  console.log(`[KERNEL] Spawning: ${command} ${args.join(' ')}`);

  // THE ONLY spawn() call in this codebase.
  const exitCode = await new Promise<number>((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'inherit', shell: false });
    child.on('close', (code) => resolve(code ?? 0));
    child.on('error', (err) => reject(err));
  });

  return {
    exit_code: exitCode,
    token_id: token.token_id,
    audit_ref: token.audit_ref
  };
}
