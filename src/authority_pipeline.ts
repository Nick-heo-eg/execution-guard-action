/**
 * Authority Pipeline — evaluate → issue → verify → VerifiedToken
 *
 * This module is the bridge between the sealed evaluate() core
 * and the execution kernel. It orchestrates:
 *
 *   1. Build canonical proposal
 *   2. Build environment fingerprint
 *   3. Call evaluate() (sealed core — never modified)
 *   4. If ALLOW: generate ephemeral ED25519 key pair, issue token, return VerifiedToken
 *   5. If STOP/DENY: append audit record, return STOP result
 *
 * Key design: ephemeral ED25519 key pair is generated fresh each run.
 * Keys are never persisted — by design. Production would use HSM/KMS.
 *
 * SEAL BOUNDARY: evaluate() is called here and nowhere else.
 */

import { generateKeyPairSync, sign as cryptoSign, randomUUID } from 'crypto';
import { evaluate } from 'execution-runtime-core/src/core/evaluate.js';
import { buildCanonicalProposal, canonicalHash, type CanonicalProposal } from './canonical_proposal.js';
import { buildEnvironmentFingerprint } from './environment_fingerprint.js';
import { appendAuditRecord } from './token_registry.js';
import { canonicalStringify } from './canonical_stringify.js';
import type { VerifiedToken } from './execution_kernel.js';

const GUARD_VERSION = process.env['GUARD_VERSION'] ?? '0.3.0';
const TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes — single-run window

export type PipelineDecision = 'ALLOW' | 'STOP' | 'HOLD';

export interface PipelineResult {
  decision: PipelineDecision;
  proposal_hash: string;
  reason: string;
  /** Present only when decision === 'ALLOW' */
  token?: VerifiedToken;
  /** Present only when decision === 'ALLOW' */
  proposal?: CanonicalProposal;
}

/**
 * Run the full authority pipeline for a command + policy.
 *
 * Returns a PipelineResult — caller must check decision before proceeding.
 * Never throws — fail-closed: returns STOP on any internal error.
 */
export async function runAuthorityPipeline(
  command: string,
  args: string[],
  policyPath: string
): Promise<PipelineResult> {
  try {
    return await _pipeline(command, args, policyPath);
  } catch (err) {
    // Fail-closed: any internal error → STOP
    const safeMsg = err instanceof Error ? err.message : String(err);
    console.error(`[PIPELINE ERROR] ${safeMsg}`);
    appendAuditRecord({
      event: 'PIPELINE_ERROR',
      error: safeMsg,
      command,
      args,
      policy_path: policyPath,
      guard_version: GUARD_VERSION,
      timestamp: new Date().toISOString()
    });
    return {
      decision: 'STOP',
      proposal_hash: 'error',
      reason: `pipeline_error: ${safeMsg}`
    };
  }
}

async function _pipeline(
  command: string,
  args: string[],
  policyPath: string
): Promise<PipelineResult> {
  // Step 1: Build canonical proposal (binds command + args + policy hash + timestamp)
  const proposal = buildCanonicalProposal(command, args, policyPath);
  const proposalHash = canonicalHash(proposal);

  // Step 2: Build environment fingerprint (binds runner identity)
  const envFingerprint = buildEnvironmentFingerprint(policyPath);

  // Step 3: Evaluate via sealed core (evaluate.ts is NEVER modified)
  const evalResult = evaluate({ command, args, policyPath });

  // Map core verdict to pipeline decision
  const decision: PipelineDecision = evalResult.verdict === 'ALLOW' ? 'ALLOW' : 'STOP';

  if (decision === 'STOP') {
    appendAuditRecord({
      event: 'STOP',
      proposal_hash: proposalHash,
      environment_fingerprint: envFingerprint,
      reason: evalResult.reason,
      command,
      args,
      policy_path: policyPath,
      guard_version: GUARD_VERSION,
      timestamp: new Date().toISOString()
    });
    return { decision: 'STOP', proposal_hash: proposalHash, reason: evalResult.reason };
  }

  // Step 4: ALLOW — generate ephemeral ED25519 key pair (not persisted, per-run only)
  const { privateKey: ephemeralPrivKey, publicKey: ephemeralPubKey } =
    generateKeyPairSync('ed25519');

  const publicKeyHex = ephemeralPubKey
    .export({ type: 'spki', format: 'der' })
    .toString('hex');

  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + TOKEN_TTL_MS);
  const auditRef = randomUUID();
  const tokenId = randomUUID();

  // Build token payload (without signature — this is what gets signed)
  const tokenPayload: Omit<VerifiedToken, 'issuer_signature' | 'public_key_hex'> = {
    token_id: tokenId,
    proposal_hash: proposalHash,
    environment_fingerprint: envFingerprint,
    policy_version: proposal.policy_hash, // policy version = policy content hash
    decision: 'ALLOW',
    audit_ref: auditRef,
    expires_at: expiresAt.toISOString(),
    issued_at: issuedAt.toISOString(),
    scope: 'execution-guard-action',
    guard_version: GUARD_VERSION
  };

  // Step 5: Sign with ephemeral ED25519 private key
  // Node.js ED25519 signing: algorithm must be null (key type implies algorithm)
  const canonicalPayload = canonicalStringify(tokenPayload);
  const signatureBuffer = cryptoSign(null, Buffer.from(canonicalPayload, 'utf8'), ephemeralPrivKey);
  const signatureHex = signatureBuffer.toString('hex');

  const token: VerifiedToken = {
    ...tokenPayload,
    issuer_signature: signatureHex,
    public_key_hex: publicKeyHex
  };

  // Step 6: Log issuance audit record
  appendAuditRecord({
    event: 'TOKEN_ISSUED',
    token_id: tokenId,
    audit_ref: auditRef,
    proposal_hash: proposalHash,
    environment_fingerprint: envFingerprint,
    policy_version: proposal.policy_hash,
    command,
    args,
    guard_version: GUARD_VERSION,
    expires_at: expiresAt.toISOString(),
    timestamp: issuedAt.toISOString()
  });

  return {
    decision: 'ALLOW',
    proposal_hash: proposalHash,
    reason: evalResult.reason,
    token,
    proposal
  };
}
