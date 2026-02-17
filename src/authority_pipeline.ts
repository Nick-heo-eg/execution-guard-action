/**
 * Authority Pipeline — evaluate → issue → VerifiedToken
 *
 * Orchestrates:
 *   1. Build canonical proposal
 *   2. Build environment fingerprint
 *   3. evaluate() [sealed core — never modified]
 *   4. STRICT: rule miss → STOP (no token). PERMISSIVE: rule miss → HOLD token.
 *   5. ALLOW: issue ALLOW token with ephemeral ED25519 key
 *
 * SEAL BOUNDARY: evaluate() called here and nowhere else.
 *
 * Decision → Token mapping:
 *   ALLOW  → VerifiedToken(decision='ALLOW')  → kernel may spawn
 *   STOP   → no token                          → kernel never reached
 *   HOLD   → VerifiedToken(decision='HOLD')   → kernel blocks spawn (step 2)
 *
 * GateMode.STRICT  (default): evaluate DENY → STOP
 * GateMode.PERMISSIVE        : evaluate DENY → HOLD token
 */

import { generateKeyPairSync, sign as cryptoSign } from 'crypto';
import { evaluate } from 'execution-runtime-core/src/core/evaluate.js';
import { buildCanonicalProposal, canonicalHash, hashPolicyFile, type CanonicalProposal } from './canonical_proposal.js';
import { buildEnvironmentFingerprint } from './environment_fingerprint.js';
import { appendAuditRecord } from './token_registry.js';
import { canonicalStringify } from './canonical_stringify.js';
import { GateMode } from './config/mode.js';
import { uuidv7 } from './uuid_v7.js';
import type { VerifiedToken, TokenScope, TokenDecision } from './execution_kernel.js';

const GUARD_VERSION = process.env['GUARD_VERSION'] ?? '0.4.0';
const TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes — single-run window

export type PipelineDecision = 'ALLOW' | 'STOP' | 'HOLD';

export interface PipelineResult {
  decision: PipelineDecision;
  proposal_hash: string;
  reason: string;
  /** Present when decision === 'ALLOW' or 'HOLD' */
  token?: VerifiedToken;
  /** Present when decision === 'ALLOW' or 'HOLD' */
  proposal?: CanonicalProposal;
  gate_mode: string;
}

/**
 * Run the full authority pipeline.
 *
 * Never throws — fail-closed: returns STOP on any internal error.
 */
export async function runAuthorityPipeline(
  command: string,
  args: string[],
  policyPath: string,
  mode: GateMode = GateMode.STRICT
): Promise<PipelineResult> {
  try {
    return await _pipeline(command, args, policyPath, mode);
  } catch (err) {
    const safeMsg = err instanceof Error ? err.message : String(err);
    console.error(`[PIPELINE ERROR] ${safeMsg}`);
    appendAuditRecord({
      event: 'PIPELINE_ERROR',
      error: safeMsg,
      command,
      args,
      policy_path: policyPath,
      gate_mode: mode,
      guard_version: GUARD_VERSION,
      timestamp: new Date().toISOString()
    });
    return {
      decision: 'STOP',
      proposal_hash: 'error',
      reason: `pipeline_error: ${safeMsg}`,
      gate_mode: mode
    };
  }
}

async function _pipeline(
  command: string,
  args: string[],
  policyPath: string,
  mode: GateMode
): Promise<PipelineResult> {
  // Step 1: Build canonical proposal
  const proposal = buildCanonicalProposal(command, args, policyPath);
  const proposalHash = canonicalHash(proposal);
  const policyHash = hashPolicyFile(policyPath);

  // Step 2: Build environment fingerprint
  const envFingerprint = buildEnvironmentFingerprint(policyPath);

  // Step 3: Evaluate via sealed core
  const evalResult = evaluate({ command, args, policyPath });

  const coreAllowed = evalResult.verdict === 'ALLOW';

  // Step 4: Mode-gated decision
  let tokenDecision: TokenDecision;
  let pipelineDecision: PipelineDecision;

  if (coreAllowed) {
    tokenDecision = 'ALLOW';
    pipelineDecision = 'ALLOW';
  } else if (mode === GateMode.PERMISSIVE) {
    // PERMISSIVE: rule miss → HOLD token (auditable, not blocked at gate)
    tokenDecision = 'HOLD';
    pipelineDecision = 'HOLD';
  } else {
    // STRICT: rule miss → STOP, no token issued
    appendAuditRecord({
      event: 'STOP',
      proposal_hash: proposalHash,
      environment_fingerprint: envFingerprint,
      policy_hash: policyHash,
      reason: evalResult.reason,
      command,
      args,
      policy_path: policyPath,
      gate_mode: mode,
      guard_version: GUARD_VERSION,
      timestamp: new Date().toISOString()
    });
    return { decision: 'STOP', proposal_hash: proposalHash, reason: evalResult.reason, gate_mode: mode };
  }

  // Step 5: Issue authority token (ALLOW or HOLD)
  const { privateKey: ephemeralPrivKey, publicKey: ephemeralPubKey } =
    generateKeyPairSync('ed25519');

  const publicKeyHex = ephemeralPubKey
    .export({ type: 'spki', format: 'der' })
    .toString('hex');

  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + TOKEN_TTL_MS);
  const auditRef = uuidv7();
  const tokenId = uuidv7();

  const scope: TokenScope = {
    action: 'execute',
    resource: `${command} ${args.join(' ')}`.trim(),
    constraints: {
      policy_version: policyHash,
      gate_mode: mode,
      guard_version: GUARD_VERSION
    }
  };

  const tokenPayload: Omit<VerifiedToken, 'issuer_signature' | 'public_key_hex'> = {
    token_id: tokenId,
    proposal_hash: proposalHash,
    policy_hash: policyHash,
    environment_fingerprint: envFingerprint,
    policy_version: policyHash, // backward compat alias
    decision: tokenDecision,
    audit_ref: auditRef,
    expires_at: expiresAt.toISOString(),
    issued_at: issuedAt.toISOString(),
    scope,
    gate_mode: mode,
    guard_version: GUARD_VERSION
  };

  // Step 6: Sign with ephemeral ED25519 (algorithm=null: key type implies hash)
  const canonicalPayload = canonicalStringify(tokenPayload);
  const signatureBuffer = cryptoSign(null, Buffer.from(canonicalPayload, 'utf8'), ephemeralPrivKey);
  const signatureHex = signatureBuffer.toString('hex');

  const token: VerifiedToken = {
    ...tokenPayload,
    issuer_signature: signatureHex,
    public_key_hex: publicKeyHex
  };

  // Step 7: Log issuance
  appendAuditRecord({
    event: `TOKEN_ISSUED_${tokenDecision}`,
    token_id: tokenId,
    audit_ref: auditRef,
    proposal_hash: proposalHash,
    policy_hash: policyHash,
    environment_fingerprint: envFingerprint,
    decision: tokenDecision,
    command,
    args,
    gate_mode: mode,
    guard_version: GUARD_VERSION,
    expires_at: expiresAt.toISOString(),
    timestamp: issuedAt.toISOString()
  });

  return {
    decision: pipelineDecision,
    proposal_hash: proposalHash,
    reason: evalResult.reason,
    token,
    proposal,
    gate_mode: mode
  };
}
