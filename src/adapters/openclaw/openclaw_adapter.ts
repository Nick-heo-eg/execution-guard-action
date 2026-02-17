/**
 * OpenClaw Adapter — execute_with_authority (single public API)
 *
 * This is the ONLY entry point for OpenClaw to request execution.
 * It wraps the full 3-layer architecture in a single call:
 *
 *   1. Validate OpenClaw proposal (reject shell strings)
 *   2. Canonicalize → proposal_hash
 *   3. Scope elevation check (net/fs/admin require pre-approved token)
 *   4. Check token_store for human-approved token
 *   5. Run authority pipeline (Front Gate → Token Issuance)
 *   6. Kernel execution (7-step verify → spawn)
 *   7. Append structured OpenClaw audit log
 *
 * SECURITY INVARIANT: spawn() is never called from this file.
 *   All execution goes through executeWithAuthority() in execution_kernel.ts.
 *   scripts/check-spawn.sh enforces this in CI.
 *
 * GateMode behavior:
 *   STRICT + safe scope + policy match  → ALLOW (auto token)
 *   STRICT + net/fs/admin              → SCOPE_ELEVATION_HOLD (need human token)
 *   STRICT + admin scope               → SCOPE_ELEVATION_STOP (never auto)
 *   STRICT + rule miss                 → POLICY_MISS_STOP
 *
 *   PERMISSIVE + safe scope + policy match  → ALLOW (auto token)
 *   PERMISSIVE + net/fs scope + policy match → SCOPE_ELEVATION_HOLD (need human token)
 *   PERMISSIVE + admin scope               → SCOPE_ELEVATION_HOLD
 *   PERMISSIVE + rule miss                 → POLICY_MISS_HOLD
 *   PERMISSIVE + rule miss + allow_with_audit=true → AUDITED_PERMIT (ALLOW with audit flag)
 *
 *   Pre-approved token (any mode): token retrieved → kernel verifies all 7 steps
 */

import { createHash } from 'crypto';
import { runAuthorityPipeline } from '../../authority_pipeline.js';
import { executeWithAuthority } from '../../execution_kernel.js';
import { GateMode } from '../../config/mode.js';
import { appendAuditRecord } from '../../token_registry.js';
import { ExecutionDeniedError } from '../../errors.js';
import { validateOpenClawProposal, type OpenClawProposal } from './openclaw_proposal.js';
import { canonicalizeOpenClawProposal } from './canonicalize_openclaw.js';
import { retrieveToken, deleteToken } from './token_store.js';
import { getRuleScope, scopeRequiresPreApprovedToken, isAdminScope } from './scope_policy.js';

// ─── Public Types ─────────────────────────────────────────────────────────────

export type OpenClawVerdict = 'ALLOW' | 'STOP' | 'HOLD';

export type OpenClawReasonCode =
  | 'POLICY_MATCH_ALLOW'        // policy matched, safe scope, auto-allowed
  | 'PRE_APPROVED_TOKEN_ALLOW'  // human-approved token from token_store
  | 'AUDITED_PERMIT'            // PERMISSIVE + allow_with_audit=true (policy miss permitted)
  | 'POLICY_MISS_STOP'          // STRICT + no policy match
  | 'POLICY_MISS_HOLD'          // PERMISSIVE + no policy match (standard hold)
  | 'SCOPE_ELEVATION_HOLD'      // policy matched but scope needs human token
  | 'SCOPE_ELEVATION_STOP'      // admin scope in STRICT (never auto-execute)
  | 'SHELL_STRING_REJECTED'     // command/args contained shell metacharacters
  | 'VALIDATION_ERROR'          // malformed proposal
  | 'TOKEN_EXPIRED'
  | 'TOKEN_REPLAYED'
  | 'SIGNATURE_INVALID'
  | 'PROPOSAL_HASH_MISMATCH'
  | 'POLICY_HASH_MISMATCH'
  | 'ENV_FINGERPRINT_MISMATCH'
  | 'DECISION_NOT_ALLOW'
  | 'PIPELINE_ERROR';

export interface OpenClawExecuteRequest {
  /** Raw OpenClaw agent proposal (will be validated before use) */
  openclaw_proposal: unknown;
  /** Policy file path (defaults to ./policy.yaml) */
  policy_path?: string;
  /** Gate mode (defaults to GateMode.STRICT) */
  mode?: GateMode;
  /**
   * PERMISSIVE only: allow execution even on policy miss, with mandatory audit trail.
   * Does NOT apply to admin scope. Ignored in STRICT mode.
   */
  allow_with_audit?: boolean;
}

/** Structured OpenClaw audit log entry (§12 of work order) */
export interface OpenClawAuditEntry {
  time: string;
  actor: 'openclaw';
  agent_id: string;
  session_id: string;
  turn_id: string;
  proposal_hash: string;
  short_hash: string;
  verdict: OpenClawVerdict;
  reason_code: OpenClawReasonCode;
  reason: string;
  token_id: string | null;
  policy_hash: string | null;
  env_fp: string | null;
  command: string;
  /** SHA256(JSON.stringify(args)) — args stored as hash for privacy */
  args_hash: string;
  audited_permit: boolean;
  executed: boolean;
}

export interface OpenClawExecuteResult {
  verdict: OpenClawVerdict;
  proposal_hash: string;
  /** First 8 hex chars — for Telegram/UI display */
  short_hash: string;
  token_id: string | null;
  reason: string;
  reason_code: OpenClawReasonCode;
  audit_ref: string | null;
  executed: boolean;
  exit_code: number | null;
  audit_entry: OpenClawAuditEntry;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function argsHash(args: string[]): string {
  return createHash('sha256').update(JSON.stringify(args), 'utf8').digest('hex');
}

function buildAuditEntry(
  proposal: OpenClawProposal,
  proposalHash: string,
  shortHash: string,
  verdict: OpenClawVerdict,
  reasonCode: OpenClawReasonCode,
  reason: string,
  tokenId: string | null,
  policyHash: string | null,
  envFp: string | null,
  auditedPermit: boolean,
  executed: boolean
): OpenClawAuditEntry {
  return {
    time: new Date().toISOString(),
    actor: 'openclaw',
    agent_id: proposal.agent_id,
    session_id: proposal.session_id,
    turn_id: proposal.turn_id,
    proposal_hash: proposalHash,
    short_hash: shortHash,
    verdict,
    reason_code: reasonCode,
    reason,
    token_id: tokenId,
    policy_hash: policyHash,
    env_fp: envFp,
    command: proposal.command,
    args_hash: argsHash(proposal.args),
    audited_permit: auditedPermit,
    executed
  };
}

function earlyStop(
  reason: string,
  reasonCode: OpenClawReasonCode,
  command: string
): OpenClawExecuteResult {
  const dummyHash = 'unknown';
  return {
    verdict: 'STOP',
    proposal_hash: dummyHash,
    short_hash: dummyHash.slice(0, 8),
    token_id: null,
    reason,
    reason_code: reasonCode,
    audit_ref: null,
    executed: false,
    exit_code: null,
    audit_entry: {
      time: new Date().toISOString(),
      actor: 'openclaw',
      agent_id: 'unknown',
      session_id: 'unknown',
      turn_id: 'unknown',
      proposal_hash: dummyHash,
      short_hash: dummyHash.slice(0, 8),
      verdict: 'STOP',
      reason_code: reasonCode,
      reason,
      token_id: null,
      policy_hash: null,
      env_fp: null,
      command,
      args_hash: 'unknown',
      audited_permit: false,
      executed: false
    }
  };
}

// ─── Main Public API ──────────────────────────────────────────────────────────

/**
 * execute_with_authority — the ONLY execution path for OpenClaw.
 *
 * OpenClaw MUST call this function for every execution proposal.
 * Direct spawn() calls are prohibited and detected by CI guard.
 *
 * Never throws — fail-closed: returns STOP on unexpected error.
 */
export async function executeWithOpenClawAuthority(
  req: OpenClawExecuteRequest
): Promise<OpenClawExecuteResult> {
  const policyPath = req.policy_path ?? './policy.yaml';
  const mode = req.mode ?? GateMode.STRICT;
  const allowWithAudit = req.allow_with_audit ?? false;

  // ─── Step 1: Validate proposal ─────────────────────────────────────────────
  const validation = validateOpenClawProposal(req.openclaw_proposal);
  if (!validation.valid) {
    return earlyStop(validation.reason, validation.reason_code, 'unknown');
  }
  const ocProposal = validation.proposal;

  // ─── Step 2: Canonicalize → proposal_hash ─────────────────────────────────
  const { proposal, proposal_hash, short_hash } = canonicalizeOpenClawProposal(ocProposal, policyPath);

  // ─── Step 3: Scope elevation check ────────────────────────────────────────
  const scope = getRuleScope(ocProposal.command, policyPath) ?? 'safe';
  const needsPreApprovedToken = scopeRequiresPreApprovedToken(scope);

  // Admin scope in STRICT: hard block (no execution path)
  if (isAdminScope(scope) && mode === GateMode.STRICT) {
    const reason = `command "${ocProposal.command}" is admin scope — requires human-approved token. ` +
                   `In STRICT mode, admin commands cannot be auto-executed.`;
    const entry = buildAuditEntry(
      ocProposal, proposal_hash, short_hash,
      'STOP', 'SCOPE_ELEVATION_STOP', reason,
      null, null, null, false, false
    );
    appendAuditRecord({ ...entry });
    return {
      verdict: 'STOP', proposal_hash, short_hash,
      token_id: null, reason, reason_code: 'SCOPE_ELEVATION_STOP',
      audit_ref: null, executed: false, exit_code: null, audit_entry: entry
    };
  }

  // ─── Step 4: Check token_store for pre-approved token ────────────────────
  const storedToken = retrieveToken(proposal_hash);

  if (storedToken) {
    // Human-approved path: run kernel directly with stored token
    try {
      const kernelResult = await executeWithAuthority(
        ocProposal.command, ocProposal.args, proposal, storedToken
      );
      // Delete from store after use (kernel marks it used in registry)
      deleteToken(proposal_hash);

      const entry = buildAuditEntry(
        ocProposal, proposal_hash, short_hash,
        'ALLOW', 'PRE_APPROVED_TOKEN_ALLOW',
        'Human-approved token executed successfully',
        storedToken.token_id, storedToken.policy_hash,
        storedToken.environment_fingerprint, false, true
      );
      appendAuditRecord({ ...entry, exit_code: kernelResult.exit_code });

      return {
        verdict: 'ALLOW', proposal_hash, short_hash,
        token_id: storedToken.token_id,
        reason: 'Human-approved token executed successfully',
        reason_code: 'PRE_APPROVED_TOKEN_ALLOW',
        audit_ref: kernelResult.audit_ref,
        executed: true, exit_code: kernelResult.exit_code,
        audit_entry: entry
      };
    } catch (err) {
      deleteToken(proposal_hash); // Remove invalid/expired stored token
      const isDenied = err instanceof ExecutionDeniedError;
      const errType = isDenied ? (err as ExecutionDeniedError).error_type : 'PIPELINE_ERROR';
      const reason = err instanceof Error ? err.message : String(err);
      const entry = buildAuditEntry(
        ocProposal, proposal_hash, short_hash,
        'STOP', errType as OpenClawReasonCode, reason,
        storedToken.token_id, storedToken.policy_hash,
        storedToken.environment_fingerprint, false, false
      );
      appendAuditRecord({ ...entry });
      return {
        verdict: 'STOP', proposal_hash, short_hash,
        token_id: storedToken.token_id, reason,
        reason_code: errType as OpenClawReasonCode,
        audit_ref: null, executed: false, exit_code: null,
        audit_entry: entry
      };
    }
  }

  // ─── Step 5: Scope elevation → HOLD if no token and scope requires it ─────
  if (needsPreApprovedToken) {
    const reason = `command "${ocProposal.command}" is ${scope} scope — requires human-approved token. ` +
                   `proposal_hash: ${short_hash}. Store approval via token_store.storeToken().`;
    const entry = buildAuditEntry(
      ocProposal, proposal_hash, short_hash,
      'HOLD', 'SCOPE_ELEVATION_HOLD', reason,
      null, null, null, false, false
    );
    appendAuditRecord({ ...entry });
    return {
      verdict: 'HOLD', proposal_hash, short_hash,
      token_id: null, reason, reason_code: 'SCOPE_ELEVATION_HOLD',
      audit_ref: null, executed: false, exit_code: null,
      audit_entry: entry
    };
  }

  // ─── Step 6: Authority pipeline (safe scope auto-issuance or audited permit) ──
  //
  // allow_with_audit: PERMISSIVE + policy miss → issue ALLOW token with audit flag
  // This is safe because the kernel still runs all 7 verification steps.
  // The 'audited_permit' flag in scope.constraints marks it as policy-miss execution.
  const pipelineResult = await runAuthorityPipeline(
    ocProposal.command,
    ocProposal.args,
    policyPath,
    mode,
    allowWithAudit  // new parameter — see authority_pipeline.ts
  );

  if (pipelineResult.decision === 'STOP') {
    const reason = pipelineResult.reason;
    const entry = buildAuditEntry(
      ocProposal, proposal_hash, short_hash,
      'STOP', 'POLICY_MISS_STOP', reason,
      null, null, null, false, false
    );
    return {
      verdict: 'STOP', proposal_hash, short_hash,
      token_id: null, reason, reason_code: 'POLICY_MISS_STOP',
      audit_ref: null, executed: false, exit_code: null,
      audit_entry: entry
    };
  }

  if (pipelineResult.decision === 'HOLD') {
    const reason = pipelineResult.reason;
    const reasonCode: OpenClawReasonCode = 'POLICY_MISS_HOLD';
    const entry = buildAuditEntry(
      ocProposal, proposal_hash, short_hash,
      'HOLD', reasonCode, reason,
      pipelineResult.token?.token_id ?? null,
      pipelineResult.token?.policy_hash ?? null,
      pipelineResult.token?.environment_fingerprint ?? null,
      false, false
    );
    return {
      verdict: 'HOLD', proposal_hash, short_hash,
      token_id: pipelineResult.token?.token_id ?? null,
      reason, reason_code: reasonCode,
      audit_ref: pipelineResult.token?.audit_ref ?? null,
      executed: false, exit_code: null,
      audit_entry: entry
    };
  }

  // ─── Step 7: ALLOW — run kernel ───────────────────────────────────────────
  if (!pipelineResult.token || !pipelineResult.proposal) {
    const reason = '[INVARIANT VIOLATION] ALLOW decision without token — STOP.';
    return earlyStop(reason, 'PIPELINE_ERROR', ocProposal.command);
  }

  const isAuditedPermit = pipelineResult.token.scope.constraints.gate_mode === mode &&
    (pipelineResult.token.scope.constraints as Record<string,string>)['audited_permit'] === 'true';
  const reasonCode: OpenClawReasonCode = isAuditedPermit ? 'AUDITED_PERMIT' : 'POLICY_MATCH_ALLOW';

  try {
    const kernelResult = await executeWithAuthority(
      ocProposal.command,
      ocProposal.args,
      pipelineResult.proposal,
      pipelineResult.token
    );

    const entry = buildAuditEntry(
      ocProposal, proposal_hash, short_hash,
      'ALLOW', reasonCode, pipelineResult.reason,
      pipelineResult.token.token_id,
      pipelineResult.token.policy_hash,
      pipelineResult.token.environment_fingerprint,
      isAuditedPermit, true
    );
    appendAuditRecord({ ...entry, exit_code: kernelResult.exit_code });

    return {
      verdict: 'ALLOW', proposal_hash, short_hash,
      token_id: pipelineResult.token.token_id,
      reason: pipelineResult.reason,
      reason_code: reasonCode,
      audit_ref: kernelResult.audit_ref,
      executed: true, exit_code: kernelResult.exit_code,
      audit_entry: entry
    };

  } catch (err) {
    const isDenied = err instanceof ExecutionDeniedError;
    const errType = isDenied ? (err as ExecutionDeniedError).error_type : 'PIPELINE_ERROR';
    const reason = err instanceof Error ? err.message : String(err);
    const entry = buildAuditEntry(
      ocProposal, proposal_hash, short_hash,
      'STOP', errType as OpenClawReasonCode, reason,
      pipelineResult.token.token_id,
      pipelineResult.token.policy_hash,
      pipelineResult.token.environment_fingerprint,
      isAuditedPermit, false
    );
    appendAuditRecord({ ...entry });
    return {
      verdict: 'STOP', proposal_hash, short_hash,
      token_id: pipelineResult.token.token_id,
      reason, reason_code: errType as OpenClawReasonCode,
      audit_ref: null, executed: false, exit_code: null,
      audit_entry: entry
    };
  }
}
