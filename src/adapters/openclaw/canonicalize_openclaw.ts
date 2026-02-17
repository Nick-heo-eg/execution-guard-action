/**
 * Canonicalize OpenClaw Proposal → CanonicalProposal
 *
 * Converts an OpenClaw agent proposal into the deterministic canonical form
 * that the authority pipeline uses for hashing and token binding.
 *
 * INVARIANT: Same OpenClaw proposal always produces the same CanonicalProposal
 *            (and therefore the same proposal_hash).
 *
 * Only command + args are hashed. Metadata (session_id, agent_id, etc.)
 * goes into the audit log but does NOT affect the proposal_hash.
 * This means: two different agents requesting the same command+args
 * will get the same proposal_hash — intentional (it's the execution that's bound,
 * not the agent identity, which is enforced at the policy/token level).
 */

import { buildCanonicalProposal, canonicalHash, type CanonicalProposal } from '../../canonical_proposal.js';
import type { OpenClawProposal } from './openclaw_proposal.js';

export interface OpenClawCanonicalResult {
  proposal: CanonicalProposal;
  proposal_hash: string;
  /** First 8 hex chars — for display in Telegram/UI */
  short_hash: string;
}

/**
 * Build a CanonicalProposal from an OpenClaw proposal.
 *
 * policy_ref in the OpenClaw proposal (if provided) overrides the default policyPath.
 */
export function canonicalizeOpenClawProposal(
  ocProposal: OpenClawProposal,
  defaultPolicyPath: string
): OpenClawCanonicalResult {
  const policyPath = ocProposal.policy_ref ?? defaultPolicyPath;

  // buildCanonicalProposal uses command + args + policyPath + timestamp_floor + guard_version
  const proposal = buildCanonicalProposal(ocProposal.command, ocProposal.args, policyPath);
  const proposal_hash = canonicalHash(proposal);

  return {
    proposal,
    proposal_hash,
    short_hash: proposal_hash.slice(0, 8)
  };
}
