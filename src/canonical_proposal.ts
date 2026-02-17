/**
 * Canonical Proposal — Stable, deterministic hash of an execution request.
 *
 * Same inputs MUST always produce the same hash.
 * Any change to command, args, policy, or time window = different hash.
 *
 * This is the root of the audit chain. Every token is bound to this hash.
 */

import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';

export interface CanonicalProposal {
  command: string;
  args: string[];
  policy_path: string;
  policy_hash: string;   // SHA256 of policy.yaml content
  guard_version: string;
  timestamp_floor: string; // Floored to 60s — defines token TTL window
}

/**
 * Hash the policy file content deterministically.
 * Returns 'policy_not_found' if file is missing — triggers DENY at evaluate().
 */
export function hashPolicyFile(policyPath: string): string {
  try {
    if (!existsSync(policyPath)) return 'policy_not_found';
    const content = readFileSync(policyPath, 'utf8');
    return createHash('sha256').update(content, 'utf8').digest('hex');
  } catch {
    return 'policy_read_error';
  }
}

/**
 * Build canonical proposal from execution inputs.
 * timestamp_floor is floored to the current 60-second window.
 */
export function buildCanonicalProposal(
  command: string,
  args: string[],
  policyPath: string
): CanonicalProposal {
  const now = new Date();
  now.setSeconds(0, 0); // Floor to minute boundary

  return {
    command,
    args: [...args], // Defensive copy — preserve order
    policy_path: policyPath,
    policy_hash: hashPolicyFile(policyPath),
    guard_version: process.env['GUARD_VERSION'] ?? '0.3.0',
    timestamp_floor: now.toISOString()
  };
}

/**
 * Compute SHA256 of canonical proposal.
 * Keys are sorted alphabetically for determinism.
 * Array order is preserved (args order is significant).
 */
export function canonicalHash(proposal: CanonicalProposal): string {
  const stable = stableStringify(proposal);
  return createHash('sha256').update(stable, 'utf8').digest('hex');
}

/**
 * Stable JSON stringify — sorted keys, no spaces, arrays preserve order.
 */
function stableStringify(obj: unknown): string {
  if (Array.isArray(obj)) {
    return '[' + obj.map(stableStringify).join(',') + ']';
  }
  if (obj !== null && typeof obj === 'object') {
    const sorted = Object.keys(obj as Record<string, unknown>)
      .sort()
      .map((k) => {
        const v = (obj as Record<string, unknown>)[k];
        return JSON.stringify(k) + ':' + stableStringify(v);
      });
    return '{' + sorted.join(',') + '}';
  }
  return JSON.stringify(obj);
}
