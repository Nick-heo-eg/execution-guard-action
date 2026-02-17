/**
 * Environment Fingerprint — Reference Implementation
 *
 * REFERENCE ONLY: Demonstrates the concept of environment binding.
 * Uses 3 stable fields sufficient for local/PoC use.
 *
 * Production kernel: extended runner-identity binding.
 * See echo-execution-kernel (private).
 *
 * Concept: A token issued in environment A cannot be verified in environment B.
 * Environment change = different fingerprint = ENV_FINGERPRINT_MISMATCH at step 6.
 */

import { createHash } from 'crypto';
import { hashPolicyFile } from './canonical_proposal.js';

export interface EnvironmentComponents {
  node_version: string;   // process.version — runtime identity
  runner_os: string;      // RUNNER_OS / process.platform
  policy_hash: string;    // SHA256(policy.yaml) — policy change = new env
}

export function buildEnvironmentComponents(policyPath: string): EnvironmentComponents {
  return {
    node_version: process.version,
    runner_os: process.env['RUNNER_OS'] ?? process.platform,
    policy_hash: hashPolicyFile(policyPath)
  };
}

/**
 * Build SHA256 fingerprint of the current execution environment.
 * Keys sorted for determinism.
 */
export function buildEnvironmentFingerprint(policyPath: string): string {
  const components = buildEnvironmentComponents(policyPath);
  const keys = Object.keys(components).sort() as (keyof EnvironmentComponents)[];
  const stable: Record<string, string> = {};
  for (const k of keys) stable[k] = components[k];
  const serialized = JSON.stringify(stable);
  return createHash('sha256').update(serialized, 'utf8').digest('hex');
}
