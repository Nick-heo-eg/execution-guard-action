/**
 * Environment Fingerprint — SHA256 of the execution environment.
 *
 * A token issued on runner A cannot be replayed on runner B.
 * Environment mismatch = STOP, even if token is structurally valid.
 *
 * Minimal required fields for GitHub Actions context.
 * Falls back to process-level values for local/non-CI use.
 */

import { createHash } from 'crypto';
import { hashPolicyFile } from './canonical_proposal.js';

export interface EnvironmentComponents {
  runner_os: string;
  arch: string;
  node_version: string;
  repo_sha: string;
  workflow_run_id: string;
  guard_version: string;
  policy_hash: string;
}

export function buildEnvironmentComponents(policyPath: string): EnvironmentComponents {
  return {
    runner_os: process.env['RUNNER_OS'] ?? process.platform,
    arch: process.arch,
    node_version: process.version,
    repo_sha: process.env['GITHUB_SHA'] ?? 'local',
    workflow_run_id: process.env['GITHUB_RUN_ID'] ?? 'local',
    guard_version: process.env['GUARD_VERSION'] ?? '0.3.0',
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
