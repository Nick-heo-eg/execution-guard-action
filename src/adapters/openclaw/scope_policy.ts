/**
 * Scope Policy — extract and enforce command scope from policy.yaml.
 *
 * Scope is metadata on each policy rule: safe | net | fs | admin
 *
 * Enforcement rules (applied on top of evaluate() result):
 *   safe  → auto-ALLOW in both STRICT and PERMISSIVE when policy matches
 *   net   → requires pre-approved token even when policy matches
 *   fs    → requires pre-approved token even when policy matches
 *   admin → requires pre-approved token in ALL modes (never auto-issued)
 *
 * This is enforced in the adapter AFTER evaluate() returns ALLOW.
 * If evaluate() returns DENY, the gate decision already handles it.
 */

import { readFileSync, existsSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import type { CommandScope } from './openclaw_proposal.js';

interface PolicyRule {
  command: string;
  scope?: string;
  args?: string[];
}

interface PolicyFile {
  default?: string;
  rules?: PolicyRule[];
}

/**
 * Get the scope of the first matching rule for a command.
 * Returns 'safe' as default if rule has no scope field.
 * Returns null if no matching rule found (evaluate() will handle DENY).
 */
export function getRuleScope(command: string, policyPath: string): CommandScope | null {
  try {
    if (!existsSync(policyPath)) return null;
    const content = readFileSync(policyPath, 'utf8');
    const policy = parseYaml(content) as PolicyFile;
    if (!policy?.rules) return null;

    for (const rule of policy.rules) {
      if (rule.command === command) {
        const scope = (rule.scope ?? 'safe') as CommandScope;
        return scope;
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Determine if a scope requires a pre-approved token (human-in-the-loop).
 *
 * safe  → no, auto-issuance fine
 * net   → yes, human token required
 * fs    → yes, human token required
 * admin → yes, always (even in PERMISSIVE)
 */
export function scopeRequiresPreApprovedToken(scope: CommandScope): boolean {
  return scope === 'net' || scope === 'fs' || scope === 'admin';
}

/**
 * Determine if admin scope is blocked in STRICT mode (no execution path).
 */
export function isAdminScope(scope: CommandScope): boolean {
  return scope === 'admin';
}
