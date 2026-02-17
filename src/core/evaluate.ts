/**
 * Policy Evaluation — Reference Implementation
 *
 * Deny-by-default. Exact command identity matching only.
 * No shell parsing. No semantic interpretation.
 *
 * SEALED: evaluate() is called from authority_pipeline only.
 * Adapters do not call evaluate() directly.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as yaml from 'yaml';

export interface PolicyRule {
  command: string;
  args?: string[];
  scope?: string;
  description?: string;
}

export interface Policy {
  default: 'DENY' | 'ALLOW';
  rules: PolicyRule[];
}

export interface ExecutionRequest {
  command: string;
  args: string[];
  policyPath?: string;
}

export interface EvaluationResult {
  verdict: 'ALLOW' | 'DENY';
  proposalHash: string;
  reason: string;
}

function generateProposalHash(command: string, args: string[]): string {
  const proposal = { command, args, timestamp: new Date().toISOString() };
  return crypto.createHash('sha256').update(JSON.stringify(proposal), 'utf8').digest('hex');
}

function loadPolicy(policyPath: string): Policy | null {
  try {
    if (!fs.existsSync(policyPath)) return null;
    const content = fs.readFileSync(policyPath, 'utf-8');
    const parsed = yaml.parse(content) as Policy;
    if (!parsed || typeof parsed !== 'object') return null;
    if (parsed.default !== 'DENY' && parsed.default !== 'ALLOW') return null;
    if (!Array.isArray(parsed.rules)) return null;
    return parsed;
  } catch {
    return null;  // Fail-closed: malformed policy → DENY
  }
}

function matchesRule(command: string, args: string[], rule: PolicyRule): boolean {
  if (command !== rule.command) return false;
  if (!rule.args) return true;
  if (rule.args.length === 1 && rule.args[0] === '*') return true;
  if (args.length !== rule.args.length) return false;
  return args.every((arg, i) => arg === rule.args![i] || rule.args![i] === '*');
}

/**
 * Evaluate an execution request against policy.
 * Fail-closed: no policy → DENY. No rule match + default DENY → DENY.
 */
export function evaluate(request: ExecutionRequest): EvaluationResult {
  const proposalHash = generateProposalHash(request.command, request.args);
  const policyPath = request.policyPath ?? './policy.yaml';
  const policy = loadPolicy(policyPath);

  if (!policy) {
    return { verdict: 'DENY', proposalHash, reason: 'No valid policy found. Fail-closed: DENY.' };
  }

  for (const rule of policy.rules) {
    if (matchesRule(request.command, request.args, rule)) {
      return {
        verdict: 'ALLOW',
        proposalHash,
        reason: `Policy match: command="${rule.command}" scope="${rule.scope ?? 'unset'}"`
      };
    }
  }

  return {
    verdict: policy.default,
    proposalHash,
    reason: `No rule matched. Default: ${policy.default}`
  };
}
