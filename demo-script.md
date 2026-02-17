# Execution Guard — 60-Second Demo Script

**Format**: Screen capture with terminal + GitHub Actions log
**Duration**: ~60 seconds
**Goal**: Show that dangerous commands are blocked, safe commands execute, and every decision is traced.

---

## Setup (pre-record)

Ensure you have:
- A checkout of this repo
- `dist/index.js` built (committed)
- Policy file `policies/safe-commands.yaml` in place

---

## Script

### [0:00 - 0:08] Intro

> "Execution Guard blocks dangerous commands before they run — at the GitHub Actions level."

Show the README hero line on screen:
```
Execution Guard is a deny-by-default execution layer for GitHub Actions
built on Execution Boundary architecture.
```

---

### [0:08 - 0:20] Scene 1: Dangerous Command — STOP

**Show**: Trigger a workflow with `rm -rf /`

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.1.0
  with:
    command: 'rm -rf /'
    policy_path: './policies/safe-commands.yaml'
```

**Expected Actions log output**:
```
DECISION: STOP
PROPOSAL_HASH: 8b4e91d3a...
REASON: No rule matched. Default: DENY
❌ EXECUTION BLOCKED (STOP)
   Command: rm -rf /
   Policy:  ./policies/safe-commands.yaml
Error: Execution denied by policy. DECISION: STOP
```

**Narrate**: "rm -rf / is not in the policy. Decision is immediate: STOP. The job fails. The filesystem is untouched."

---

### [0:20 - 0:32] Scene 2: Network Command — STOP

**Show**: Trigger with `curl https://example.com`

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.1.0
  with:
    command: 'curl https://example.com'
    policy_path: './policies/safe-commands.yaml'
```

**Expected output**:
```
DECISION: STOP
PROPOSAL_HASH: a3f2c1e8b...
REASON: No rule matched. Default: DENY
❌ EXECUTION BLOCKED (STOP)
```

**Narrate**: "curl is not in the policy either. No network call was made. Decision was STOP before the process even started."

---

### [0:32 - 0:46] Scene 3: Safe Command — ALLOW

**Show**: Trigger with `echo hello from execution-guard`

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.1.0
  with:
    command: 'echo hello from execution-guard'
    policy_path: './policies/safe-commands.yaml'
```

**Expected output**:
```
DECISION: ALLOW
PROPOSAL_HASH: 7d2f44a9c...
REASON: Policy match: command="echo" scope="safe-commands"

✅ Execution permitted: echo hello from execution-guard
hello from execution-guard
```

**Narrate**: "echo is in the policy. ALLOW. The command runs. The output appears. All three fields — DECISION, PROPOSAL_HASH, REASON — are logged every time."

---

### [0:46 - 0:55] Scene 4: Trace Log

**Show**: Scroll through the three log lines side by side across all three runs.

```
Run 1 (rm):   DECISION: STOP  | PROPOSAL_HASH: 8b4e91... | REASON: No rule matched
Run 2 (curl): DECISION: STOP  | PROPOSAL_HASH: a3f2c1... | REASON: No rule matched
Run 3 (echo): DECISION: ALLOW | PROPOSAL_HASH: 7d2f44... | REASON: Policy match: command="echo"
```

**Narrate**: "Every attempt is hashed. Every decision is logged. You have a cryptographic record of every execution request — allowed or denied."

---

### [0:55 - 1:00] Close

> "Execution Guard. Deny-by-default. Deterministic. Auditable. Built on a sealed core you can verify."

Show the invariant hash on screen:
```
Core invariant hash:
54add9db6f88f28a81bbfd428d47fa011ad9151b91df672c3c1fa75beac32f04
```

---

## Notes for Recording

- Use GitHub Actions log view (not terminal) for main visuals — shows step names clearly
- Zoom into the `DECISION:` line in each run
- Keep the policy file visible on the left side, Actions log on the right
- Do not skip the PROPOSAL_HASH line — that's the key differentiator

---

**Version**: v0.1.0
**Date**: 2026-02-17
