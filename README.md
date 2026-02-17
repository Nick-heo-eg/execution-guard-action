# Execution Guard Action

Execution Guard is a deny-by-default execution layer for GitHub Actions built on Execution Boundary architecture.

[![Demo](https://github.com/Nick-heo-eg/execution-guard-action/actions/workflows/demo.yml/badge.svg)](https://github.com/Nick-heo-eg/execution-guard-action/actions/workflows/demo.yml)

---

## 30-Second Demo

Three scenarios. Run them yourself.

### Scenario 1: curl blocked (STOP)

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.1.0
  with:
    command: 'curl https://example.com'
    policy_path: './policies/safe-commands.yaml'
```

```
DECISION: STOP
PROPOSAL_HASH: a3f2c1...
REASON: No rule matched. Default: DENY
❌ EXECUTION BLOCKED (STOP)
```

### Scenario 2: rm -rf / blocked (STOP)

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.1.0
  with:
    command: 'rm -rf /'
    policy_path: './policies/safe-commands.yaml'
```

```
DECISION: STOP
PROPOSAL_HASH: 8b4e91...
REASON: No rule matched. Default: DENY
❌ EXECUTION BLOCKED (STOP)
```

### Scenario 3: echo allowed (ALLOW)

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.1.0
  with:
    command: 'echo hello'
    policy_path: './policies/safe-commands.yaml'
```

```
DECISION: ALLOW
PROPOSAL_HASH: 7d2f44...
REASON: Policy match: command="echo" scope="safe-commands"
✅ Execution permitted: echo hello
hello
```

---

## Architecture

```
GitHub Actions Workflow
         │
         ▼
  ┌──────────────────────────┐
  │   AI Step / CI Step      │  ← generates command
  │   command: "rm -rf /"    │
  └──────────┬───────────────┘
             │  INPUT_COMMAND
             ▼
  ┌──────────────────────────┐
  │   Execution Guard        │  ← this action
  │   (Adapter Layer)        │
  │                          │
  │  reads: INPUT_COMMAND    │
  │         POLICY_PATH      │
  └──────────┬───────────────┘
             │
             ▼
  ┌──────────────────────────┐
  │   Execution Boundary     │  ← sealed core engine
  │   (execution-runtime-    │    core invariant hash:
  │    core, SEALED)         │    54add9db6f88f28a8...
  │                          │
  │  evaluate(request)       │
  │  → verdict: ALLOW|DENY   │
  └──────────┬───────────────┘
             │
             ▼
  ┌──────────────────────────┐
  │   Verdict                │
  │   ALLOW → spawn()        │  ← command executes
  │   STOP  → exit(1)        │  ← job fails, blocked
  │   HOLD  → warn/exit(1)   │  ← soft gate (future)
  └──────────────────────────┘
```

---

## Usage

### Basic

```yaml
steps:
  - uses: actions/checkout@v4

  - name: Guard command execution
    uses: Nick-heo-eg/execution-guard-action@v0.1.0
    with:
      command: 'echo deploy complete'
      policy_path: './policy.yaml'
```

### With fail_on_hold

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.1.0
  with:
    command: 'npm run build'
    policy_path: './policy.yaml'
    fail_on_hold: 'false'   # warn on HOLD, don't fail
```

### Capture outputs

```yaml
- name: Guard
  id: guard
  uses: Nick-heo-eg/execution-guard-action@v0.1.0
  with:
    command: 'deploy.sh'
    policy_path: './policy.yaml'

- name: Audit log
  run: |
    echo "Verdict: ${{ steps.guard.outputs.verdict }}"
    echo "Hash:    ${{ steps.guard.outputs.proposal_hash }}"
    echo "Reason:  ${{ steps.guard.outputs.reason }}"
```

---

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `command` | yes | — | Command string to evaluate and execute |
| `policy_path` | no | `./policy.yaml` | Path to policy YAML file |
| `fail_on_hold` | no | `true` | Exit 1 on HOLD verdict (false = warn + exit 0) |

## Outputs

| Output | Description |
|--------|-------------|
| `verdict` | `ALLOW`, `STOP`, or `HOLD` |
| `proposal_hash` | SHA256 hash of execution proposal (audit trail) |
| `reason` | Human-readable verdict reason |

---

## Policy Format

```yaml
default: DENY

rules:
  - command: echo
    args: ['*']
    scope: safe-commands

  - command: ls
    args: ['*']
    scope: safe-commands
```

**Guarantee**: No match → DENY. Malformed policy → DENY. No policy → DENY.

See [`policies/`](./policies/) for examples.

---

## Verdict Reference

| Verdict | Meaning | Exit Code |
|---------|---------|-----------|
| `ALLOW` | Policy match — command spawned | 0 (or command's exit code) |
| `STOP` | No match or no policy — execution blocked | 1 |
| `HOLD` | Soft gate (future) — fail_on_hold controls behavior | 0 or 1 |

---

## Core Boundary

This action is an adapter over the sealed **Execution Boundary** core engine.

**Core is UNTOUCHED.** No core code modified in this adapter.

**Core invariant hash**: `54add9db6f88f28a81bbfd428d47fa011ad9151b91df672c3c1fa75beac32f04`

The core engine enforces:
- Default = DENY (no policy → no execution)
- Exact string match only (no semantic evaluation)
- Deterministic (same input → same decision)
- Fail-closed (all errors → DENY)
- Cryptographic audit (SHA256 proposal hash on every attempt)

---

## Roadmap

- [x] v0.1.0 — GitHub Actions adapter (ALLOW/STOP/HOLD)
- [ ] v0.2.0 — HOLD verdict via policy `action: hold`
- [ ] v0.3.0 — Multi-command policy evaluation
- [ ] v1.0.0 — OpenTelemetry span export (optional, roadmap only)

---

## License

MIT
